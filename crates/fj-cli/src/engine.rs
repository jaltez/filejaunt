//! Transfer engines: sender (offer side) and receiver (answer side), driven
//! by `fj-protocol::Session` + `fj-webrtc::PeerHandle`.
//!
//! Frame flow: `PeerHandle` callbacks (sync, runtime threads) push decrypted
//! wire bytes into a std mpsc channel; the async engine drains it and feeds
//! `session.on_frame`. Outbound `Action::Send` bytes from channel-open go to
//! ALL data channels (HELO/MANIFEST are idempotent on the peer); chunk data
//! rides channel `index % channels`.

use std::collections::HashMap;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::Duration;

use fj_protocol::manifest::FileSpec;
use fj_protocol::pake::AttemptLimiter;
use fj_protocol::session::{Action, Session, SessionOpts};
use fj_protocol::{ErrorCode, FILE_ALL};
use fj_webrtc::{IceConfig, PeerHandle};
use tokio::sync::mpsc as tokio_mpsc;

use crate::store::Store;
use crate::ui;
use crate::ui::{Mode, Out};

pub const PUBLIC_STUN: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
];

pub fn parse_stun(spec: &str) -> Vec<String> {
    match spec.trim() {
        "none" => vec![],
        "public" => PUBLIC_STUN.iter().map(|s| s.to_string()).collect(),
        other => other
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    }
}

/// USER:PASS@HOST:PORT -> (turn:host:port, user, pass)
pub fn parse_turn(spec: &str) -> Option<(String, String, String)> {
    let (userpass, hostport) = spec.rsplit_once('@')?;
    let (user, pass) = userpass.split_once(':')?;
    let hostport = hostport.trim_start_matches("turn://");
    Some((
        format!("turn:{hostport}"),
        user.to_string(),
        pass.to_string(),
    ))
}

/// Engine outcome: `Done` = clean session completion (exit 0).
pub enum Outcome {
    Done,
}

struct LocalFile {
    spec: FileSpec,
    path: PathBuf,
}

pub struct Engine {
    pub out: Out,
    pub store: Store,
    pub ice: IceConfig,
    pub channels: usize,
    pub yes: bool,
    /// resume: passphrase known up-front (prompt suppressed)
    pub passphrase_prompt: Option<String>,
    /// relay URL for pairing-blob transport (None = manual paste mode)
    pub relay_url: Option<String>,
    /// file id -> absolute source path (sender side; used to wrap state)
    pub sources: std::cell::RefCell<Vec<PathBuf>>,
}

impl Engine {
    fn log_step(&self, msg: &str) {
        self.out.stderr_line(msg);
    }

    /// Wormhole-style visual checksum derived from K_confirm. Show on both
    /// screens; matching values rule out a signaling-channel MITM.
    fn show_checksum(&self, session: &Session, relay_mode: bool) {
        if !relay_mode {
            return;
        }
        let Some(sum) = session.verify_checksum() else {
            return;
        };
        match self.out.mode {
            Mode::Json => {
                self.out
                    .json(serde_json::json!({"type": "checksum", "checksum": sum}));
            }
            Mode::Human => {
                self.out.stderr_line(&format!(
                    "verification checksum: {sum} — compare on both screens"
                ));
            }
        }
    }

    /// Structured failure: stderr line always; NDJSON `error` event in --json
    /// mode (the documented event contract).
    fn fail_event(&self, code: ErrorCode, msg: &str) -> ErrorCode {
        eprintln!("[{code}] {}", ui::sanitize(msg));
        if self.out.mode == Mode::Json {
            self.out.json(serde_json::json!({
                "type": "error", "code": code.as_str(), "msg": msg,
            }));
        }
        code
    }

    /// Sender state wrapper: session snapshot + source paths (receiver state
    /// is stored as the plain snapshot).
    fn wrap_sender_state(&self, _sid: &str, session: &Session, sources: &[PathBuf]) -> String {
        let snapshot: serde_json::Value =
            serde_json::from_str(&session.snapshot()).unwrap_or(serde_json::Value::Null);
        serde_json::json!({
            "v": 1,
            "role": "sender",
            "sources": sources.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
            "session": snapshot,
        })
        .to_string()
    }
}

/// Read a trimmed line from stdin; hidden prompt when interactive.
pub fn read_line_prompt(prompt: &str) -> String {
    if stdin_is_tty() {
        rpassword::prompt_password(prompt)
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        line.trim().to_string()
    }
}

fn stdin_is_tty() -> bool {
    std::fs::read_link("/proc/self/fd/0")
        .map(|p| {
            let s = p.to_string_lossy().to_string();
            s.starts_with("/dev/pts/") || s == "/dev/tty" || s.starts_with("/dev/tty")
        })
        .unwrap_or(false)
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::Digest;
    let mut f = std::fs::File::open(path)?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn collect_files(paths: &[PathBuf]) -> std::io::Result<Vec<(PathBuf, String, String)>> {
    let mut out = Vec::new();
    fn walk(
        p: &Path,
        rel_dir: &str,
        out: &mut Vec<(PathBuf, String, String)>,
    ) -> std::io::Result<()> {
        let meta = std::fs::symlink_metadata(p)?;
        if meta.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(p)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            entries.sort();
            for e in entries {
                let name = e
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let rel = if rel_dir.is_empty() {
                    name.clone()
                } else {
                    format!("{rel_dir}/{name}")
                };
                walk(&e, &rel, out)?;
            }
        } else if meta.is_file() {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            out.push((p.to_path_buf(), name, rel_dir.to_string()));
        }
        Ok(())
    }
    for p in paths {
        walk(p, "", &mut out)?;
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

/// Register frame callbacks for all channels; returns the merged receiver.
async fn wire_frames(peer: &Arc<PeerHandle>, channels: usize) -> std_mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std_mpsc::channel::<Vec<u8>>();
    for ch in 0..channels.max(1) {
        let tx = tx.clone();
        peer.on_frame(ch, move |bytes| {
            if std::env::var("FJ_DEBUG").is_ok() && bytes.len() > 12 {
                eprintln!(
                    "[fj-debug pid={}] ch{ch} delivered type=0x{:02x} seq={}",
                    std::process::id(),
                    bytes[1],
                    u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
                );
            }
            let _ = tx.send(bytes);
        })
        .await;
    }
    rx
}

impl Engine {
    // ------------------------------------------------------------------
    // sender
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        paths: &[PathBuf],
        words: usize,
        private3: bool,
        gzip: &str,
        receivers: usize,
        resume: Option<(&str, &str)>,
    ) -> Result<Outcome, ErrorCode> {
        let listing = if let Some((sid, _pass)) = resume {
            // sender resume: source paths come from the saved state
            let raw = self
                .store
                .load_session(sid, "send")
                .ok_or(ErrorCode::StorageFailed)?;
            let wrapper: serde_json::Value =
                serde_json::from_str(&raw).map_err(|_| ErrorCode::StorageFailed)?;
            wrapper["sources"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(PathBuf::from))
                        .collect::<Vec<PathBuf>>()
                })
                .unwrap_or_default()
                .into_iter()
                .map(|p| {
                    (
                        p.clone(),
                        p.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        String::new(),
                    )
                })
                .collect::<Vec<_>>()
        } else {
            collect_files(paths).map_err(|_| ErrorCode::StorageFailed)?
        };
        if listing.is_empty() {
            eprintln!("nothing to send");
            return Err(ErrorCode::StorageFailed);
        }
        if listing.len() > fj_protocol::MAX_FILES {
            eprintln!(
                "too many files ({} > {})",
                listing.len(),
                fj_protocol::MAX_FILES
            );
            return Err(ErrorCode::PathRejected);
        }

        *self.sources.borrow_mut() = listing.iter().map(|(p, _, _)| p.clone()).collect();
        // file specs (hash + gzip probe) computed once, shared by receivers
        let mut locals: Vec<LocalFile> = Vec::with_capacity(listing.len());
        for (path, name, dir) in &listing {
            let meta = std::fs::metadata(path).map_err(|_| ErrorCode::StorageFailed)?;
            let size = meta.len();
            let sha = sha256_file(path).map_err(|_| ErrorCode::StorageFailed)?;
            let gzip_on = match gzip {
                "on" => true,
                "off" => false,
                _ => probe_gzip(path, size)?,
            };
            locals.push(LocalFile {
                spec: FileSpec {
                    name: name.clone(),
                    path: dir.clone(),
                    size,
                    sha256: sha,
                    gzip: gzip_on,
                },
                path: path.clone(),
            });
        }
        let total: u64 = locals.iter().map(|l| l.spec.size).sum();
        let mut names: Vec<(String, u64)> = locals
            .iter()
            .map(|l| (l.spec.name.clone(), l.spec.size))
            .collect();
        let _ = &mut names;

        let n = receivers.max(1);
        let mut ctxs: Vec<SendCtx> = Vec::with_capacity(n);
        for i in 0..n {
            if n > 1 && self.out.mode == Mode::Human {
                eprintln!("--- receiver {}/{} ---", i + 1, n);
            } else if n > 1 {
                self.out
                    .json(serde_json::json!({"type": "receiver", "index": i, "of": n}));
            }
            let ctx = self.pair_sender(words, private3, resume, &locals).await?;
            ctxs.push(ctx);
        }

        // manifests: same file list for every receiver session. On resume the
        // restored session already carries the manifest + bitmaps.
        if resume.is_none() {
            let specs: Vec<FileSpec> = locals.iter().map(|l| l.spec.clone()).collect();
            for ctx in &mut ctxs {
                ctx.session.set_files(&specs).map_err(|e| {
                    eprintln!("manifest rejected: {}", e.msg());
                    ErrorCode::PathRejected
                })?;
            }
        }

        if std::env::var("FJ_DEBUG").is_ok() {
            eprintln!(
                "[fj-debug pid={}] send: {} sessions",
                std::process::id(),
                ctxs.len()
            );
        }
        // open channels for every receiver (wait for the wire first: HELO
        // must not race the channel open)
        for ctx in &mut ctxs {
            ctx.peer
                .wait_channels_open(Duration::from_secs(20))
                .await
                .map_err(|_| {
                    eprintln!("data channel did not open (ICE failed?)");
                    ErrorCode::IceFailed
                })?;
            let actions = ctx.session.on_channel_open();
            for a in actions {
                self.route_sender(ctx, a).await?;
            }
            self.emit_path(&ctx.peer).await;
        }
        self.emit_manifest(&locals, total);

        let pause_flag = Arc::new(AtomicBool::new(false));
        let cancel_flag = Arc::new(AtomicBool::new(false));
        crate::signals::install(pause_flag.clone(), cancel_flag.clone());

        let mut readers: Vec<TakeReader> = Vec::with_capacity(locals.len());
        for l in &locals {
            let f = std::fs::File::open(&l.path).map_err(|_| ErrorCode::StorageFailed)?;
            readers.push(TakeReader::new(f));
        }

        self.drive_sender(&mut ctxs, &locals, &mut readers, &pause_flag, &cancel_flag)
            .await?;
        for ctx in &ctxs {
            self.store.delete_session(&ctx.sid);
        }
        self.out
            .json(serde_json::json!({"type": "done", "ok": true}));
        Ok(Outcome::Done)
    }

    async fn pair_sender(
        &self,
        words: usize,
        private3: bool,
        resume: Option<(&str, &str)>,
        _locals: &[LocalFile],
    ) -> Result<SendCtx, ErrorCode> {
        // For a resume, the snapshot must be loaded BEFORE the offer is
        // created: the offer must contain as many data channels as the
        // original session (the envelope announces `ch`, and the receiver
        // waits for exactly that many).
        let restored = match resume {
            Some((sid, _)) => {
                let raw = self
                    .store
                    .load_session(sid, "send")
                    .ok_or(ErrorCode::StorageFailed)?;
                let snap = serde_json::from_str::<serde_json::Value>(&raw)
                    .ok()
                    .and_then(|w| {
                        w.get("session")
                            .map(|s| s.to_string())
                            .filter(|s| s != "null")
                    })
                    .unwrap_or(raw);
                Some(Session::restore(&snap).map_err(|e| {
                    eprintln!("bad session state: {}", e.msg());
                    ErrorCode::StorageFailed
                })?)
            }
            None => None,
        };
        let (channels, private3) = match (&restored, resume) {
            (Some(s), Some((_, _pass))) => (s.channels().max(1), s.private3()),
            _ => (self.channels, private3),
        };
        let peer = PeerHandle::new(&self.ice)
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let offer_sdp = peer
            .create_offer(channels)
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let (mut session, passphrase, blob1) = match resume {
            None => Session::initiator_new(SessionOpts {
                words,
                private3,
                chunk_size: fj_protocol::CHUNK_SIZE_DEFAULT,
                channels: self.channels,
                sid: None,
                offer_sdp,
            })
            .map_err(|e| {
                eprintln!("pairing failed: {}", e.msg());
                ErrorCode::SecPakeFailed
            })?,
            Some((_sid, pass)) => {
                let mut s = restored.expect("restored above");
                let blob1 = s.resume_initiator(pass, &offer_sdp).map_err(|e| {
                    eprintln!("resume pairing failed: {}", e.msg());
                    ErrorCode::SecPakeFailed
                })?;
                (s, pass.to_string(), blob1)
            }
        };
        let sid = session.sid_hex();
        // Relay mode: one-line pairing code (Wormhole style) — the room id
        // travels in the code, so the receiver types a single string.
        let relay_room = self
            .relay_url
            .as_ref()
            .map(|_| RelayHandle::room_from_passphrase(&passphrase));
        let code = relay_room
            .as_ref()
            .map(|room| pairing_code(room, &passphrase));

        match self.out.mode {
            Mode::Json => self.out.json(serde_json::json!({
                "type": "hello", "sid": sid, "passphrase": passphrase, "blob1": blob1,
                "private3": private3,
                "code": code,
            })),
            Mode::Human => {
                if let Some(code) = &code {
                    if resume.is_some() {
                        eprintln!("\x1b[1;33mresume code (same passphrase session):\x1b[0m");
                    } else {
                        eprintln!("\x1b[1;33mpairing code (say or send it):\x1b[0m");
                    }
                    eprintln!("\x1b[1;32m{code}\x1b[0m");
                } else {
                    if resume.is_some() {
                        eprintln!(
                            "\x1b[1;33mresume passphrase (same as the original session):\x1b[0m"
                        );
                    } else {
                        eprintln!("\x1b[1;33mpassphrase (say it, don't send it):\x1b[0m");
                    }
                    eprintln!("\x1b[1;32m{passphrase}\x1b[0m");
                }
                if self.relay_url.is_none() {
                    eprintln!("blob-1 (paste to the other side):");
                    println!("{blob1}");
                    let _ = std::io::stdout().flush();
                }
            }
        }

        // resume must keep the restored pairing mode/channel count
        let effective_private3 = session.private3();
        let channels = session.channels().max(1);

        // Relay mode: transport blob-1/blob-2 (and blob-3/blob-4 for p3)
        // through the signaling relay room instead of copy/paste. The
        // initiator speaks first (blob-1).
        let relay = if let (Some(url), Some(room)) = (&self.relay_url, &relay_room) {
            let rc = RelayHandle::connect(url, room).await?;
            // initiator speaks first: blob-1 only after the peer joined
            rc.wait_peer().await.map_err(|_| ErrorCode::IceFailed)?;
            rc.send_blob(&blob1)?;
            Some(rc)
        } else {
            None
        };

        let blob2 = match relay.as_ref() {
            Some(rc) => rc.recv_blob().await.map_err(|e| {
                eprintln!("relay recv failed: {e}");
                ErrorCode::IceFailed
            })?,
            None => read_blob_field(self.out.mode, "blob2")?,
        };
        session.initiator_accept(&blob2).map_err(|e| {
            eprintln!("[{}] pairing failed: {}", e.code(), e.msg());
            ErrorCode::SecPakeFailed
        })?;
        self.show_checksum(&session, relay.is_some());
        if effective_private3 {
            let blob3 = session.initiator_private_blob3().map_err(|e| {
                eprintln!("[{}] {}", e.code(), e.msg());
                ErrorCode::SecPakeFailed
            })?;
            let blob4 = match relay.as_ref() {
                Some(rc) => {
                    rc.send_blob(&blob3).map_err(|_| ErrorCode::IceFailed)?;
                    rc.recv_blob().await.map_err(|_| ErrorCode::IceFailed)?
                }
                None => {
                    match self.out.mode {
                        Mode::Json => self
                            .out
                            .json(serde_json::json!({"type": "blob3", "blob3": blob3})),
                        Mode::Human => {
                            eprintln!("blob-3 (paste into the receiver):");
                            println!("{blob3}");
                            let _ = std::io::stdout().flush();
                        }
                    }
                    read_blob_field(self.out.mode, "blob4")?
                }
            };
            session.initiator_private_final(&blob4).map_err(|e| {
                eprintln!("[{}] {}", e.code(), e.msg());
                ErrorCode::SecPakeFailed
            })?;
        }
        // apply the answer to the peer connection (connectivity starts here)
        peer.set_answer(session.answer_sdp())
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let frames = wire_frames(&peer, channels).await;
        Ok(SendCtx {
            session,
            peer,
            passphrase,
            sid,
            frames,
            channels,
        })
    }

    fn emit_manifest(&self, locals: &[LocalFile], total: u64) {
        match self.out.mode {
            Mode::Json => self.out.json(serde_json::json!({
                "type": "manifest",
                "files": locals.iter().enumerate().map(|(i, l)| serde_json::json!({
                    "id": i, "name": l.spec.name, "path": l.spec.path,
                    "size": l.spec.size, "sha256": l.spec.sha256,
                })).collect::<Vec<_>>(),
                "total": total,
            })),
            Mode::Human => {
                self.out.stderr_line(&format!(
                    "{} file(s), total {}",
                    locals.len(),
                    crate::ui::mib_pub(total)
                ));
            }
        }
    }

    async fn emit_path(&self, peer: &Arc<PeerHandle>) {
        let cand = peer
            .selected_candidate_type()
            .await
            .unwrap_or_else(|| "unknown".into());
        let kind = match cand.as_str() {
            "host" | "srflx" => "direct",
            "relay" => "relay",
            _ => "unknown",
        };
        match self.out.mode {
            Mode::Json => self
                .out
                .json(serde_json::json!({"type": "path", "kind": kind, "candidate": cand})),
            Mode::Human => {
                let label = match cand.as_str() {
                    "host" => "DIRECT(host)".to_string(),
                    "srflx" => "DIRECT(srflx)".to_string(),
                    "relay" => "RELAY".to_string(),
                    other => other.to_string(),
                };
                self.out.stderr_line(&format!("path: {label}"));
            }
        }
    }

    /// Route one action produced on the sender side. `Ok(true)` = session
    /// finished cleanly.
    async fn route_sender(&self, ctx: &mut SendCtx, a: Action) -> Result<bool, ErrorCode> {
        match a {
            Action::Send(bytes) => {
                // HELO / MANIFEST / empty-file DONE: every channel carries
                // them (duplicate handling is idempotent on the peer)
                for ch in 0..ctx.channels.max(1) {
                    ctx.peer
                        .send_backpressured(ch, bytes.clone())
                        .await
                        .map_err(|_| ErrorCode::IceFailed)?;
                }
                Ok(false)
            }
            Action::SaveState => {
                let wrapped =
                    self.wrap_sender_state(&ctx.sid, &ctx.session, &self.sources.borrow());
                self.store.save_session(&ctx.sid, "send", &wrapped).ok();
                Ok(false)
            }
            Action::Progress {
                file,
                done,
                total,
                wire_bytes,
                resumed,
            } => {
                let name = ctx
                    .session
                    .manifest()
                    .and_then(|m| m.file(file).map(|f| f.name.clone()))
                    .unwrap_or_default();
                match self.out.mode {
                    Mode::Json => self.out.json(serde_json::json!({
                        "type": "progress", "file": file, "name": name, "done": done,
                        "total": total, "wire_bytes": wire_bytes, "resumed": resumed,
                    })),
                    Mode::Human => self.out.progress(&name, done, total, wire_bytes, ""),
                }
                Ok(false)
            }
            Action::FileDone {
                file,
                sha256,
                verified,
            } => {
                self.out.progress_end();
                match self.out.mode {
                    Mode::Json => self.out.json(serde_json::json!({
                        "type": "fileDone", "file": file, "sha256": hex::encode(sha256),
                        "verified": verified,
                    })),
                    Mode::Human => {
                        eprintln!("file {file}: done verified={verified}");
                        eprintln!("verified: sha256 {}", hex::encode(sha256));
                    }
                }
                Ok(false)
            }
            Action::Receipt(r) => {
                self.save_receipt(&r);
                Ok(false)
            }
            Action::SessionDone => Ok(true),
            Action::Fail { code, msg } => Err(self.fail_event(code, &msg)),
            _ => Ok(false),
        }
    }

    fn save_receipt(&self, r: &fj_protocol::Receipt) {
        let path = self.store.save_receipt(r).ok();
        match self.out.mode {
            Mode::Json => self.out.json(serde_json::json!({
                "type": "receipt", "receipt": r,
                "saved": path.map(|p| p.to_string_lossy().to_string()),
            })),
            Mode::Human => {
                eprintln!(
                    "receipt saved: {}",
                    path.map(|p| p.display().to_string())
                        .unwrap_or_else(|| "?".into())
                );
                eprintln!("verified: sha256 {}", r.sha256);
            }
        }
    }

    async fn drive_sender(
        &self,
        ctxs: &mut [SendCtx],
        locals: &[LocalFile],
        readers: &mut [TakeReader],
        pause_flag: &Arc<AtomicBool>,
        cancel_flag: &Arc<AtomicBool>,
    ) -> Result<bool, ErrorCode> {
        let mut ctx_done = vec![false; ctxs.len()];
        let mut was_paused = false;
        let mut last_activity = std::time::Instant::now();
        loop {
            // 1) drain inbound frames
            for ci in 0..ctxs.len() {
                let ctx = &mut ctxs[ci];
                while let Ok(frame) = ctx.frames.try_recv() {
                    let actions = ctx.session.on_frame(&frame).map_err(|e| e.code())?;
                    for a in actions {
                        match a {
                            Action::Send(bytes) => {
                                // post-HELO sends from the peer side of the
                                // receiver (BITMAP/RECEIPT replies route ch0)
                                ctx.peer
                                    .send_backpressured(0, bytes)
                                    .await
                                    .map_err(|_| ErrorCode::IceFailed)?;
                            }
                            other => {
                                if self.route_sender(ctx, other).await? {
                                    ctx_done[ci] = true;
                                }
                            }
                        }
                    }
                }
            }
            if ctx_done.iter().all(|d| *d) {
                return Ok(false);
            }
            if cancel_flag.load(Ordering::SeqCst) {
                // SIGINT/SIGTERM: clean cancel, exit 0 (single terminal event)
                for ctx in ctxs.iter_mut() {
                    for a in ctx.session.cancel(FILE_ALL) {
                        if let Action::Send(bytes) = a {
                            let _ = ctx.peer.send_backpressured(0, bytes).await;
                        }
                    }
                }
                self.out
                    .json(serde_json::json!({"type": "done", "ok": false, "cancelled": true}));
                return Ok(true);
            }
            if pause_flag.load(Ordering::SeqCst) {
                if !was_paused {
                    was_paused = true;
                    for ctx in ctxs.iter_mut() {
                        for a in ctx.session.pause(FILE_ALL) {
                            if let Action::Send(bytes) = a {
                                let _ = ctx.peer.send_backpressured(0, bytes).await;
                            }
                        }
                    }
                    match self.out.mode {
                        Mode::Json => self.out.json(serde_json::json!({"type": "paused"})),
                        Mode::Human => eprintln!("paused"),
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            if was_paused {
                was_paused = false;
                for ctx in ctxs.iter_mut() {
                    for a in ctx.session.resume(FILE_ALL) {
                        if let Action::Send(bytes) = a {
                            let _ = ctx.peer.send_backpressured(0, bytes).await;
                        }
                    }
                }
                match self.out.mode {
                    Mode::Json => self.out.json(serde_json::json!({"type": "resumed"})),
                    Mode::Human => eprintln!("resumed"),
                }
            }
            // 2) push one chunk per receiver per round (shared disk read,
            // sequential send). Pipelining was tried and reverted: it stalled
            // CLI transfers; keep the simple, correct loop until a measured
            // alternative exists (roadmap: throughput work).
            let mut pushed = 0usize;
            for ci in 0..ctxs.len() {
                let ctx = &mut ctxs[ci];
                if ctx.session.is_done() || ctx.session.is_failed() {
                    continue;
                }
                for (fi, _local) in locals.iter().enumerate() {
                    if ctx.session.is_paused(fi as u16) {
                        continue;
                    }
                    let Some((index, len)) = ctx.session.next_send_chunk(fi as u16) else {
                        continue;
                    };
                    let data = readers[fi].read_range(
                        index,
                        fj_protocol::CHUNK_SIZE_DEFAULT as u64,
                        len,
                    )?;
                    let (wire, actions) = ctx
                        .session
                        .push_chunk_data(fi as u16, index, &data)
                        .map_err(|e| e.code())?;
                    let ch = (index as usize) % ctx.channels.max(1);
                    ctx.peer
                        .send_backpressured(ch, wire)
                        .await
                        .map_err(|_| ErrorCode::IceFailed)?;
                    pushed += 1;
                    for a in actions {
                        match a {
                            Action::Send(bytes) => {
                                // DONE rides channel 0
                                ctx.peer
                                    .send_backpressured(0, bytes)
                                    .await
                                    .map_err(|_| ErrorCode::IceFailed)?;
                            }
                            Action::SessionDone => {
                                ctx_done[ci] = true;
                            }
                            Action::Fail { code, msg } => {
                                eprintln!("[{code}] {msg}");
                                return Err(code);
                            }
                            other => {
                                self.route_sender(ctx, other).await?;
                            }
                        }
                    }
                    break; // one chunk per receiver per round
                }
            }
            if pushed > 0 {
                last_activity = std::time::Instant::now();
            }
            if pushed == 0 {
                tokio::time::sleep(Duration::from_millis(15)).await;
                // stall watchdog: a dead peer can leave SCTP silently
                // buffering forever; fail after 15 s without progress
                if last_activity.elapsed() > Duration::from_secs(15) {
                    eprintln!("connection stalled (no progress for 15s)");
                    return Err(ErrorCode::IceFailed);
                }
            }
            // allow tokio to breathe under heavy loops
            tokio::task::yield_now().await;
        }
    }

    // ------------------------------------------------------------------
    // receiver
    // ------------------------------------------------------------------

    pub async fn receive(
        &self,
        out_dir: &Path,
        resume_sid: Option<&str>,
    ) -> Result<Outcome, ErrorCode> {
        // 1) pairing transport: relay room (passphrase first — it derives the
        // room id) or manual paste (blob-1, then passphrase)
        let (relay, blob1, passphrase) = match (&self.relay_url, self.passphrase_prompt.as_deref())
        {
            (Some(url), prompt) => {
                let input = match prompt {
                    Some(p) => p.to_string(),
                    None => read_line_prompt("pairing code (or passphrase): "),
                };
                if input.trim().is_empty() {
                    eprintln!("no pairing code given");
                    return Err(ErrorCode::SecPakeFailed);
                }
                // `fj-<room8>-<words>` carries the room id; a bare input
                // falls back to deriving the room from the passphrase.
                let (room, pass) = match parse_pairing_code(&input) {
                    Some((r, p)) => (r, p),
                    None => (
                        RelayHandle::room_from_passphrase(&input),
                        input.trim().to_string(),
                    ),
                };
                let rc = RelayHandle::connect(url, &room).await?;
                let blob1 = rc.recv_blob().await.map_err(|_| ErrorCode::IceFailed)?;
                (Some(rc), blob1, pass)
            }
            (None, prompt) => {
                let blob1 = read_blob_field(self.out.mode, "blob1")?;
                let pass = match prompt {
                    Some(p) => p.to_string(),
                    None => read_line_prompt("passphrase: "),
                };
                if pass.is_empty() {
                    eprintln!("no passphrase given");
                    return Err(ErrorCode::SecPakeFailed);
                }
                (None, blob1, pass)
            }
        };

        let peer = PeerHandle::new(&self.ice)
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let mut limiter = AttemptLimiter::new();

        let json = fj_protocol::envelope::inflate(&blob1).map_err(|e| {
            eprintln!("[{}] {}", e.code(), e.msg());
            ErrorCode::ProtoMalformed
        })?;
        let env1: fj_protocol::envelope::Envelope1 =
            serde_json::from_str(&json).map_err(|_| ErrorCode::ProtoMalformed)?;
        let (sid, mode) = fj_protocol::envelope::validate_env1(&env1).map_err(|e| {
            eprintln!("[{}] {}", e.code(), e.msg());
            ErrorCode::ProtoMalformed
        })?;
        let channels = env1.ch.clamp(1, fj_protocol::CHANNELS_MAX);
        let private3 = mode == fj_protocol::envelope::PairingMode::P3;

        let session = match resume_sid {
            None => {
                if private3 {
                    // p3: blob-2 carries only the PAKE message; the offer
                    // arrives encrypted in blob-3 and is applied exactly once
                    let (mut s, blob2) =
                        Session::responder_join(&blob1, &passphrase, "", &mut limiter).map_err(
                            |e| {
                                eprintln!("[{}] {}", e.code(), e.msg());
                                e.code()
                            },
                        )?;
                    self.emit_blob2(relay.as_ref(), &blob2);
                    self.p3_responder(&peer, &mut s, channels, &mut limiter, relay.as_ref())
                        .await?;
                    s
                } else {
                    let offer = env1.sdp.clone().unwrap_or_default();
                    let answer = peer
                        .accept_offer(&offer, channels)
                        .await
                        .map_err(|_| ErrorCode::IceFailed)?;
                    let (s, blob2) =
                        Session::responder_join(&blob1, &passphrase, &answer, &mut limiter)
                            .map_err(|e| {
                                eprintln!("[{}] {}", e.code(), e.msg());
                                e.code()
                            })?;
                    self.emit_blob2(relay.as_ref(), &blob2);
                    s
                }
            }
            Some(sid_hex) => {
                let snap = self
                    .store
                    .load_session(sid_hex, "recv")
                    .or_else(|| self.store.load_session(&hex::encode(sid), "recv"))
                    .ok_or(ErrorCode::StorageFailed)?;
                let mut s = Session::restore(&snap).map_err(|e| {
                    eprintln!("bad session state: {}", e.msg());
                    ErrorCode::StorageFailed
                })?;
                if private3 {
                    let blob2 = s
                        .resume_responder(&blob1, &passphrase, "", &mut limiter)
                        .map_err(|e| {
                            eprintln!("[{}] {}", e.code(), e.msg());
                            e.code()
                        })?;
                    self.emit_blob2(relay.as_ref(), &blob2);
                    self.p3_responder(&peer, &mut s, channels, &mut limiter, relay.as_ref())
                        .await?;
                    s
                } else {
                    let offer = env1.sdp.clone().unwrap_or_default();
                    let answer = peer
                        .accept_offer(&offer, channels)
                        .await
                        .map_err(|_| ErrorCode::IceFailed)?;
                    let blob2 = s
                        .resume_responder(&blob1, &passphrase, &answer, &mut limiter)
                        .map_err(|e| {
                            eprintln!("[{}] {}", e.code(), e.msg());
                            e.code()
                        })?;
                    self.emit_blob2(relay.as_ref(), &blob2);
                    s
                }
            }
        };
        // Relay mode MITM check: both screens must show the same checksum.
        self.show_checksum(&session, relay.is_some());

        let frames = wire_frames(&peer, channels.max(self.channels)).await;
        let mut rx = Receiver {
            session,
            peer,
            sid: hex::encode(sid),
            files: HashMap::new(),
            confirmed: false,
            frames,
            relay,
        };
        rx.peer
            .wait_channels_open(Duration::from_secs(20))
            .await
            .map_err(|_| {
                eprintln!("data channel did not open (ICE failed?)");
                ErrorCode::IceFailed
            })?;
        let actions = rx.session.on_channel_open();
        for a in actions {
            if self.route_receiver(&mut rx, out_dir, a).await? {
                self.store.delete_session(&rx.sid);
                self.out
                    .json(serde_json::json!({"type": "done", "ok": true}));
                return Ok(Outcome::Done);
            }
        }
        self.emit_path(&rx.peer).await;

        // receiver-side SIGINT/SIGTERM: emit CANCEL and exit cleanly
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let pause_flag = Arc::new(AtomicBool::new(false));
        crate::signals::install(pause_flag, cancel_flag.clone());

        loop {
            if cancel_flag.load(Ordering::SeqCst) {
                for a in rx.session.cancel(FILE_ALL) {
                    if let Action::Send(bytes) = a {
                        let _ = rx.peer.send_backpressured(0, bytes).await;
                    }
                }
                // let the CANCEL reach the peer before we exit
                tokio::time::sleep(Duration::from_millis(300)).await;
                self.store.delete_session(&rx.sid);
                self.out
                    .json(serde_json::json!({"type": "done", "ok": false, "cancelled": true}));
                return Ok(Outcome::Done);
            }
            match rx.frames.try_recv() {
                Ok(frame) => {
                    let actions = match rx.session.on_frame(&frame) {
                        Ok(a) => a,
                        Err(e) => return Err(self.fail_event(e.code(), e.msg())),
                    };
                    for a in actions {
                        if self.route_receiver(&mut rx, out_dir, a).await? {
                            self.store.delete_session(&rx.sid);
                            self.out
                                .json(serde_json::json!({"type": "done", "ok": true}));
                            return Ok(Outcome::Done);
                        }
                    }
                }
                Err(std_mpsc::TryRecvError::Empty) => {
                    if rx.session.is_failed() {
                        return Err(ErrorCode::PeerCancel);
                    }
                    if rx.session.is_done() {
                        self.store.delete_session(&rx.sid);
                        self.out
                            .json(serde_json::json!({"type": "done", "ok": true}));
                        return Ok(Outcome::Done);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(std_mpsc::TryRecvError::Disconnected) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if rx.session.is_done() {
                        return Ok(Outcome::Done);
                    }
                    if rx.session.is_failed() {
                        return Err(ErrorCode::PeerCancel);
                    }
                    eprintln!("connection closed before completion");
                    return Err(ErrorCode::IceFailed);
                }
            }
        }
    }

    async fn p3_responder(
        &self,
        peer: &Arc<PeerHandle>,
        session: &mut Session,
        channels: usize,
        limiter: &mut AttemptLimiter,
        relay: Option<&RelayHandle>,
    ) -> Result<(), ErrorCode> {
        let blob3 = match relay {
            Some(rc) => rc.recv_blob().await.map_err(|_| ErrorCode::IceFailed)?,
            None => read_blob_field(self.out.mode, "blob3")?,
        };
        let offer = session
            .responder_private_offer(&blob3, limiter)
            .map_err(|e| {
                eprintln!("[{}] {}", e.code(), e.msg());
                e.code()
            })?;
        let answer = peer
            .accept_offer(&offer, channels)
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let blob4 = session
            .responder_private_blob4(&answer)
            .map_err(|e| e.code())?;
        if let Some(rc) = relay {
            let _ = rc.send_blob(&blob4);
            self.log_step("blob-4 sent through relay");
            return Ok(());
        }
        match self.out.mode {
            Mode::Json => self
                .out
                .json(serde_json::json!({"type": "blob4", "blob4": blob4})),
            Mode::Human => {
                eprintln!("blob-4 (paste back to the sender):");
                println!("{blob4}");
                let _ = std::io::stdout().flush();
            }
        }
        Ok(())
    }

    fn emit_blob2(&self, relay: Option<&RelayHandle>, blob2: &str) {
        if let Some(rc) = relay {
            let _ = rc.send_blob(blob2);
            self.log_step("blob-2 sent through relay");
            return;
        }
        match self.out.mode {
            Mode::Json => self
                .out
                .json(serde_json::json!({"type": "joined", "blob2": blob2})),
            Mode::Human => {
                eprintln!("blob-2 (paste back to the sender):");
                println!("{blob2}");
                let _ = std::io::stdout().flush();
            }
        }
    }

    /// Route one receiver action; `Ok(true)` = clean session completion.
    async fn route_receiver(
        &self,
        rx: &mut Receiver,
        out_dir: &Path,
        a: Action,
    ) -> Result<bool, ErrorCode> {
        match a {
            Action::Send(bytes) => {
                // control replies (HELO/BITMAP/RECEIPT/ERROR) ride channel 0
                // only; broadcasting duplicates them per channel
                rx.peer
                    .send_backpressured(0, bytes)
                    .await
                    .map_err(|_| ErrorCode::IceFailed)?;
                Ok(false)
            }
            Action::SaveChunk { file, index, data } => {
                self.save_chunk(rx, out_dir, file, index, &data)?;
                Ok(false)
            }
            Action::HashFeed { file } => {
                // zero-chunk files reach HashFeed without any SaveChunk: make
                // sure the (empty) target exists before hashing
                self.ensure_target(rx, out_dir, file)?;
                let path = rx.files[&file].0.clone();
                // stream the re-read so multi-GB files never sit in RAM
                let mut fh = std::fs::File::open(&path).map_err(|_| ErrorCode::StorageFailed)?;
                let mut buf = vec![0u8; 1024 * 1024];
                let mut actions: Vec<Action> = vec![];
                loop {
                    let n = fh.read(&mut buf).map_err(|_| ErrorCode::StorageFailed)?;
                    if n == 0 {
                        break;
                    }
                    let acts = rx
                        .session
                        .hash_feed(file, &buf[..n])
                        .map_err(|e| e.code())?;
                    actions.extend(acts);
                }
                // zero-size files only: one empty feed finalizes the digest
                let size = rx
                    .session
                    .manifest()
                    .and_then(|m| m.file(file))
                    .map(|e| e.size)
                    .unwrap_or(0);
                if size == 0 {
                    let acts = rx.session.hash_feed(file, &[]).map_err(|e| e.code())?;
                    actions.extend(acts);
                }
                for a in actions {
                    match a {
                        Action::Send(bytes) => {
                            rx.peer
                                .send_backpressured(0, bytes)
                                .await
                                .map_err(|_| ErrorCode::IceFailed)?;
                        }
                        notice => {
                            if self.route_notice(rx, notice).await? {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
            Action::Progress { .. }
            | Action::FileDone { .. }
            | Action::Receipt(_)
            | Action::SaveState
            | Action::EmitText(_)
            | Action::FilesAdded(_)
            | Action::Fail { .. }
            | Action::SessionDone => self.route_notice(rx, a).await,
        }
    }

    /// Notification actions (no I/O recursion).
    async fn route_notice(&self, rx: &mut Receiver, a: Action) -> Result<bool, ErrorCode> {
        match a {
            Action::Progress {
                file,
                done,
                total,
                wire_bytes,
                resumed,
            } => {
                let name = rx
                    .session
                    .manifest()
                    .and_then(|m| m.file(file).map(|f| f.name.clone()))
                    .unwrap_or_default();
                match self.out.mode {
                    Mode::Json => self.out.json(serde_json::json!({
                        "type": "progress", "file": file, "name": name, "done": done,
                        "total": total, "wire_bytes": wire_bytes, "resumed": resumed,
                    })),
                    Mode::Human => self.out.progress(&name, done, total, wire_bytes, ""),
                }
                Ok(false)
            }
            Action::FileDone {
                file,
                sha256,
                verified,
            } => {
                self.out.progress_end();
                match self.out.mode {
                    Mode::Json => self.out.json(serde_json::json!({
                        "type": "fileDone", "file": file, "sha256": hex::encode(sha256),
                        "verified": verified,
                    })),
                    Mode::Human => {
                        eprintln!("file {file}: received verified={verified}");
                        eprintln!("verified: sha256 {}", hex::encode(sha256));
                    }
                }
                if let Some((path, _)) = rx.files.get(&file)
                    && let Ok(f) = std::fs::OpenOptions::new().write(true).open(path)
                {
                    let _ = f.sync_all();
                }
                Ok(false)
            }
            Action::Receipt(r) => {
                self.save_receipt(&r);
                Ok(false)
            }
            Action::Fail { code, msg } => Err(self.fail_event(code, &msg)),
            Action::SaveState => {
                self.store
                    .save_session(&rx.sid, "recv", &rx.session.snapshot())
                    .ok();
                Ok(false)
            }
            Action::EmitText(t) => {
                self.out.stderr_line(&format!("text: {}", ui::sanitize(&t)));
                Ok(false)
            }
            Action::FilesAdded(files) => {
                match self.out.mode {
                    Mode::Json => self.out.json(serde_json::json!({
                        "type": "filesAdded", "count": files.len(),
                    })),
                    Mode::Human => self
                        .out
                        .stderr_line(&format!("{} file(s) added to the share", files.len())),
                }
                Ok(false)
            }
            Action::SessionDone => Ok(true),
            _ => Ok(false),
        }
    }

    /// Open/create the target file once: ask before overwriting (unless
    /// --yes), create parents, and fix the final length with `set_len` so a
    /// stale larger file cannot leak a tail into the hash. On resume the
    /// chunks already on disk are kept (same size), and missing chunks are
    /// rewritten by offset.
    fn ensure_target(&self, rx: &mut Receiver, out_dir: &Path, file: u16) -> Result<(), ErrorCode> {
        if rx.files.contains_key(&file) {
            return Ok(());
        }
        let entry = rx
            .session
            .manifest()
            .and_then(|m| m.file(file).cloned())
            .ok_or(ErrorCode::ProtoMalformed)?;
        let path = out_dir.join(rel_path(&entry.path, &entry.name));
        if !rx.confirmed && !self.yes && path.exists() {
            eprintln!("file exists: {}", path.display());
            eprint!("overwrite? [y/N] ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            if !line.trim().eq_ignore_ascii_case("y") {
                return Err(ErrorCode::StorageFailed);
            }
        }
        rx.confirmed = true;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| ErrorCode::StorageFailed)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| ErrorCode::StorageFailed)?;
        f.set_len(entry.size)
            .map_err(|_| ErrorCode::StorageFailed)?;
        rx.files.insert(file, (path, Some(f)));
        Ok(())
    }

    fn save_chunk(
        &self,
        rx: &mut Receiver,
        out_dir: &Path,
        file: u16,
        index: u64,
        data: &[u8],
    ) -> Result<(), ErrorCode> {
        self.ensure_target(rx, out_dir, file)?;
        let chunk_size = rx
            .session
            .manifest()
            .and_then(|m| m.file(file))
            .map(|e| e.chunk_size as u64)
            .ok_or(ErrorCode::ProtoMalformed)?;
        let (_path, handle) = rx.files.get_mut(&file).ok_or(ErrorCode::StorageFailed)?;
        let f = handle.as_mut().ok_or(ErrorCode::StorageFailed)?;
        f.write_at(data, index * chunk_size)
            .map_err(|_| ErrorCode::StorageFailed)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------

/// Signaling-relay transport for the pairing blobs (Wormhole-style):
/// both sides derive the same room id from the passphrase and exchange the
/// opaque blobs through a fj-relay server. The relay sees the room id
/// (a hash of the passphrase) and ciphertext only.
pub struct RelayHandle {
    inbound: std_mpsc::Receiver<RelayEvent>,
    outbound: std_mpsc::Sender<String>,
}

/// One-line pairing code (Wormhole style): `fj-<room8>-<passphrase>`.
/// The receiver joins the room and runs PAKE with the passphrase —
/// typing this single string is enough to connect.
pub fn pairing_code(room: &str, passphrase: &str) -> String {
    format!("fj-{room}-{passphrase}")
}

/// Split a pasted pairing code into (room, passphrase). Returns None
/// when the input has no `<8 hex>-` prefix (bare passphrase input).
pub fn parse_pairing_code(input: &str) -> Option<(String, String)> {
    let t = input.trim().strip_prefix("fj-").unwrap_or(input.trim());
    let (room, rest) = t.split_once('-')?;
    if room.len() == 8 && room.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some((room.to_ascii_lowercase(), rest.trim().to_string()))
    } else {
        None
    }
}

#[derive(Debug)]
pub enum RelayEvent {
    PeerJoined,
    Blob(String),
    Gone,
}

impl RelayHandle {
    /// Room id derived from the typed passphrase (SHA-256, first 8 hex —
    /// 4.3e9 ids make collisions among a relay's live rooms negligible).
    /// Deterministic so both sides (and resumes) meet in the same room;
    /// the relay cannot invert it. With a generated 77-bit passphrase this
    /// leaks nothing usable; see SECURITY.md before allowing user-chosen
    /// passphrases over the relay.
    pub fn room_from_passphrase(passphrase: &str) -> String {
        use sha2::Digest;
        let canon = fj_protocol::pake::canonical_passphrase(passphrase);
        hex::encode(sha2::Sha256::digest(canon.as_bytes()))[..8].to_string()
    }

    /// Connect to the relay and join the room derived from the passphrase.
    pub async fn connect(url: &str, room: &str) -> Result<RelayHandle, ErrorCode> {
        use futures_util::{SinkExt, StreamExt};
        let (ws, _) = tokio_tungstenite::connect_async(url).await.map_err(|e| {
            eprintln!("relay connect failed: {e}");
            ErrorCode::IceFailed
        })?;
        let (mut sink, mut stream) = ws.split();
        sink.send(tungstenite_text(&format!(
            "{{\"t\":\"join\",\"room\":\"{room}\"}}"
        )))
        .await
        .map_err(|_| ErrorCode::IceFailed)?;
        let (blob_tx, blob_rx) = std_mpsc::channel::<RelayEvent>();
        let (out_tx, out_rx) = std_mpsc::channel::<String>();
        // drive the websocket with two forwarders: inbound → blob_rx,
        // outbound ← out_rx (std channels; no select needed)
        let in_tx = blob_tx.clone();
        tokio::spawn(async move {
            while let Some(Ok(m)) = stream.next().await {
                let tokio_tungstenite::tungstenite::Message::Text(line) = m else {
                    continue;
                };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                    continue;
                };
                match v.get("t").and_then(|t| t.as_str()) {
                    Some("msg") => {
                        if let Some(d) = v.get("data").and_then(|d| d.as_str()) {
                            let _ = in_tx.send(RelayEvent::Blob(d.to_string()));
                        }
                    }
                    Some("peer-joined") => {
                        let _ = in_tx.send(RelayEvent::PeerJoined);
                    }
                    Some("peer-left") | Some("error") => {
                        let _ = in_tx.send(RelayEvent::Gone);
                    }
                    _ => {}
                }
            }
        });
        tokio::spawn(async move {
            while let Ok(line) = out_rx.recv() {
                if sink
                    .send(tokio_tungstenite::tungstenite::Message::Text(line))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(RelayHandle {
            inbound: blob_rx,
            outbound: out_tx,
        })
    }

    /// Wait until the peer joined (sender must wait before sending blob-1).
    pub async fn wait_peer(&self) -> Result<(), ErrorCode> {
        loop {
            match self.inbound.recv_timeout(Duration::from_secs(120)) {
                Ok(RelayEvent::PeerJoined) => return Ok(()),
                Ok(RelayEvent::Gone) => return Err(ErrorCode::IceFailed),
                Ok(_) => continue,
                Err(_) => return Err(ErrorCode::IceFailed),
            }
        }
    }

    pub fn send_blob(&self, blob: &str) -> Result<(), ErrorCode> {
        let line = serde_json::json!({ "t": "msg", "data": blob }).to_string();
        self.outbound.send(line).map_err(|_| ErrorCode::IceFailed)
    }

    /// Receive the next blob (timeout: dead relay / peer never sent).
    pub async fn recv_blob(&self) -> Result<String, ErrorCode> {
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            if std::time::Instant::now() > deadline {
                return Err(ErrorCode::IceFailed);
            }
            match self.inbound.recv_timeout(Duration::from_millis(200)) {
                Ok(RelayEvent::Blob(b)) => return Ok(b),
                Ok(RelayEvent::Gone) => return Err(ErrorCode::IceFailed),
                Ok(_) => continue,
                Err(std_mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ErrorCode::IceFailed);
                }
            }
        }
    }
}

fn tungstenite_text(line: &str) -> tokio_tungstenite::tungstenite::Message {
    tokio_tungstenite::tungstenite::Message::Text(line.to_string())
}

fn rel_path(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

struct SendCtx {
    session: Session,
    peer: Arc<PeerHandle>,
    #[allow(dead_code)]
    passphrase: String,
    sid: String,
    frames: std_mpsc::Receiver<Vec<u8>>,
    /// channels actually negotiated for this context (resume-safe)
    channels: usize,
}

struct Receiver {
    session: Session,
    peer: Arc<PeerHandle>,
    sid: String,
    files: HashMap<u16, (PathBuf, Option<std::fs::File>)>,
    confirmed: bool,
    frames: std_mpsc::Receiver<Vec<u8>>,
    /// signaling relay (relay mode); kept alive through the transfer loop —
    /// read only for the p3 blob-4 emission during pairing
    #[allow(dead_code)]
    relay: Option<RelayHandle>,
}

/// Read one stdin line: in JSON mode the line is an NDJSON event and the
/// blob is extracted from `field` ("blob1"/"blob2"/"blob3"/"blob4"); in human
/// mode the line IS the blob.
fn read_blob_field(mode: Mode, field: &str) -> Result<String, ErrorCode> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|_| ErrorCode::StorageFailed)?;
    let t = line.trim().to_string();
    if t.is_empty() {
        eprintln!("pairing input closed before the blob arrived (peer aborted?)");
        return Err(ErrorCode::SecPakeFailed);
    }
    if mode == Mode::Json
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&t)
        && let Some(b) = v[field].as_str()
    {
        return Ok(b.to_string());
    }
    Ok(t)
}

fn probe_gzip(path: &Path, size: u64) -> Result<bool, ErrorCode> {
    let take = (4 * fj_protocol::CHUNK_SIZE_DEFAULT as u64).min(size);
    let mut buf = vec![0u8; take as usize];
    let mut f = std::fs::File::open(path).map_err(|_| ErrorCode::StorageFailed)?;
    f.read_exact(&mut buf)
        .map_err(|_| ErrorCode::StorageFailed)?;
    let comp = fj_protocol::session::gzip_probe_bytes(&buf);
    Ok((comp as f64) < 0.9 * buf.len() as f64)
}

/// Sequential read helper: seeks + reads a chunk range.
struct TakeReader {
    f: std::fs::File,
}

impl TakeReader {
    fn new(f: std::fs::File) -> TakeReader {
        TakeReader { f }
    }

    fn read_range(&mut self, index: u64, chunk_size: u64, len: u32) -> Result<Vec<u8>, ErrorCode> {
        let mut buf = vec![0u8; len as usize];
        self.f
            .seek(SeekFrom::Start(index * chunk_size))
            .map_err(|_| ErrorCode::StorageFailed)?;
        self.f
            .read_exact(&mut buf)
            .map_err(|_| ErrorCode::StorageFailed)?;
        Ok(buf)
    }
}

// keep tokio_mpsc in scope for future text-chat wiring
#[allow(unused_imports)]
use tokio_mpsc as _tokio_mpsc;

#[cfg(test)]
mod code_tests {
    use super::{RelayHandle, pairing_code, parse_pairing_code};

    #[test]
    fn code_roundtrip() {
        let room = RelayHandle::room_from_passphrase("word-one-word-two");
        let code = pairing_code(&room, "word-one-word-two");
        assert!(code.starts_with("fj-"));
        let (r, p) = parse_pairing_code(&code).expect("parses");
        assert_eq!(r, room);
        assert_eq!(p, "word-one-word-two");
    }

    #[test]
    fn code_parses_without_prefix_and_case_insensitive_room() {
        let (r, p) = parse_pairing_code("AB12CD34-word-one-word-two").unwrap();
        assert_eq!(r, "ab12cd34");
        assert_eq!(p, "word-one-word-two");
        assert_eq!(
            parse_pairing_code("fj-ab12cd34-x"),
            Some(("ab12cd34".into(), "x".into()))
        );
    }

    #[test]
    fn bare_passphrase_is_not_a_code() {
        // first word segment is not 8 hex -> None (fallback path)
        assert!(parse_pairing_code("word-one-word-two-word-three").is_none());
        assert!(parse_pairing_code("").is_none());
    }
}
