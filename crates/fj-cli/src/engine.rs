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

use fj_protocol::ErrorCode;
use fj_protocol::manifest::FileSpec;
use fj_protocol::pake::AttemptLimiter;
use fj_protocol::session::{Action, Session, SessionOpts};
use fj_webrtc::{IceConfig, PeerHandle};
use tokio::sync::mpsc as tokio_mpsc;

use crate::store::Store;
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
    pub passphrase_prompt: Option<String>, // resume: passphrase known up-front
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
        let listing = collect_files(paths).map_err(|_| ErrorCode::StorageFailed)?;
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

        // manifests: same file list for every receiver session
        let specs: Vec<FileSpec> = locals.iter().map(|l| l.spec.clone()).collect();
        for ctx in &mut ctxs {
            ctx.session.set_files(&specs).map_err(|e| {
                eprintln!("manifest rejected: {}", e.msg());
                ErrorCode::PathRejected
            })?;
        }

        // open channels for every receiver (wait for the wire first: HELO
        // must not race the channel open)
        for ctx in &mut ctxs {
            if std::env::var("FJ_DEBUG").is_ok() {
                eprintln!(
                    "[fj-debug pid={}] sender: waiting channels open",
                    std::process::id()
                );
            }
            ctx.peer
                .wait_channels_open(Duration::from_secs(20))
                .await
                .map_err(|_| {
                    eprintln!("data channel did not open (ICE failed?)");
                    ErrorCode::IceFailed
                })?;
            if std::env::var("FJ_DEBUG").is_ok() {
                eprintln!(
                    "[fj-debug pid={}] sender: channels open",
                    std::process::id()
                );
            }
            let actions = ctx.session.on_channel_open();
            if std::env::var("FJ_DEBUG").is_ok() {
                eprintln!(
                    "[fj-debug pid={}] sender: on_channel_open -> {} actions",
                    std::process::id(),
                    actions.len()
                );
            }
            for a in actions {
                self.route_sender(ctx, a).await?;
            }
            self.emit_path(&ctx.peer).await;
        }
        self.emit_manifest(&locals, total);

        let pause_flag = Arc::new(AtomicBool::new(false));
        crate::signals::install(pause_flag.clone());

        let mut readers: Vec<TakeReader> = Vec::with_capacity(locals.len());
        for l in &locals {
            let f = std::fs::File::open(&l.path).map_err(|_| ErrorCode::StorageFailed)?;
            readers.push(TakeReader::new(f));
        }

        self.drive_sender(&mut ctxs, &locals, &mut readers, &pause_flag)
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
        let peer = PeerHandle::new(&self.ice)
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let offer_sdp = peer
            .create_offer(self.channels)
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let (mut session, passphrase, blob1) = match resume {
            None => Session::initiator_new(SessionOpts {
                words,
                private3,
                chunk_size: fj_protocol::CHUNK_SIZE_DEFAULT,
                sid: None,
                offer_sdp,
            })
            .map_err(|e| {
                eprintln!("pairing failed: {}", e.msg());
                ErrorCode::SecPakeFailed
            })?,
            Some((sid, pass)) => {
                let snap = self
                    .store
                    .load_session(sid)
                    .ok_or(ErrorCode::StorageFailed)?;
                let mut s = Session::restore(&snap).map_err(|e| {
                    eprintln!("bad session state: {}", e.msg());
                    ErrorCode::StorageFailed
                })?;
                let blob1 = s.resume_initiator(pass, &offer_sdp).map_err(|e| {
                    eprintln!("resume pairing failed: {}", e.msg());
                    ErrorCode::SecPakeFailed
                })?;
                (s, pass.to_string(), blob1)
            }
        };
        let sid = session.sid_hex();

        match self.out.mode {
            Mode::Json => self.out.json(serde_json::json!({
                "type": "hello", "sid": sid, "passphrase": passphrase, "blob1": blob1,
                "private3": private3,
            })),
            Mode::Human => {
                if resume.is_some() {
                    eprintln!("\x1b[1;33mresume passphrase (same as the original session):\x1b[0m");
                } else {
                    eprintln!("\x1b[1;33mpassphrase (say it, don't send it):\x1b[0m");
                }
                eprintln!("\x1b[1;32m{passphrase}\x1b[0m");
                eprintln!("blob-1 (paste to the other side):");
                println!("{blob1}");
                let _ = std::io::stdout().flush();
            }
        }

        let blob2 = read_blob_field(self.out.mode, "blob2")?;
        if std::env::var("FJ_DEBUG").is_ok() {
            eprintln!(
                "[fj-debug pid={}] got blob2 ({} bytes)",
                std::process::id(),
                blob2.len()
            );
        }
        session.initiator_accept(&blob2).map_err(|e| {
            eprintln!("[{}] pairing failed: {}", e.code(), e.msg());
            ErrorCode::SecPakeFailed
        })?;
        if private3 {
            let blob3 = session.initiator_private_blob3().map_err(|e| {
                eprintln!("[{}] {}", e.code(), e.msg());
                ErrorCode::SecPakeFailed
            })?;
            match self.out.mode {
                Mode::Json => self
                    .out
                    .json(serde_json::json!({"type": "blob3", "blob3": blob3})),
                Mode::Human => {
                    eprintln!("blob-3 (paste to the other side):");
                    println!("{blob3}");
                    let _ = std::io::stdout().flush();
                }
            }
            let blob4 = read_blob_field(self.out.mode, "blob4")?;
            session.initiator_private_final(&blob4).map_err(|e| {
                eprintln!("[{}] {}", e.code(), e.msg());
                ErrorCode::SecPakeFailed
            })?;
        }
        // apply the answer to the peer connection (connectivity starts here)
        peer.set_answer(session.answer_sdp())
            .await
            .map_err(|_| ErrorCode::IceFailed)?;
        let frames = wire_frames(&peer, self.channels).await;
        Ok(SendCtx {
            session,
            peer,
            passphrase,
            sid,
            frames,
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
        let kind = if cand == "relay" { "relay" } else { "direct" };
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
                for ch in 0..self.channels.max(1) {
                    ctx.peer
                        .send_backpressured(ch, bytes.clone())
                        .await
                        .map_err(|_| ErrorCode::IceFailed)?;
                }
                Ok(false)
            }
            Action::SaveState => {
                self.store
                    .save_session(&ctx.sid, &ctx.session.snapshot())
                    .ok();
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
            Action::Fail { code, msg } => {
                eprintln!("[{code}] {msg}");
                Err(code)
            }
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
    ) -> Result<(), ErrorCode> {
        let mut done_count = 0usize;
        loop {
            // 1) drain inbound frames
            for ctx in ctxs.iter_mut() {
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
                                    done_count += 1;
                                }
                            }
                        }
                    }
                }
            }
            if done_count >= ctxs.len() {
                return Ok(());
            }
            if pause_flag.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            // 2) push one chunk per receiver per round (shared disk read)
            let mut pushed = 0usize;
            for ctx in ctxs.iter_mut() {
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
                    if std::env::var("FJ_DEBUG").is_ok() && index < 2 {
                        eprintln!(
                            "[fj-debug pid={}] sender: pushed chunk file={fi} idx={index} wire={}",
                            std::process::id(),
                            wire.len()
                        );
                    }
                    let ch = (index as usize) % self.channels.max(1);
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
                                done_count += 1;
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
            if pushed == 0 {
                tokio::time::sleep(Duration::from_millis(15)).await;
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
        // 1) blob-1 (or the hello event) from stdin
        let blob1 = read_blob_field(self.out.mode, "blob1")?;
        let passphrase = match &self.passphrase_prompt {
            Some(p) => p.clone(),
            None => read_line_prompt("passphrase: "),
        };
        if passphrase.is_empty() {
            eprintln!("no passphrase given");
            return Err(ErrorCode::SecPakeFailed);
        }

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
        let channels = count_sctp_streams(&env1.sdp.clone().unwrap_or_default()).max(1);
        let private3 = mode == fj_protocol::envelope::PairingMode::P3;

        let mut session = match resume_sid {
            None => {
                let offer = env1.sdp.clone().unwrap_or_default();
                let answer = peer
                    .accept_offer(&offer, channels)
                    .await
                    .map_err(|_| ErrorCode::IceFailed)?;
                let (mut s, blob2) =
                    Session::responder_join(&blob1, &passphrase, &answer, &mut limiter).map_err(
                        |e| {
                            eprintln!("[{}] {}", e.code(), e.msg());
                            e.code()
                        },
                    )?;
                self.emit_blob2(&blob2);
                if private3 {
                    self.p3_responder(&peer, &mut s, channels, &mut limiter)
                        .await?;
                }
                s
            }
            Some(sid_hex) => {
                let snap = self
                    .store
                    .load_session(sid_hex)
                    .or_else(|| self.store.load_session(&hex::encode(sid)))
                    .ok_or(ErrorCode::StorageFailed)?;
                let mut s = Session::restore(&snap).map_err(|e| {
                    eprintln!("bad session state: {}", e.msg());
                    ErrorCode::StorageFailed
                })?;
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
                self.emit_blob2(&blob2);
                if private3 {
                    self.p3_responder(&peer, &mut s, channels, &mut limiter)
                        .await?;
                }
                s
            }
        };

        let frames = wire_frames(&peer, channels.max(self.channels)).await;
        let mut rx = Receiver {
            session,
            peer,
            sid: hex::encode(sid),
            files: HashMap::new(),
            confirmed: false,
            frames,
            channels: channels.max(self.channels),
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

        loop {
            match rx.frames.try_recv() {
                Ok(frame) => {
                    let actions = rx.session.on_frame(&frame).map_err(|e| e.code())?;
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
    ) -> Result<(), ErrorCode> {
        let blob3 = read_blob_field(self.out.mode, "blob3")?;
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

    fn emit_blob2(&self, blob2: &str) {
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
                for ch in 0..rx.channels.max(1) {
                    rx.peer
                        .send_backpressured(ch, bytes.clone())
                        .await
                        .map_err(|_| ErrorCode::IceFailed)?;
                }
                Ok(false)
            }
            Action::SaveChunk { file, index, data } => {
                self.save_chunk(rx, out_dir, file, index, &data)?;
                Ok(false)
            }
            Action::HashFeed { file } => {
                let path = rx
                    .files
                    .get(&file)
                    .map(|(p, _)| p.clone())
                    .ok_or(ErrorCode::StorageFailed)?;
                let mut buf = Vec::new();
                std::fs::File::open(&path)
                    .map_err(|_| ErrorCode::StorageFailed)?
                    .read_to_end(&mut buf)
                    .map_err(|_| ErrorCode::StorageFailed)?;
                // hash_feed actions are flat: notices + Send(RECEIPT) + SessionDone
                let actions = rx.session.hash_feed(file, &buf).map_err(|e| e.code())?;
                for a in actions {
                    match a {
                        Action::Send(bytes) => {
                            for ch in 0..rx.channels.max(1) {
                                rx.peer
                                    .send_backpressured(ch, bytes.clone())
                                    .await
                                    .map_err(|_| ErrorCode::IceFailed)?;
                            }
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
                if let Some((path, _)) = rx.files.get(&file) {
                    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
                        let _ = f.sync_all();
                    }
                }
                Ok(false)
            }
            Action::Receipt(r) => {
                self.save_receipt(&r);
                Ok(false)
            }
            Action::Fail { code, msg } => {
                eprintln!("[{code}] {msg}");
                Err(code)
            }
            Action::SaveState => {
                self.store
                    .save_session(&rx.sid, &rx.session.snapshot())
                    .ok();
                Ok(false)
            }
            Action::EmitText(t) => {
                self.out.stderr_line(&format!("text: {t}"));
                Ok(false)
            }
            Action::SessionDone => Ok(true),
            _ => Ok(false),
        }
    }

    fn save_chunk(
        &self,
        rx: &mut Receiver,
        out_dir: &Path,
        file: u16,
        index: u64,
        data: &[u8],
    ) -> Result<(), ErrorCode> {
        let entry = rx
            .session
            .manifest()
            .and_then(|m| m.file(file).cloned())
            .ok_or(ErrorCode::ProtoMalformed)?;
        if !rx.confirmed && !self.yes {
            let target = out_dir.join(rel_path(&entry.path, &entry.name));
            if target.exists() {
                eprintln!("file exists: {}", target.display());
                eprint!("overwrite? [y/N] ");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                let _ = std::io::stdin().lock().read_line(&mut line);
                if !line.trim().eq_ignore_ascii_case("y") {
                    return Err(ErrorCode::StorageFailed);
                }
            }
            rx.confirmed = true;
        }
        let (_path, handle) = rx.files.entry(file).or_insert_with(|| {
            let path = out_dir.join(rel_path(&entry.path, &entry.name));
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .ok();
            (path, f)
        });
        let f = handle.as_mut().ok_or(ErrorCode::StorageFailed)?;
        f.write_at(data, index * entry.chunk_size as u64)
            .map_err(|_| ErrorCode::StorageFailed)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------

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
}

struct Receiver {
    session: Session,
    peer: Arc<PeerHandle>,
    sid: String,
    files: HashMap<u16, (PathBuf, Option<std::fs::File>)>,
    confirmed: bool,
    frames: std_mpsc::Receiver<Vec<u8>>,
    channels: usize,
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
    if mode == Mode::Json {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
            if let Some(b) = v[field].as_str() {
                return Ok(b.to_string());
            }
        }
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

/// Count `m=application` sections in an SDP (number of SCTP data channels).
fn count_sctp_streams(sdp: &str) -> usize {
    sdp.lines()
        .filter(|l| l.starts_with("m=application"))
        .count()
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
