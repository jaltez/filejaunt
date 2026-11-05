//! Sans-IO transfer state machine.
//!
//! The glue (CLI / WASM web client) owns WebRTC, files and timers; this
//! module owns everything protocol: pairing, HELO verification, manifest,
//! chunk scheduling (sequential-first; holes-first after a resume BITMAP),
//! pause/resume/cancel, receipts and session snapshots.
//!
//! All outbound frames are returned as already-encrypted wire bytes in
//! `Action::Send` (header in the clear, payload AES-GCM with the
//! direction/epoch key and the session's tx counter), so the glue can never
//! desynchronize counters.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

use crate::bitmap::{Bitmap, BitmapJson};
use crate::crypto::{self, Dir, Key32};
use crate::envelope::{Envelope1, Envelope2, Envelope3, Envelope4, PairingMode, validate_env1};
use crate::error::{ErrorCode, Result, err};
use crate::frame::Frame;
use crate::manifest::{FileSpec, Manifest, build_manifest};
use crate::pake::{AttemptLimiter, PakeSide};
use crate::receipt::{Receipt, ReceiptMsg};
use crate::{
    FILE_ALL, MAX_CHUNK_DATA, MAX_TEXT_BYTES, PROTOCOL_VERSION, SAVE_EVERY_CHUNKS, WORDS_DEFAULT,
    words,
};

use crate::crypto::Dir::{InitiatorToResponder, ResponderToInitiator};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Sender: creates the offer, pushes chunks. SPAKE2 side A.
    Initiator,
    /// Receiver: joins, writes files. SPAKE2 side B.
    Responder,
}

/// Options for a fresh initiator session.
#[derive(Debug, Clone)]
pub struct SessionOpts {
    /// Words in the generated passphrase (4..=12, default 6).
    pub words: usize,
    /// Private 3-step pairing (SDP never in clear).
    pub private3: bool,
    /// Chunk size (CHUNK_SIZE_DEFAULT or negotiated CHUNK_SIZE_LARGE).
    pub chunk_size: u32,
    /// Data channels to announce (1 or CHANNELS_MAX).
    pub channels: usize,
    /// Deterministic sid (test vectors only; None = OsRng).
    pub sid: Option<[u8; 16]>,
    /// The offer SDP created by the glue BEFORE pairing starts.
    pub offer_sdp: String,
}

impl Default for SessionOpts {
    fn default() -> Self {
        SessionOpts {
            words: WORDS_DEFAULT,
            private3: false,
            chunk_size: crate::CHUNK_SIZE_DEFAULT,
            channels: 1,
            sid: None,
            offer_sdp: String::new(),
        }
    }
}

/// Instructions to the glue. `Send` carries encrypted wire bytes ready for
/// the DataChannel.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Send(Vec<u8>),
    /// Persist `session.snapshot()` now.
    SaveState,
    /// Write decrypted (and decompressed) chunk data at the file's chunk index.
    SaveChunk {
        file: u16,
        index: u64,
        data: Vec<u8>,
    },
    /// Re-read the completed file from storage and feed `hash_feed`.
    HashFeed {
        file: u16,
    },
    /// done/total in bytes; wire_bytes attributed to this file.
    Progress {
        file: u16,
        done: u64,
        total: u64,
        wire_bytes: u64,
        resumed: bool,
    },
    /// Receiver: file complete and hash-verified. Sender: receipt accepted.
    FileDone {
        file: u16,
        sha256: [u8; 32],
        verified: bool,
    },
    EmitText(String),
    Receipt(Receipt),
    SessionDone,
    Fail {
        code: ErrorCode,
        msg: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Keys derived, SDPs known; waiting for the DataChannel to open.
    Paired,
    /// Channel open, HELO sent; peer HELO may still be pending.
    HeloPending,
    /// Both HELOs verified.
    Active,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileSnap {
    id: u16,
    #[serde(default)]
    sent: Option<BitmapJson>,
    #[serde(default)]
    acked: Option<BitmapJson>,
    #[serde(default)]
    have: Option<BitmapJson>,
    #[serde(default)]
    done_claimed: bool,
    #[serde(default)]
    done_sent: bool,
    #[serde(default)]
    file_done: bool,
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    receipt_sent: bool,
    #[serde(default)]
    bytes_moved: u64,
    #[serde(default)]
    wire_bytes: u64,
    #[serde(default)]
    dups: u64,
    #[serde(default)]
    gzip: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    v: u8,
    role: Role,
    sid: String,
    epoch: u32,
    #[serde(default)]
    private3: bool,
    manifest: Option<Manifest>,
    tx: u32,
    rx: u32,
    ctrl_seq: u32,
    #[serde(default)]
    resumed: bool,
    files: Vec<FileSnap>,
    paused: Vec<u16>,
    cancelled: Vec<u16>,
}

/// Per-file live state shared by both roles (fields used per role).
struct FileState {
    id: u16,
    /// Sender: chunks pushed this epoch.
    sent: Bitmap,
    /// Sender: chunks the receiver confirmed (BITMAP).
    acked: Bitmap,
    /// Receiver: chunks written.
    have: Bitmap,
    done_claimed: bool,
    done_sent: bool,
    file_done: bool,
    verified: bool,
    receipt_sent: bool,
    bytes_moved: u64,
    wire_bytes: u64,
    dups: u64,
    gzip: Option<bool>,
}

pub struct Session {
    role: Role,
    sid: [u8; 16],
    epoch: u32,
    private3: bool,
    channels: usize,
    chunk_size: u32,
    passphrase: Zeroizing<String>,
    k_root: Option<Key32>,
    k_tx: Option<Key32>,
    k_rx: Option<Key32>,
    k_confirm: Option<Key32>,
    k_receipt: Option<Key32>,
    k_pf: Option<Key32>,
    pake: Option<PakeSide>,
    pake1_b64: String,
    pake2_b64: String,
    offer_sdp: String,
    answer_sdp: String,
    tx_counter: u32,
    rx_counter: u32,
    ctrl_seq: u32,
    phase: Phase,
    helo_sent: bool,
    helo_received: bool,
    manifest_sent: bool,
    manifest: Option<Manifest>,
    files: Vec<FileState>,
    paused: BTreeSet<u16>,
    cancelled: BTreeSet<u16>,
    resumed: bool,
    chunks_since_save: u64,
    hashers: std::collections::HashMap<u16, (sha2::Sha256, u64)>,
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Session {
    // ------------------------------------------------------------------
    // Fresh pairing: 2-step (p2)
    // ------------------------------------------------------------------

    /// Create the initiator (sender) session: generates the passphrase and
    /// envelope-1. Call `set_files` before the channel opens.
    pub fn initiator_new(opts: SessionOpts) -> Result<(Session, String, String)> {
        let passphrase = words::generate(opts.words)?;
        let sid = opts.sid.unwrap_or_else(crate::pake::new_sid);
        let mut s = Session::empty(Role::Initiator, sid, 0, opts.private3, &passphrase)?;
        s.chunk_size = opts.chunk_size;
        s.channels = opts.channels.clamp(1, crate::CHANNELS_MAX);
        s.pair_start(&opts.offer_sdp)?;
        let blob1 = s.build_envelope1()?;
        Ok((s, passphrase, blob1))
    }

    /// Responder joins with envelope-1 + the passphrase + the answer SDP its
    /// glue created after applying the (clear, p2-only) offer.
    pub fn responder_join(
        blob1_raw: &str,
        passphrase: &str,
        answer_sdp: &str,
        limiter: &mut AttemptLimiter,
    ) -> Result<(Session, String)> {
        let env1 = Session::parse_envelope1(blob1_raw)?;
        let (sid, mode) = validate_env1(&env1)?;
        let canonical = crate::pake::canonical_passphrase(passphrase);
        let mut s = Session::empty(
            Role::Responder,
            sid,
            env1.ep,
            mode == PairingMode::P3,
            &canonical,
        )?;
        s.pair_respond(&env1).inspect_err(|_| {
            let _ = limiter.record_failure(&sid);
        })?;
        s.answer_sdp = answer_sdp.to_string();
        let blob2 = s.build_envelope2(mode)?;
        Ok((s, blob2))
    }

    /// Initiator consumes envelope-2: finishes PAKE, decrypts the answer
    /// (p2). SEC_PAKE_FAILED on wrong passphrase / tampered envelope.
    pub fn initiator_accept(&mut self, blob2_raw: &str) -> Result<Vec<Action>> {
        self.ensure_role(Role::Initiator)?;
        let env2: Envelope2 =
            serde_json::from_str(&crate::envelope::inflate(blob2_raw)?).map_err(|e| {
                crate::error::Error::new(ErrorCode::ProtoMalformed, format!("bad envelope-2: {e}"))
            })?;
        self.pair_finish(&env2.pake)?;
        if let Some(sdpe) = &env2.sdpe {
            let ct = crate::envelope::b64_decode(sdpe)?;
            let k = self.k_root.as_ref().expect("k_root");
            self.answer_sdp =
                crypto::decrypt_sdp(&crypto::derive_env_answer(k, &self.sid), "sdp-answer", &ct)
                    .map_err(|e| {
                        crate::error::Error::new(ErrorCode::SecPakeFailed, e.msg().to_string())
                    })?;
        }
        // p3: blob-2 carries only the PAKE message; the answer arrives
        // encrypted in blob-4 (initiator_private_final).
        self.phase = Phase::Paired;
        Ok(vec![])
    }

    // ------------------------------------------------------------------
    // Private 3-step (p3): all SDP encrypted
    // ------------------------------------------------------------------

    /// Initiator -> responder: encrypted offer.
    pub fn initiator_private_blob3(&mut self) -> Result<String> {
        self.ensure_role(Role::Initiator)?;
        if !self.private3 {
            return err(ErrorCode::ProtoMalformed, "session is not in private mode");
        }
        let k = self.k_root.as_ref().expect("k_root");
        let ct = crypto::encrypt_sdp(
            &crypto::derive_env_offer(k, &self.sid),
            "sdp-offer",
            &self.offer_sdp,
        );
        crate::envelope::serialize(&Envelope3 {
            v: PROTOCOL_VERSION,
            sdpe: crate::envelope::b64(&ct),
        })
    }

    /// Responder decrypts blob-3 and returns the offer SDP for the glue to
    /// apply before creating its answer.
    pub fn responder_private_offer(
        &mut self,
        blob3_raw: &str,
        limiter: &mut AttemptLimiter,
    ) -> Result<String> {
        self.ensure_role(Role::Responder)?;
        let env3: Envelope3 =
            serde_json::from_str(&crate::envelope::inflate(blob3_raw)?).map_err(|e| {
                crate::error::Error::new(ErrorCode::ProtoMalformed, format!("bad envelope-3: {e}"))
            })?;
        let ct = crate::envelope::b64_decode(&env3.sdpe)?;
        let k = self.k_root.as_ref().expect("k_root");
        match crypto::decrypt_sdp(&crypto::derive_env_offer(k, &self.sid), "sdp-offer", &ct) {
            Ok(offer) => {
                limiter.clear(&self.sid);
                self.offer_sdp = offer.clone();
                Ok(offer)
            }
            Err(e) => {
                limiter.record_failure(&self.sid)?;
                Err(crate::error::Error::new(
                    ErrorCode::SecPakeFailed,
                    e.msg().to_string(),
                ))
            }
        }
    }

    /// Responder -> initiator: encrypted answer (after the glue created it).
    pub fn responder_private_blob4(&mut self, answer_sdp: &str) -> Result<String> {
        self.ensure_role(Role::Responder)?;
        self.answer_sdp = answer_sdp.to_string();
        let k = self.k_root.as_ref().expect("k_root");
        let ct = crypto::encrypt_sdp(
            &crypto::derive_env_answer(k, &self.sid),
            "sdp-answer",
            answer_sdp,
        );
        crate::envelope::serialize(&Envelope4 {
            v: PROTOCOL_VERSION,
            sdpe: crate::envelope::b64(&ct),
        })
    }

    /// Initiator consumes blob-4.
    pub fn initiator_private_final(&mut self, blob4_raw: &str) -> Result<Vec<Action>> {
        self.ensure_role(Role::Initiator)?;
        let env4: Envelope4 =
            serde_json::from_str(&crate::envelope::inflate(blob4_raw)?).map_err(|e| {
                crate::error::Error::new(ErrorCode::ProtoMalformed, format!("bad envelope-4: {e}"))
            })?;
        let ct = crate::envelope::b64_decode(&env4.sdpe)?;
        let k = self.k_root.as_ref().expect("k_root");
        self.answer_sdp =
            crypto::decrypt_sdp(&crypto::derive_env_answer(k, &self.sid), "sdp-answer", &ct)
                .map_err(|e| {
                    crate::error::Error::new(ErrorCode::SecPakeFailed, e.msg().to_string())
                })?;
        self.phase = Phase::Paired;
        Ok(vec![])
    }

    // ------------------------------------------------------------------
    // Resume (epoch + 1, same passphrase, fresh pairing)
    // ------------------------------------------------------------------

    /// Restored initiator re-pairs: bumps the epoch, returns envelope-1.
    pub fn resume_initiator(&mut self, passphrase: &str, offer_sdp: &str) -> Result<String> {
        self.ensure_role(Role::Initiator)?;
        if self.manifest.is_none() {
            return err(
                ErrorCode::ProtoMalformed,
                "cannot resume without a manifest",
            );
        }
        self.epoch = self.epoch.checked_add(1).ok_or_else(|| {
            crate::error::Error::new(ErrorCode::ProtoMalformed, "epoch exhausted")
        })?;
        self.reset_transport_state();
        self.passphrase = Zeroizing::new(crate::pake::canonical_passphrase(passphrase));
        self.pair_start(offer_sdp)?;
        self.resumed = true;
        self.build_envelope1()
    }

    /// Restored responder re-pairs via a fresh envelope-1 (same sid, ep =
    /// its epoch + 1) and a new answer SDP.
    pub fn resume_responder(
        &mut self,
        blob1_raw: &str,
        passphrase: &str,
        answer_sdp: &str,
        limiter: &mut AttemptLimiter,
    ) -> Result<String> {
        self.ensure_role(Role::Responder)?;
        if self.manifest.is_none() {
            return err(
                ErrorCode::ProtoMalformed,
                "cannot resume without a manifest",
            );
        }
        let env1 = Session::parse_envelope1(blob1_raw)?;
        let (sid, mode) = validate_env1(&env1)?;
        if sid != self.sid {
            return err(ErrorCode::ProtoMalformed, "resume sid mismatch");
        }
        if env1.ep != self.epoch + 1 {
            return err(ErrorCode::ProtoMalformed, "resume epoch must be exactly +1");
        }
        self.epoch = env1.ep;
        self.reset_transport_state();
        self.passphrase = Zeroizing::new(crate::pake::canonical_passphrase(passphrase));
        self.pair_respond(&env1).inspect_err(|_| {
            let _ = limiter.record_failure(&sid);
        })?;
        self.answer_sdp = answer_sdp.to_string();
        self.resumed = true;
        self.build_envelope2(mode)
    }

    /// After HELO on a resumed connection the receiver emits BITMAPs of the
    /// chunks it still needs.
    pub fn on_resume_handshake(&mut self) -> Vec<Action> {
        if self.role != Role::Responder || !self.resumed {
            return vec![];
        }
        self.emit_missing_bitmaps()
    }

    fn emit_missing_bitmaps(&mut self) -> Vec<Action> {
        let mut actions = vec![Action::SaveState];
        let pending: Vec<(u16, Vec<(u64, u64)>)> = self
            .files
            .iter()
            .filter(|f| !f.file_done && !f.have.is_full())
            .map(|f| (f.id, f.have.to_runs()))
            .collect();
        for (file, runs) in pending {
            actions.push(self.send(Frame::Bitmap { file, runs }));
        }
        actions
    }

    // ------------------------------------------------------------------
    // Sender file setup
    // ------------------------------------------------------------------

    /// Initiator: set the files to transfer (call before channel open).
    pub fn set_files(&mut self, specs: &[FileSpec]) -> Result<()> {
        self.ensure_role(Role::Initiator)?;
        let manifest = build_manifest(&self.sid, self.epoch, specs, self.chunk_size)?;
        self.set_manifest(manifest)?;
        // carry the per-file compression decision into the send state
        for (i, spec) in specs.iter().enumerate() {
            if let Some(f) = self.files.get_mut(i) {
                f.gzip = Some(spec.gzip);
            }
        }
        Ok(())
    }

    pub(crate) fn set_manifest(&mut self, manifest: Manifest) -> Result<()> {
        manifest.validate()?;
        self.files = manifest
            .files
            .iter()
            .map(|f| FileState {
                id: f.id,
                sent: Bitmap::new(f.chunks),
                acked: Bitmap::new(f.chunks),
                have: Bitmap::new(f.chunks),
                done_claimed: false,
                done_sent: false,
                file_done: false,
                verified: false,
                receipt_sent: false,
                bytes_moved: 0,
                wire_bytes: 0,
                dups: 0,
                gzip: None,
            })
            .collect();
        self.manifest = Some(manifest);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Channel lifecycle
    // ------------------------------------------------------------------

    /// The glue calls this once the DataChannel is open. Emits encrypted
    /// HELO (and, for the initiator, MANIFEST + DONEs for empty files).
    pub fn on_channel_open(&mut self) -> Vec<Action> {
        if self.phase != Phase::Paired {
            return vec![
                self.fail_action(ErrorCode::ProtoMalformed, "channel opened in wrong phase"),
            ];
        }
        let mut actions = vec![self.send_helo()];
        self.phase = Phase::HeloPending;
        if self.role == Role::Initiator && self.manifest.is_some() {
            actions.extend(self.send_manifest_action());
        }
        actions
    }

    /// Send the MANIFEST if the channel opened before files were set.
    pub fn send_manifest_if_pending(&mut self) -> Vec<Action> {
        if self.role == Role::Initiator && self.phase != Phase::Paired && !self.manifest_sent {
            self.manifest_sent = true;
            self.send_manifest_action()
        } else {
            vec![]
        }
    }

    fn send_helo(&mut self) -> Action {
        let k = self.k_confirm.as_ref().expect("keys derived");
        let fp = crypto::confirm_fp(k, &self.offer_sdp, &self.answer_sdp, &self.sid);
        let role_byte = match self.role {
            Role::Initiator => 0,
            Role::Responder => 1,
        };
        self.send(Frame::Hello {
            role: role_byte,
            version: PROTOCOL_VERSION,
            fp,
        })
    }

    fn send_manifest_action(&mut self) -> Vec<Action> {
        self.manifest_sent = true;
        let manifest = self.manifest.clone().expect("initiator has manifest");
        // record per-file gzip decisions from the manifest policy
        let mut actions = vec![self.send(Frame::Manifest(manifest)), Action::SaveState];
        // empty files are immediately DONE
        let empty: Vec<u16> = self
            .files
            .iter()
            .filter(|f| {
                self.manifest
                    .as_ref()
                    .unwrap()
                    .file(f.id)
                    .map(|e| e.chunks == 0)
                    .unwrap_or(false)
            })
            .map(|f| f.id)
            .collect();
        for id in empty {
            if let Some(f) = self.files.iter_mut().find(|f| f.id == id) {
                f.done_sent = true;
            }
            actions.push(self.send(Frame::Done { file: id }));
        }
        actions
    }

    // ------------------------------------------------------------------
    // Frame I/O
    // ------------------------------------------------------------------

    /// Feed one complete wire message (as received on the DataChannel).
    /// Decrypts with the rx counter, decodes, advances the state machine.
    pub fn on_frame(&mut self, wire: &[u8]) -> Result<Vec<Action>> {
        if wire.len() < crate::FRAME_HEADER_LEN {
            return err(ErrorCode::ProtoMalformed, "frame shorter than header");
        }
        let mut header = [0u8; 12];
        header.copy_from_slice(&wire[..12]);
        let frame = match self.decrypt(&header, &wire[12..]) {
            Ok(f) => f,
            Err(e) => {
                if std::env::var("FJ_DEBUG").is_ok() {
                    eprintln!(
                        "[fj-debug pid={}] DECRYPT FAIL type=0x{:02x} seq={}",
                        std::process::id(),
                        wire[1],
                        u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]])
                    );
                }
                self.phase = Phase::Failed;
                return Ok(vec![Action::Fail {
                    code: e.code(),
                    msg: e.msg().to_string(),
                }]);
            }
        };
        self.handle_frame(frame)
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<Vec<Action>> {
        // First frame from the peer must be HELO.
        if !self.helo_received {
            let Frame::Hello { role, version, fp } = frame else {
                self.phase = Phase::Failed;
                return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "first frame was not HELO"));
            };
            return self.on_helo(role, version, fp);
        }
        match frame {
            Frame::Hello { role, version, fp } => {
                // duplicate HELOs happen when the peer announces on every
                // channel; the fingerprint must still match
                self.on_helo(role, version, fp)
            }
            Frame::Manifest(m) => self.on_manifest(m),
            Frame::ChunkReq { .. } => Ok(vec![]), // push model; BITMAP covers resume
            Frame::Chunk {
                file,
                index,
                gzip,
                data,
            } => self.on_chunk(file, index, gzip, data),
            Frame::Bitmap { file, runs } => self.on_bitmap(file, runs),
            Frame::Pause { file } => {
                self.set_paused(file, true);
                Ok(vec![Action::SaveState])
            }
            Frame::Resume { file } => {
                self.set_paused(file, false);
                Ok(vec![Action::SaveState])
            }
            Frame::Cancel { file } => self.on_cancel(file),
            Frame::Receipt(r) => self.on_receipt(r),
            Frame::Text(t) => Ok(vec![Action::EmitText(t)]),
            Frame::Error { code, msg } => {
                self.phase = Phase::Failed;
                Ok(vec![Action::Fail { code, msg }])
            }
            Frame::Done { file } => self.on_done(file),
        }
    }

    fn on_helo(&mut self, role: u8, version: u8, fp: [u8; 32]) -> Result<Vec<Action>> {
        let expect_role = match self.role {
            Role::Initiator => 1u8,
            Role::Responder => 0u8,
        };
        let k = self.k_confirm.as_ref().expect("keys derived").clone();
        let want = crypto::confirm_fp(&k, &self.offer_sdp, &self.answer_sdp, &self.sid);
        if version != PROTOCOL_VERSION || role != expect_role || !crypto::ct_eq(&fp, &want) {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::SecHelloMismatch, "HELO fingerprint mismatch"));
        }
        self.helo_received = true;
        self.phase = Phase::Active;
        let mut actions = vec![Action::SaveState];
        if self.resumed {
            actions.extend(self.on_resume_handshake());
        }
        Ok(actions)
    }

    fn fail_pair(&mut self, code: ErrorCode, msg: &str) -> Vec<Action> {
        // Best-effort ERROR frame before failing (may fail itself if keys are
        // unusable; then just Fail).
        let mut actions = Vec::new();
        if self.k_tx.is_some() && self.phase != Phase::Failed {
            actions.push(self.send(Frame::Error {
                code: code.clone(),
                msg: msg.to_string(),
            }));
        }
        actions.push(Action::Fail {
            code,
            msg: msg.to_string(),
        });
        actions
    }

    fn fail_action(&mut self, code: ErrorCode, msg: &str) -> Action {
        self.phase = Phase::Failed;
        Action::Fail {
            code,
            msg: msg.to_string(),
        }
    }

    // ------------------------------------------------------------------
    // Manifest / chunks (receiver)
    // ------------------------------------------------------------------

    fn on_manifest(&mut self, m: Manifest) -> Result<Vec<Action>> {
        if self.role != Role::Responder {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(
                ErrorCode::ProtoMalformed,
                "initiator must not receive MANIFEST",
            ));
        }
        if self.manifest.is_some() {
            // Duplicate MANIFEST (multi-channel fan-out of the manifest) is
            // tolerated only if identical.
            if self.manifest.as_ref() == Some(&m) {
                return Ok(vec![]);
            }
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "MANIFEST changed mid-session"));
        }
        if m.sid != hex::encode(self.sid) || m.epoch != self.epoch {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "MANIFEST sid/epoch mismatch"));
        }
        m.validate()?;
        let uniform = m
            .files
            .iter()
            .all(|f| f.chunk_size == m.files[0].chunk_size);
        if !uniform {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "manifest mixes chunk sizes"));
        }
        self.chunk_size = m.files[0].chunk_size;
        self.set_manifest(m)?;
        Ok(vec![Action::SaveState])
    }

    fn on_chunk(
        &mut self,
        file: u16,
        index: u64,
        gzip: bool,
        data: Vec<u8>,
    ) -> Result<Vec<Action>> {
        let Some(entry) = self.manifest.as_ref().and_then(|m| m.file(file).cloned()) else {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(
                ErrorCode::ProtoMalformed,
                &format!("CHUNK for unknown file {file}"),
            ));
        };
        if index >= entry.chunks {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "chunk index out of range"));
        }
        let expected = std::cmp::min(
            entry.chunk_size as u64,
            entry.size.saturating_sub(index * entry.chunk_size as u64),
        ) as usize;
        let wire_len = (crate::FRAME_HEADER_LEN + 11 + data.len() + 16) as u64;
        let raw = if gzip {
            decompress_chunk(&data, expected)?
        } else {
            data
        };
        if raw.len() != expected {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "chunk length mismatch"));
        }
        let dup = self
            .file_ref(file)
            .map(|f| f.have.get(index))
            .unwrap_or(false);
        let mut actions = Vec::new();
        if dup {
            let f = self.file_mut(file).expect("file state");
            f.dups += 1;
            f.wire_bytes += wire_len;
        } else {
            let f = self.file_mut(file).expect("file state");
            f.have.set(index, true);
            f.bytes_moved += raw.len() as u64;
            f.wire_bytes += wire_len;
            actions.push(Action::SaveChunk {
                file,
                index,
                data: raw,
            });
            self.chunks_since_save += 1;
        }
        let (done, wire) = {
            let f = self.file_ref(file).expect("file state");
            (f.bytes_moved, f.wire_bytes)
        };
        actions.push(Action::Progress {
            file,
            done,
            total: entry.size,
            wire_bytes: wire,
            resumed: dup || self.resumed,
        });
        if self.chunks_since_save >= SAVE_EVERY_CHUNKS {
            self.chunks_since_save = 0;
            actions.push(Action::SaveState);
        }
        let (full, claimed) = {
            let f = self.file_ref(file).expect("file state");
            (f.have.is_full(), f.done_claimed)
        };
        if full && claimed {
            actions.extend(self.start_hash(file));
        }
        Ok(actions)
    }

    fn on_done(&mut self, file: u16) -> Result<Vec<Action>> {
        let Some(entry) = self.manifest.as_ref().and_then(|m| m.file(file).cloned()) else {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(
                ErrorCode::ProtoMalformed,
                &format!("DONE for unknown file {file}"),
            ));
        };
        let f = self.file_mut(file).expect("file state");
        if f.file_done {
            return Ok(vec![]);
        }
        let full = f.have.is_full();
        f.done_claimed = true;
        if full || entry.chunks == 0 {
            Ok(self.start_hash(file))
        } else {
            Ok(vec![Action::SaveState])
        }
    }

    /// Receiver: begin (or immediately finish, for empty files) hash
    /// verification of a completed file.
    fn start_hash(&mut self, file: u16) -> Vec<Action> {
        if self.hashers.contains_key(&file) {
            return vec![];
        }
        self.hashers.insert(file, (sha2::Sha256::default(), 0));
        vec![Action::HashFeed { file }]
    }

    /// Receiver glue feeds re-read file bytes; auto-finishes at full size.
    pub fn hash_feed(&mut self, file: u16, bytes: &[u8]) -> Result<Vec<Action>> {
        use sha2::Digest;
        let Some(entry) = self.manifest.as_ref().and_then(|m| m.file(file).cloned()) else {
            return err(ErrorCode::ProtoMalformed, "hash_feed for unknown file");
        };
        let Some((h, fed)) = self.hashers.get_mut(&file) else {
            return err(
                ErrorCode::ProtoMalformed,
                "hash_feed without pending HashFeed",
            );
        };
        h.update(bytes);
        *fed += bytes.len() as u64;
        if *fed < entry.size {
            return Ok(vec![]);
        }
        if *fed > entry.size {
            return err(ErrorCode::StorageFailed, "hash_feed overshot file size");
        }
        let (h, _) = self.hashers.remove(&file).expect("present");
        let digest: [u8; 32] = h.finalize().into();
        let hex_digest = hex::encode(digest);
        let verified = hex_digest == entry.sha256.to_lowercase();
        if !verified {
            self.phase = Phase::Failed;
            return Ok(vec![Action::Fail {
                code: ErrorCode::HashMismatch,
                msg: format!(
                    "file {file} hash mismatch: got {hex_digest}, manifest {}",
                    entry.sha256
                ),
            }]);
        }
        let ts = now_ts();
        let k_receipt = self.k_receipt.as_ref().expect("keys").clone();
        let k_pf = self.k_pf.as_ref().expect("keys").clone();
        let sid_hex = hex::encode(self.sid);
        let pake1 = self.pake1_b64.clone();
        let pake2 = self.pake2_b64.clone();
        {
            let f = self.file_mut(file).expect("file state");
            f.file_done = true;
            f.verified = true;
        }
        let mac = crate::receipt::receipt_mac(&k_receipt, file, &hex_digest, entry.size, ts);
        let macpf = crate::receipt::receipt_mac_pf(&k_pf, file, &hex_digest, entry.size, ts);
        let msg = ReceiptMsg {
            file,
            sha256: hex_digest.clone(),
            bytes: entry.size,
            ts,
            mac,
        };
        let receipt = Receipt::from_msg(&msg, &sid_hex, &pake1, &pake2, &macpf);
        self.file_mut(file).expect("file state").receipt_sent = true;
        let mut actions = vec![
            Action::FileDone {
                file,
                sha256: digest,
                verified: true,
            },
            Action::Receipt(receipt),
        ];
        actions.push(self.send(Frame::Receipt(msg)));
        actions.push(Action::SaveState);
        if self.all_files_settled_receiver() {
            self.phase = Phase::Done;
            actions.push(Action::SessionDone);
        }
        Ok(actions)
    }

    // ------------------------------------------------------------------
    // Bitmaps (sender side of resume)
    // ------------------------------------------------------------------

    fn on_bitmap(&mut self, file: u16, runs: Vec<(u64, u64)>) -> Result<Vec<Action>> {
        if self.role != Role::Initiator {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(
                ErrorCode::ProtoMalformed,
                "responder must not receive BITMAP",
            ));
        }
        let Some(entry) = self.manifest.as_ref().and_then(|m| m.file(file).cloned()) else {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(
                ErrorCode::ProtoMalformed,
                &format!("BITMAP for unknown file {file}"),
            ));
        };
        let merged = self
            .file_mut(file)
            .expect("file state")
            .acked
            .merge_runs(&runs);
        let (acked_count, wire_bytes) = match merged {
            Ok(_) => {
                let f = self.file_ref(file).expect("file state");
                (f.acked.count_ones(), f.wire_bytes)
            }
            Err(e) => {
                self.phase = Phase::Failed;
                return Err(e);
            }
        };
        // any acked chunk beyond what we sent this epoch is pre-resume progress
        self.resumed = true;
        Ok(vec![
            Action::Progress {
                file,
                done: acked_count.min(entry.chunks) * entry.chunk_size as u64,
                total: entry.size,
                wire_bytes,
                resumed: true,
            },
            Action::SaveState,
        ])
    }

    // ------------------------------------------------------------------
    // Sender: chunk plan (sequential-first; holes-first on resume)
    // ------------------------------------------------------------------

    /// Next chunk to send for `file`: ascending over chunks the receiver has
    /// not confirmed. Returns (index, read_len).
    pub fn next_send_chunk(&self, file: u16) -> Option<(u64, u32)> {
        if self.role != Role::Initiator || self.phase != Phase::Active {
            return None;
        }
        let entry = self.manifest.as_ref().and_then(|m| m.file(file))?;
        let f = self.files.iter().find(|f| f.id == file)?;
        if f.done_sent
            || f.file_done
            || self.paused.contains(&file)
            || self.cancelled.contains(&file)
        {
            return None;
        }
        let n = entry.chunks;
        // first index not acked and not sent this epoch
        let mut i = 0u64;
        while i < n {
            if !f.acked.get(i) && !f.sent.get(i) {
                let len = std::cmp::min(
                    entry.chunk_size as u64,
                    entry.size - i * entry.chunk_size as u64,
                );
                return Some((i, len as u32));
            }
            i += 1;
        }
        // everything either sent or acked: if all acked -> done; if sent but
        // waiting, nothing to push now
        None
    }

    /// File ids in manifest order (glue iterates these for sending).
    pub fn file_ids(&self) -> Vec<u16> {
        self.manifest
            .as_ref()
            .map(|m| m.files.iter().map(|f| f.id).collect())
            .unwrap_or_default()
    }

    /// Sender glue read the chunk; returns encrypted wire bytes + actions.
    pub fn push_chunk_data(
        &mut self,
        file: u16,
        index: u64,
        bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<Action>)> {
        if self.role != Role::Initiator {
            return err(
                ErrorCode::ProtoMalformed,
                "only the initiator pushes chunks",
            );
        }
        let Some(entry) = self.manifest.as_ref().and_then(|m| m.file(file).cloned()) else {
            return err(ErrorCode::ProtoMalformed, "chunk for unknown file");
        };
        if index >= entry.chunks {
            return err(ErrorCode::ProtoMalformed, "chunk index out of range");
        }
        let expected = std::cmp::min(
            entry.chunk_size as usize,
            (entry.size - index * entry.chunk_size as u64) as usize,
        );
        if bytes.len() != expected {
            return err(
                ErrorCode::StorageFailed,
                "read length does not match chunk plan",
            );
        }
        if bytes.len() > MAX_CHUNK_DATA {
            return err(
                ErrorCode::ProtoMalformed,
                "chunk data exceeds u16 length field",
            );
        }
        let use_gzip = self.file_gzip(file);
        let (data, gz) = if use_gzip {
            let c = compress_chunk(bytes);
            if c.len() < bytes.len() {
                (c, true)
            } else {
                (bytes.to_vec(), false)
            }
        } else {
            (bytes.to_vec(), false)
        };
        let frame = Frame::Chunk {
            file,
            index,
            gzip: gz,
            data,
        };
        let wire = self.encrypt_frame(&frame);
        let (done, wire_total) = {
            let f = self.file_mut(file).expect("file state");
            f.sent.set(index, true);
            f.bytes_moved += bytes.len() as u64;
            f.wire_bytes += wire.len() as u64;
            (f.bytes_moved, f.wire_bytes)
        };
        self.chunks_since_save += 1;
        let mut actions = vec![Action::Progress {
            file,
            done,
            total: entry.size,
            wire_bytes: wire_total,
            resumed: self.resumed,
        }];
        // DONE fires when the receiver has (or will have, from this epoch's
        // sends) every chunk: |acked UNION sent| == chunks. On resume the
        // sent bitmap alone never fills (pre-resume chunks are only acked).
        let all_covered = {
            let f = self.file_ref(file).expect("file state");
            let chunks = entry.chunks;
            f.acked.union_count(&f.sent) >= chunks && !f.done_sent
        };
        if all_covered {
            self.file_mut(file).expect("file state").done_sent = true;
            actions.push(self.send(Frame::Done { file }));
        }
        if self.chunks_since_save >= SAVE_EVERY_CHUNKS {
            self.chunks_since_save = 0;
            actions.push(Action::SaveState);
        }
        Ok((wire, actions))
    }

    fn file_gzip(&self, file: u16) -> bool {
        // Sender-side per-file decision (resolve_gzip_auto / FileSpec). The
        // manifest "gzip" field is informational; the per-chunk wire flag is
        // authoritative for the receiver.
        self.files
            .iter()
            .find(|f| f.id == file)
            .map(|f| f.gzip.unwrap_or(false))
            .unwrap_or(false)
    }

    /// Resolve gzip "auto" per file by probing 4 sample chunks (glue reads
    /// them from storage). Returns per-file decision and stores it.
    pub fn resolve_gzip_auto(&mut self, file: u16, samples: &[Vec<u8>]) -> Result<bool> {
        let use_gz = if samples.is_empty() {
            false
        } else {
            let mut raw = 0usize;
            let mut comp = 0usize;
            for s in samples {
                raw += s.len();
                comp += compress_chunk(s).len();
            }
            (comp as f64) < 0.9 * raw as f64
        };
        let f = self.file_mut(file).ok_or_else(|| {
            crate::error::Error::new(ErrorCode::ProtoMalformed, "unknown file for gzip probe")
        })?;
        f.gzip = Some(use_gz);
        Ok(use_gz)
    }

    // ------------------------------------------------------------------
    // Receipts (sender side)
    // ------------------------------------------------------------------

    fn on_receipt(&mut self, r: ReceiptMsg) -> Result<Vec<Action>> {
        if self.role != Role::Initiator {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(
                ErrorCode::ProtoMalformed,
                "responder must not receive RECEIPT",
            ));
        }
        let Some(entry) = self.manifest.as_ref().and_then(|m| m.file(r.file).cloned()) else {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "RECEIPT for unknown file"));
        };
        let k_receipt = self.k_receipt.as_ref().expect("keys").clone();
        if !crate::receipt::verify_receipt_mac(&k_receipt, &r) {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "RECEIPT MAC invalid"));
        }
        let verified =
            r.sha256.to_lowercase() == entry.sha256.to_lowercase() && r.bytes == entry.size;
        let digest_bytes = hex::decode(&r.sha256).map_err(|_| {
            crate::error::Error::new(ErrorCode::ProtoMalformed, "receipt sha256 not hex")
        })?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_bytes);
        let k_pf = self.k_pf.as_ref().expect("keys").clone();
        let macpf =
            crate::receipt::receipt_mac_pf(&k_pf, r.file, &r.sha256.to_lowercase(), r.bytes, r.ts);
        let receipt = Receipt::from_msg(
            &r,
            &hex::encode(self.sid),
            &self.pake1_b64,
            &self.pake2_b64,
            &macpf,
        );
        let f = self.file_mut(r.file).expect("file state");
        f.file_done = true;
        f.verified = verified;
        let mut actions = vec![
            Action::Receipt(receipt),
            Action::FileDone {
                file: r.file,
                sha256: digest,
                verified,
            },
            Action::SaveState,
        ];
        if self.all_files_settled_initiator() {
            self.phase = Phase::Done;
            actions.push(Action::SessionDone);
        }
        Ok(actions)
    }

    fn all_files_settled_initiator(&self) -> bool {
        !self.files.is_empty()
            && self
                .files
                .iter()
                .all(|f| f.file_done || self.cancelled.contains(&f.id))
    }

    fn all_files_settled_receiver(&self) -> bool {
        !self.files.is_empty()
            && self
                .files
                .iter()
                .all(|f| f.file_done || self.cancelled.contains(&f.id))
    }

    // ------------------------------------------------------------------
    // Cancel / pause / text
    // ------------------------------------------------------------------

    fn on_cancel(&mut self, file: u16) -> Result<Vec<Action>> {
        if file == FILE_ALL {
            self.phase = Phase::Failed;
            return Ok(vec![Action::Fail {
                code: ErrorCode::PeerCancel,
                msg: "peer cancelled the whole session".into(),
            }]);
        }
        if self.manifest.as_ref().and_then(|m| m.file(file)).is_none() {
            self.phase = Phase::Failed;
            return Ok(self.fail_pair(ErrorCode::ProtoMalformed, "CANCEL for unknown file"));
        }
        self.cancelled.insert(file);
        if self.all_files_settled_receiver() || self.all_files_settled_initiator() {
            self.phase = Phase::Done;
            return Ok(vec![Action::SessionDone]);
        }
        Ok(vec![Action::SaveState])
    }

    /// Local pause (emits PAUSE to the peer). `file` or FILE_ALL.
    pub fn pause(&mut self, file: u16) -> Vec<Action> {
        self.set_paused(file, true);
        vec![self.send(Frame::Pause { file }), Action::SaveState]
    }

    /// Local resume (emits RESUME to the peer).
    pub fn resume(&mut self, file: u16) -> Vec<Action> {
        self.set_paused(file, false);
        vec![self.send(Frame::Resume { file }), Action::SaveState]
    }

    fn set_paused(&mut self, file: u16, on: bool) {
        if file == FILE_ALL {
            if on {
                let ids: Vec<u16> = self.files.iter().map(|f| f.id).collect();
                self.paused.extend(ids);
            } else {
                self.paused.clear();
            }
        } else if on {
            self.paused.insert(file);
        } else {
            self.paused.remove(&file);
        }
    }

    /// Local cancel: clean close (SessionDone, no error). Emits CANCEL.
    pub fn cancel(&mut self, file: u16) -> Vec<Action> {
        if file == FILE_ALL {
            let ids: Vec<u16> = self.files.iter().map(|f| f.id).collect();
            self.cancelled.extend(ids);
        } else {
            self.cancelled.insert(file);
        }
        let mut actions = vec![self.send(Frame::Cancel { file })];
        if self.all_files_settled_initiator() || self.all_files_settled_receiver() {
            self.phase = Phase::Done;
            actions.push(Action::SessionDone);
        }
        actions
    }

    /// Send a TEXT frame (max 32 KiB). Returns encrypted wire bytes.
    pub fn send_text(&mut self, text: &str) -> Result<Vec<u8>> {
        if text.len() > MAX_TEXT_BYTES {
            return err(ErrorCode::ProtoMalformed, "TEXT exceeds 32 KiB");
        }
        if self.phase == Phase::Failed || self.phase == Phase::Done {
            return err(ErrorCode::ProtoMalformed, "session not active");
        }
        Ok(self.encrypt_frame(&Frame::Text(text.to_string())))
    }

    // ------------------------------------------------------------------
    // Encrypt / decrypt plumbing
    // ------------------------------------------------------------------

    fn tx_dir(&self) -> Dir {
        match self.role {
            Role::Initiator => InitiatorToResponder,
            Role::Responder => ResponderToInitiator,
        }
    }

    fn rx_dir(&self) -> Dir {
        match self.role {
            Role::Initiator => ResponderToInitiator,
            Role::Responder => InitiatorToResponder,
        }
    }

    /// Encrypt + advance the tx counter. Returns wire bytes.
    fn encrypt_frame(&mut self, frame: &Frame) -> Vec<u8> {
        // D4: the header `seq` field carries the encryption counter for
        // EVERY frame (chunk_index stays in the CHUNK payload), so frame
        // decryption never depends on cross-channel arrival order.
        let counter = self.tx_counter;
        let mut plain = Vec::new();
        frame.encode(&mut plain, counter);
        let mut header = [0u8; 12];
        header.copy_from_slice(&plain[..12]);
        let key = self.k_tx.as_ref().expect("keys derived");
        let ct = crypto::encrypt_frame(
            key,
            self.epoch,
            self.tx_dir(),
            counter,
            &header,
            &plain[12..],
        );
        self.tx_counter = self.tx_counter.wrapping_add(1);
        let mut wire = plain[..12].to_vec();
        wire.extend_from_slice(&ct);
        wire
    }

    fn send(&mut self, frame: Frame) -> Action {
        Action::Send(self.encrypt_frame(&frame))
    }

    fn decrypt(&mut self, header: &[u8; 12], ct: &[u8]) -> Result<Frame> {
        if self.k_rx.is_none() {
            return err(
                ErrorCode::ProtoMalformed,
                "frame received before pairing completed",
            );
        }
        let key = self.k_rx.as_ref().expect("keys").clone();
        // D4: the counter rides in the header seq field
        let counter = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let pt = crypto::decrypt_frame(&key, self.epoch, self.rx_dir(), counter, header, ct)?;
        self.rx_counter = self.rx_counter.wrapping_add(1);
        let mut wire = header.to_vec();
        wire.extend_from_slice(&pt);
        Frame::decode(&wire)
    }

    // ------------------------------------------------------------------
    // Pairing internals
    // ------------------------------------------------------------------

    fn empty(
        role: Role,
        sid: [u8; 16],
        epoch: u32,
        private3: bool,
        passphrase: &str,
    ) -> Result<Session> {
        let canonical = crate::pake::canonical_passphrase(passphrase);
        Ok(Session {
            role,
            sid,
            epoch,
            private3,
            channels: 1,
            chunk_size: crate::CHUNK_SIZE_DEFAULT,
            passphrase: Zeroizing::new(canonical),
            k_root: None,
            k_tx: None,
            k_rx: None,
            k_confirm: None,
            k_receipt: None,
            k_pf: None,
            pake: None,
            pake1_b64: String::new(),
            pake2_b64: String::new(),
            offer_sdp: String::new(),
            answer_sdp: String::new(),
            tx_counter: 0,
            rx_counter: 0,
            ctrl_seq: 0,
            phase: Phase::Paired,
            helo_sent: false,
            helo_received: false,
            manifest_sent: false,
            manifest: None,
            files: vec![],
            paused: BTreeSet::new(),
            cancelled: BTreeSet::new(),
            resumed: false,
            chunks_since_save: 0,
            hashers: Default::default(),
        })
    }

    fn ensure_role(&self, role: Role) -> Result<()> {
        if self.role == role {
            Ok(())
        } else {
            err(
                ErrorCode::ProtoMalformed,
                "operation not allowed for this role",
            )
        }
    }

    fn pair_start(&mut self, offer_sdp: &str) -> Result<()> {
        if offer_sdp.is_empty() {
            return err(ErrorCode::ProtoMalformed, "offer SDP required");
        }
        self.offer_sdp = offer_sdp.to_string();
        let pake = PakeSide::start_initiator(self.passphrase.as_bytes(), &self.sid);
        self.pake = Some(pake);
        self.phase = Phase::Paired;
        Ok(())
    }

    fn pair_respond(&mut self, env1: &Envelope1) -> Result<()> {
        let pake_a_msg = crate::envelope::b64_decode(&env1.pake)?;
        let pake = PakeSide::start_responder(self.passphrase.as_bytes(), &self.sid);
        let own_msg = pake.message().to_vec();
        let secret = pake.finish(&pake_a_msg)?;
        self.pake1_b64 = env1.pake.clone();
        self.pake2_b64 = crate::envelope::b64(&own_msg);
        self.derive_keys(&secret);
        self.offer_sdp = env1.sdp.clone().unwrap_or_default();
        self.phase = Phase::Paired;
        Ok(())
    }

    fn pair_finish(&mut self, pake2_b64: &str) -> Result<()> {
        let pake = self.pake.take().ok_or_else(|| {
            crate::error::Error::new(ErrorCode::ProtoMalformed, "pairing already finished")
        })?;
        let pake2 = crate::envelope::b64_decode(pake2_b64)?;
        let secret = pake.finish(&pake2)?;
        self.pake2_b64 = pake2_b64.to_string();
        self.derive_keys(&secret);
        Ok(())
    }

    fn derive_keys(&mut self, secret: &[u8]) {
        let root = crypto::derive_root(secret, &self.sid);
        let k_tx = crypto::derive_dir_key(&root, &self.sid, self.tx_dir(), self.epoch);
        let k_rx = crypto::derive_dir_key(&root, &self.sid, self.rx_dir(), self.epoch);
        let k_confirm = crypto::derive_confirm(&root, &self.sid);
        let k_receipt = crypto::derive_receipt(&root, &self.sid);
        let k_pf = crypto::derive_receipt_pf(self.passphrase.as_bytes(), &self.sid);
        self.k_root = Some(root);
        self.k_tx = Some(k_tx);
        self.k_rx = Some(k_rx);
        self.k_confirm = Some(k_confirm);
        self.k_receipt = Some(k_receipt);
        self.k_pf = Some(k_pf);
    }

    fn build_envelope1(&mut self) -> Result<String> {
        let pake = self
            .pake
            .as_ref()
            .expect("pairing started")
            .message()
            .to_vec();
        self.pake1_b64 = crate::envelope::b64(&pake);
        let env1 = Envelope1 {
            v: PROTOCOL_VERSION,
            sid: hex::encode(self.sid),
            pake: self.pake1_b64.clone(),
            sdp: if self.private3 {
                None
            } else {
                Some(self.offer_sdp.clone())
            },
            ep: self.epoch,
            mode: if self.private3 {
                "p3".into()
            } else {
                "p2".into()
            },
            ch: self.channels,
        };
        crate::envelope::serialize(&env1)
    }

    fn build_envelope2(&mut self, mode: PairingMode) -> Result<String> {
        if self.pake2_b64.is_empty() {
            return err(ErrorCode::ProtoMalformed, "pairing not started");
        }
        let sdpe = if mode == PairingMode::P2 {
            let k = self.k_root.as_ref().expect("k_root");
            let ct = crypto::encrypt_sdp(
                &crypto::derive_env_answer(k, &self.sid),
                "sdp-answer",
                &self.answer_sdp,
            );
            Some(crate::envelope::b64(&ct))
        } else {
            None
        };
        crate::envelope::serialize(&Envelope2 {
            v: PROTOCOL_VERSION,
            pake: self.pake2_b64.clone(),
            sdpe,
        })
    }

    fn parse_envelope1(raw: &str) -> Result<Envelope1> {
        let json = crate::envelope::inflate(raw)?;
        let env1: Envelope1 = serde_json::from_str(&json).map_err(|e| {
            crate::error::Error::new(
                ErrorCode::ProtoMalformed,
                format!("bad envelope-1 JSON: {e}"),
            )
        })?;
        Ok(env1)
    }

    fn reset_transport_state(&mut self) {
        self.tx_counter = 0;
        self.rx_counter = 0;
        self.ctrl_seq = 0;
        self.helo_sent = false;
        self.helo_received = false;
        self.chunks_since_save = 0;
        self.hashers.clear();
        // sender: this epoch re-sends anything not acked
        for f in &mut self.files {
            f.sent = Bitmap::new(f.sent.len());
            f.done_sent = f.file_done;
            f.done_claimed = f.done_claimed || f.file_done;
        }
    }

    // ------------------------------------------------------------------
    // Snapshots
    // ------------------------------------------------------------------

    pub fn snapshot(&self) -> String {
        let snap = Snapshot {
            v: PROTOCOL_VERSION,
            role: self.role,
            sid: hex::encode(self.sid),
            epoch: self.epoch,
            private3: self.private3,
            manifest: self.manifest.clone(),
            tx: self.tx_counter,
            rx: self.rx_counter,
            ctrl_seq: self.ctrl_seq,
            resumed: self.resumed,
            files: self
                .files
                .iter()
                .map(|f| FileSnap {
                    id: f.id,
                    sent: Some(BitmapJson::from(&f.sent)),
                    acked: Some(BitmapJson::from(&f.acked)),
                    have: Some(BitmapJson::from(&f.have)),
                    done_claimed: f.done_claimed,
                    done_sent: f.done_sent,
                    file_done: f.file_done,
                    verified: f.verified,
                    receipt_sent: f.receipt_sent,
                    bytes_moved: f.bytes_moved,
                    wire_bytes: f.wire_bytes,
                    dups: f.dups,
                    gzip: f.gzip,
                })
                .collect(),
            paused: self.paused.iter().copied().collect(),
            cancelled: self.cancelled.iter().copied().collect(),
        };
        serde_json::to_string(&snap).expect("snapshot serializes")
    }

    pub fn restore(json: &str) -> Result<Session> {
        let snap: Snapshot = serde_json::from_str(json).map_err(|e| {
            crate::error::Error::new(ErrorCode::StorageFailed, format!("bad snapshot: {e}"))
        })?;
        if snap.v != PROTOCOL_VERSION {
            return err(ErrorCode::ProtoVersion, "snapshot version mismatch");
        }
        let sid = crate::envelope::parse_sid(&snap.sid)?;
        // NOTE: no key material in snapshots; keys are re-derived on resume.
        let mut s = Session {
            role: snap.role,
            sid,
            epoch: snap.epoch,
            private3: snap.private3,
            channels: 1,
            chunk_size: snap
                .manifest
                .as_ref()
                .and_then(|m| m.files.first())
                .map(|f| f.chunk_size)
                .unwrap_or(crate::CHUNK_SIZE_DEFAULT),
            passphrase: Zeroizing::new(String::new()),
            k_root: None,
            k_tx: None,
            k_rx: None,
            k_confirm: None,
            k_receipt: None,
            k_pf: None,
            pake: None,
            pake1_b64: String::new(),
            pake2_b64: String::new(),
            offer_sdp: String::new(),
            answer_sdp: String::new(),
            tx_counter: snap.tx,
            rx_counter: snap.rx,
            ctrl_seq: snap.ctrl_seq,
            phase: Phase::Paired,
            helo_sent: false,
            helo_received: false,
            manifest_sent: false,
            manifest: None,
            files: vec![],
            paused: snap.paused.into_iter().collect(),
            cancelled: snap.cancelled.into_iter().collect(),
            resumed: snap.resumed,
            chunks_since_save: 0,
            hashers: Default::default(),
        };
        if let Some(m) = &snap.manifest {
            m.validate()?;
            let manifest = m.clone();
            s.set_manifest(manifest).expect("validated");
        }
        for fs in snap.files {
            if let Some(f) = s.files.iter_mut().find(|f| f.id == fs.id) {
                if let Some(b) = &fs.sent {
                    f.sent = b.to_bitmap().expect("validated snapshot");
                }
                if let Some(b) = &fs.acked {
                    f.acked = b.to_bitmap().expect("validated snapshot");
                }
                if let Some(b) = &fs.have {
                    f.have = b.to_bitmap().expect("validated snapshot");
                }
                f.done_claimed = fs.done_claimed;
                f.done_sent = fs.done_sent;
                f.file_done = fs.file_done;
                f.verified = fs.verified;
                f.receipt_sent = fs.receipt_sent;
                f.bytes_moved = fs.bytes_moved;
                f.wire_bytes = fs.wire_bytes;
                f.dups = fs.dups;
                f.gzip = fs.gzip;
            }
        }
        Ok(s)
    }

    // ------------------------------------------------------------------
    // Introspection for glue/tests
    // ------------------------------------------------------------------

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn sid_hex(&self) -> String {
        hex::encode(self.sid)
    }

    pub fn sid(&self) -> [u8; 16] {
        self.sid
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    pub fn is_failed(&self) -> bool {
        self.phase == Phase::Failed
    }

    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    /// The (decrypted) answer SDP known to this side; empty before pairing.
    pub fn answer_sdp(&self) -> &str {
        &self.answer_sdp
    }

    /// The offer SDP known to this side; empty before pairing (responder in
    /// p3 learns it from blob-3).
    pub fn offer_sdp(&self) -> &str {
        &self.offer_sdp
    }

    pub fn file_progress(&self, file: u16) -> Option<(u64, u64, u64)> {
        let f = self.files.iter().find(|f| f.id == file)?;
        Some((
            f.bytes_moved,
            self.manifest
                .as_ref()
                .and_then(|m| m.file(file))
                .map(|e| e.size)
                .unwrap_or(0),
            f.wire_bytes,
        ))
    }

    pub fn dup_count(&self, file: u16) -> u64 {
        self.files
            .iter()
            .find(|f| f.id == file)
            .map(|f| f.dups)
            .unwrap_or(0)
    }

    pub fn is_paused(&self, file: u16) -> bool {
        self.paused.contains(&file)
    }

    pub fn resumed(&self) -> bool {
        self.resumed
    }

    pub fn pake_messages_b64(&self) -> (String, String) {
        (self.pake1_b64.clone(), self.pake2_b64.clone())
    }

    /// K_root hex — TEST/vectors only (never log in production paths).
    pub fn k_root_hex_for_test(&self) -> Option<String> {
        self.k_root.as_ref().map(|k| hex::encode(**k))
    }

    pub fn file_done(&self, file: u16) -> bool {
        self.files
            .iter()
            .find(|f| f.id == file)
            .map(|f| f.file_done)
            .unwrap_or(false)
    }

    fn file_mut(&mut self, id: u16) -> Option<&mut FileState> {
        self.files.iter_mut().find(|f| f.id == id)
    }

    fn file_ref(&self, id: u16) -> Option<&FileState> {
        self.files.iter().find(|f| f.id == id)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        self.k_root = None;
        self.k_tx = None;
        self.k_rx = None;
        self.k_confirm = None;
        self.k_receipt = None;
        self.k_pf = None;
        self.offer_sdp.zeroize();
        self.answer_sdp.zeroize();
    }
}

/// gzip-compress `data` and return the compressed length (probe helper for
/// the "auto" policy).
pub fn gzip_probe_bytes(data: &[u8]) -> usize {
    compress_chunk(data).len()
}

/// gzip a chunk (level 6, rust_backend).
fn compress_chunk(data: &[u8]) -> Vec<u8> {
    use flate2::read::GzEncoder;
    use std::io::Read;
    let mut enc = GzEncoder::new(data, flate2::Compression::default());
    let mut out = Vec::new();
    let _ = enc.read_to_end(&mut out);
    out
}

/// gunzip a chunk with a hard output cap; PROTO_MALFORMED on bombs.
fn decompress_chunk(data: &[u8], expected: usize) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let dec = GzDecoder::new(data);
    let mut limited = dec.take(crate::CHUNK_SIZE_MAX as u64 + 1);
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|_| crate::error::Error::new(ErrorCode::ProtoMalformed, "bad gzip chunk"))?;
    if out.len() > crate::CHUNK_SIZE_MAX as usize || out.len() != expected {
        return err(ErrorCode::ProtoMalformed, "chunk decompressed size invalid");
    }
    Ok(out)
}
