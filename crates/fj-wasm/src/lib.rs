//! filejaunt WASM facade (fj-protocol over wasm-bindgen).
//!
//! The browser owns RTCPeerConnection/DataChannels and storage; this facade
//! owns the protocol: pairing envelopes, HELO, manifest, chunk scheduling,
//! receipts, snapshots. Frames in/out are `Uint8Array`s already read from /
//! ready for a DataChannel.
//!
//! Usage pattern: call a mutating method, then `takeActions()` and apply
//! every action; `send` bytes go to the DataChannel, `saveChunk` data to
//! storage, `saveState` persists `snapshot()`.

use wasm_bindgen::prelude::*;

use fj_protocol::FILE_ALL;
use fj_protocol::session::{Action, Role, Session, SessionOpts};

/// Actions as JSON values:
/// `{t:"send",bytes}` | `{t:"saveChunk",file,index,data}` | `{t:"saveState"}`
/// | `{t:"progress",file,done,total,wireBytes,resumed}` | `{t:"hashFeed",file}`
/// | `{t:"fileDone",file,sha256,verified}` | `{t:"receipt",receipt}`
/// | `{t:"text",text}` | `{t:"done"}` | `{t:"fail",code,msg}`
#[wasm_bindgen]
pub struct FjCore {
    session: Option<Session>,
    pending: Vec<JsValue>,
}

fn action_to_js(a: Action) -> JsValue {
    let v = match a {
        Action::Send(bytes) => serde_json::json!({
            "t": "send",
            "bytes": bytes,
        }),
        Action::SaveChunk { file, index, data } => serde_json::json!({
            "t": "saveChunk",
            "file": file,
            "index": index,
            "data": data,
        }),
        Action::SaveState => serde_json::json!({"t": "saveState"}),
        Action::HashFeed { file } => serde_json::json!({"t": "hashFeed", "file": file}),
        Action::Progress {
            file,
            done,
            total,
            wire_bytes,
            resumed,
        } => serde_json::json!({
            "t": "progress",
            "file": file,
            "done": done,
            "total": total,
            "wireBytes": wire_bytes,
            "resumed": resumed,
        }),
        Action::FileDone {
            file,
            sha256,
            verified,
        } => serde_json::json!({
            "t": "fileDone",
            "file": file,
            "sha256": hex::encode(sha256),
            "verified": verified,
        }),
        Action::EmitText(text) => serde_json::json!({"t": "text", "text": text}),
        Action::Receipt(r) => serde_json::json!({"t": "receipt", "receipt": r}),
        Action::SessionDone => serde_json::json!({"t": "done"}),
        Action::Fail { code, msg } => {
            serde_json::json!({"t": "fail", "code": code.as_str(), "msg": msg})
        }
    };
    serde_wasm_bindgen::to_value(&v).unwrap_or(JsValue::NULL)
}

/// Internal error string used by the `err_of` return convention: methods
/// return `Result<T, JsValue>`; the JsValue is a plain String message with
/// the ErrorCode prefix ("SEC_...", "PROTO_...", ...).
fn err_string(e: &fj_protocol::Error) -> String {
    format!("{}: {}", e.code(), e.msg())
}

fn err_js(e: fj_protocol::Error) -> JsValue {
    JsValue::from_str(&err_string(&e))
}

#[wasm_bindgen]
impl FjCore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> FjCore {
        FjCore {
            session: None,
            pending: vec![],
        }
    }

    /// Fresh sender: generates the passphrase + envelope-1. `offer_sdp` is
    /// the SDP the browser created beforehand.
    pub fn sender_start(
        &mut self,
        words: usize,
        private3: bool,
        offer_sdp: &str,
        channels: usize,
    ) -> Result<JsValue, JsValue> {
        let (session, passphrase, blob1) = Session::initiator_new(SessionOpts {
            words,
            private3,
            chunk_size: fj_protocol::CHUNK_SIZE_DEFAULT,
            channels: channels.clamp(1, fj_protocol::CHANNELS_MAX),
            sid: None,
            offer_sdp: offer_sdp.to_string(),
        })
        .map_err(err_js)?;
        let sid = session.sid_hex();
        self.session = Some(session);
        let v = serde_json::json!({"sid": sid, "passphrase": passphrase, "blob1": blob1});
        Ok(serde_wasm_bindgen::to_value(&v).unwrap_or(JsValue::NULL))
    }

    /// Responder joins: `answer_sdp` is the browser's answer for the (clear,
    /// p2-mode) offer inside blob-1.
    pub fn receiver_join(
        &mut self,
        blob1: &str,
        passphrase: &str,
        answer_sdp: &str,
    ) -> Result<String, JsValue> {
        let mut limiter = fj_protocol::pake::AttemptLimiter::new();
        let (session, blob2) =
            Session::responder_join(blob1, passphrase, answer_sdp, &mut limiter).map_err(err_js)?;
        self.session = Some(session);
        Ok(blob2)
    }

    /// Initiator consumes blob-2 (p2) or the PAKE-only blob-2 (p3).
    pub fn initiator_accept(&mut self, blob2: &str) -> Result<(), JsValue> {
        self.with_session(|s| s.initiator_accept(blob2).map(|_| ()))?;
        self.drain_pending();
        Ok(())
    }

    // -- private 3-step -----------------------------------------------------

    pub fn initiator_private_blob3(&mut self) -> Result<String, JsValue> {
        self.with_session(|s| s.initiator_private_blob3())
    }

    /// Responder decrypts blob-3; returns the offer SDP for the browser.
    pub fn responder_private_offer(&mut self, blob3: &str) -> Result<String, JsValue> {
        let mut limiter = fj_protocol::pake::AttemptLimiter::new();
        self.with_session(|s| s.responder_private_offer(blob3, &mut limiter))
    }

    pub fn responder_private_blob4(&mut self, answer_sdp: &str) -> Result<String, JsValue> {
        self.with_session(|s| s.responder_private_blob4(answer_sdp))
    }

    pub fn initiator_private_final(&mut self, blob4: &str) -> Result<(), JsValue> {
        self.with_session(|s| s.initiator_private_final(blob4).map(|_| ()))?;
        self.drain_pending();
        Ok(())
    }

    // -- resume ---------------------------------------------------------------

    /// Restored initiator re-pairs (epoch+1). Load state first via
    /// `restore(json)` and keep the ORIGINAL passphrase.
    pub fn resume_initiator(
        &mut self,
        passphrase: &str,
        offer_sdp: &str,
    ) -> Result<String, JsValue> {
        self.with_session(|s| s.resume_initiator(passphrase, offer_sdp))
    }

    pub fn resume_responder(
        &mut self,
        blob1: &str,
        passphrase: &str,
        answer_sdp: &str,
    ) -> Result<String, JsValue> {
        let mut limiter = fj_protocol::pake::AttemptLimiter::new();
        self.with_session(|s| s.resume_responder(blob1, passphrase, answer_sdp, &mut limiter))
    }

    // -- files & transfer -----------------------------------------------------

    /// Sender: set the file list (gzip resolved per file by the browser
    /// through `resolve_gzip_auto` or its own probe).
    pub fn set_files(&mut self, files_json: &str) -> Result<(), JsValue> {
        let specs: Vec<fj_protocol::manifest::FileSpec> =
            serde_json::from_str(files_json).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        self.with_session(|s| s.set_files(&specs).map(|_| ()))
    }

    /// gzip "auto" probe helper: returns whether the samples compress.
    pub fn resolve_gzip_auto(&mut self, file: u16, samples: Vec<JsValue>) -> Result<bool, JsValue> {
        let samples: Vec<Vec<u8>> = samples
            .into_iter()
            .filter_map(|v| {
                if v.is_string() {
                    None
                } else {
                    // Uint8Array via js_sys
                    let arr = js_sys::Uint8Array::from(v);
                    Some(arr.to_vec())
                }
            })
            .collect();
        self.with_session(|s| s.resolve_gzip_auto(file, &samples))
    }

    /// Called when the DataChannel(s) open. Emits HELO (+MANIFEST on the
    /// sender side); drain with `takeActions()`.
    pub fn on_channel_open(&mut self) -> Result<(), JsValue> {
        let actions = self.with_session(|s| Ok(s.on_channel_open()))?;
        for a in actions {
            self.pending.push(action_to_js(a));
        }
        Ok(())
    }

    /// Feed one complete wire message from a DataChannel.
    pub fn on_frame(&mut self, bytes: js_sys::Uint8Array) -> Result<(), JsValue> {
        let actions = self.with_session(|s| s.on_frame(&bytes.to_vec()))?;
        for a in actions {
            self.pending.push(action_to_js(a));
        }
        Ok(())
    }

    /// Next chunk to send: [index, read_len] or null.
    pub fn next_send_chunk(&mut self, file: u16) -> Option<js_sys::Array> {
        let s = self.session.as_mut()?;
        let (index, len) = s.next_send_chunk(file)?;
        let arr = js_sys::Array::new();
        arr.push(&JsValue::from(index as f64));
        arr.push(&JsValue::from(len as f64));
        Some(arr)
    }

    /// Sender read the chunk: returns encrypted wire bytes for the channel.
    pub fn push_chunk_data(
        &mut self,
        file: u16,
        index: u32,
        bytes: js_sys::Uint8Array,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let (wire, actions) =
            self.with_session(|s| s.push_chunk_data(file, index as u64, &bytes.to_vec()))?;
        for a in actions {
            self.pending.push(action_to_js(a));
        }
        Ok(js_sys::Uint8Array::from(&wire[..]))
    }

    /// Receiver feeds re-read file bytes for hash verification.
    pub fn hash_feed(&mut self, file: u16, bytes: js_sys::Uint8Array) -> Result<(), JsValue> {
        let actions = self.with_session(|s| s.hash_feed(file, &bytes.to_vec()))?;
        for a in actions {
            self.pending.push(action_to_js(a));
        }
        Ok(())
    }

    pub fn send_text(&mut self, text: &str) -> Result<js_sys::Uint8Array, JsValue> {
        let wire = self.with_session(|s| s.send_text(text))?;
        Ok(js_sys::Uint8Array::from(&wire[..]))
    }

    pub fn pause(&mut self, file: u16) -> Result<(), JsValue> {
        let actions = self.with_session(|s| Ok(s.pause(file)))?;
        for a in actions {
            self.pending.push(action_to_js(a));
        }
        Ok(())
    }

    pub fn resume(&mut self, file: u16) -> Result<(), JsValue> {
        let actions = self.with_session(|s| Ok(s.resume(file)))?;
        for a in actions {
            self.pending.push(action_to_js(a));
        }
        Ok(())
    }

    /// Local cancel (clean close). Use file=65535 for everything.
    pub fn cancel(&mut self, file: u16) -> Result<(), JsValue> {
        let actions = self.with_session(|s| Ok(s.cancel(file)))?;
        for a in actions {
            self.pending.push(action_to_js(a));
        }
        Ok(())
    }

    /// Drain pending actions (JSON values, see crate docs).
    pub fn take_actions(&mut self) -> js_sys::Array {
        let out = js_sys::Array::new();
        for a in self.pending.drain(..) {
            out.push(&a);
        }
        out
    }

    // -- state -----------------------------------------------------------------

    pub fn snapshot(&mut self) -> Result<String, JsValue> {
        self.with_session(|s| Ok(s.snapshot()))
    }

    pub fn restore(&mut self, json: &str) -> Result<(), JsValue> {
        let s = Session::restore(json).map_err(err_js)?;
        self.session = Some(s);
        Ok(())
    }

    pub fn sid(&mut self) -> Result<String, JsValue> {
        self.with_session(|s| Ok(s.sid_hex()))
    }

    pub fn is_done(&self) -> bool {
        self.session.as_ref().map(|s| s.is_done()).unwrap_or(false)
    }

    pub fn is_failed(&self) -> bool {
        self.session
            .as_ref()
            .map(|s| s.is_failed())
            .unwrap_or(false)
    }

    pub fn file_ids(&self) -> js_sys::Array {
        let out = js_sys::Array::new();
        if let Some(s) = &self.session {
            for id in s.file_ids() {
                out.push(&JsValue::from(id));
            }
        }
        out
    }

    pub fn manifest_json(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(|s| s.manifest())
            .and_then(|m| serde_json::to_string(m).ok())
    }

    pub fn dup_count(&self, file: u16) -> u32 {
        self.session
            .as_ref()
            .map(|s| s.dup_count(file))
            .unwrap_or(0) as u32
    }

    /// Cancel-all constant (65535), exported for JS ergonomics.
    #[wasm_bindgen(js_name = "FILE_ALL")]
    pub fn file_all() -> u16 {
        FILE_ALL
    }

    // -- crypto helpers (vectors parity) ------------------------------------

    /// TEST/parity: derive K_root from a shared secret + sid (hex in, hex out).
    pub fn derive_root_hex(secret_hex: &str, sid_hex: &str) -> Result<String, JsValue> {
        let secret = hex::decode(secret_hex).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let sid = fj_protocol::envelope::parse_sid(sid_hex).map_err(err_js)?;
        let k = fj_protocol::crypto::derive_root(&secret, &sid);
        Ok(hex::encode(*k))
    }

    /// TEST/parity: derive a direction/epoch key.
    pub fn derive_dir_key_hex(
        root_hex: &str,
        sid_hex: &str,
        dir: u32,
        epoch: u32,
    ) -> Result<String, JsValue> {
        let root = fj_protocol::crypto::Key32::new(
            hex::decode(root_hex)
                .map_err(|e| JsValue::from_str(&format!("{e}")))?
                .try_into()
                .map_err(|_| JsValue::from_str("bad root"))?,
        );
        let sid = fj_protocol::envelope::parse_sid(sid_hex).map_err(err_js)?;
        let dir = match dir {
            1 => fj_protocol::crypto::Dir::InitiatorToResponder,
            2 => fj_protocol::crypto::Dir::ResponderToInitiator,
            other => return Err(JsValue::from_str(&format!("bad dir {other}"))),
        };
        let k = fj_protocol::crypto::derive_dir_key(&root, &sid, dir, epoch);
        Ok(hex::encode(*k))
    }

    /// TEST/parity: encrypt a frame payload exactly like the session does.
    pub fn encrypt_frame_hex(
        key_hex: &str,
        epoch: u32,
        dir: u32,
        counter: u32,
        header_hex: &str,
        payload_hex: &str,
    ) -> Result<String, JsValue> {
        let key = fj_protocol::crypto::Key32::new(
            hex::decode(key_hex)
                .map_err(|e| JsValue::from_str(&format!("{e}")))?
                .try_into()
                .map_err(|_| JsValue::from_str("bad key"))?,
        );
        let dir = match dir {
            1 => fj_protocol::crypto::Dir::InitiatorToResponder,
            2 => fj_protocol::crypto::Dir::ResponderToInitiator,
            other => return Err(JsValue::from_str(&format!("bad dir {other}"))),
        };
        let header: [u8; 12] = hex::decode(header_hex)
            .map_err(|e| JsValue::from_str(&format!("{e}")))?
            .try_into()
            .map_err(|_| JsValue::from_str("bad header"))?;
        let payload = hex::decode(payload_hex).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let ct = fj_protocol::crypto::encrypt_frame(&key, epoch, dir, counter, &header, &payload);
        Ok(hex::encode(&ct[..]))
    }

    /// Receipt verification exported for the web UI.
    pub fn verify_receipt(receipt_json: &str, passphrase: &str) -> bool {
        serde_json::from_str::<fj_protocol::Receipt>(receipt_json)
            .map(|r| r.verify(passphrase))
            .unwrap_or(false)
    }

    // -- internals ------------------------------------------------------------

    fn with_session<T>(
        &mut self,
        f: impl FnOnce(&mut Session) -> Result<T, fj_protocol::Error>,
    ) -> Result<T, JsValue> {
        let s = self.session.as_mut().ok_or_else(|| {
            JsValue::from_str("no session: call senderStart/receiverJoin/restore first")
        })?;
        f(s).map_err(err_js)
    }

    fn drain_pending(&mut self) {
        // actions produced inside initiator_accept etc. are empty today; kept
        // for future use
    }
}

impl Default for FjCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Role of the current session ("initiator" | "responder" | "").
#[wasm_bindgen]
pub fn fj_role(core: &FjCore) -> String {
    match core.session.as_ref().map(|s| s.role()) {
        Some(Role::Initiator) => "initiator".into(),
        Some(Role::Responder) => "responder".into(),
        None => String::new(),
    }
}

#[cfg(test)]
mod parity {
    //! WASM parity tests (run with `wasm-pack test --node crates/fj-wasm`):
    //! (a) every vector from tests/vectors/protocol.json reproduced byte-for-byte
    //! through the exported crypto helpers; (b) a full in-memory loopback with a
    //! mid-transfer snapshot/resume, mirroring the native session test.

    use fj_protocol::manifest::FileSpec;
    use fj_protocol::pake::AttemptLimiter;
    use fj_protocol::session::{Action, Session, SessionOpts};
    use wasm_bindgen_test::wasm_bindgen_test;

    fn vectors() -> serde_json::Value {
        let raw = include_str!("../../../tests/vectors/protocol.json");
        serde_json::from_str(raw).expect("vectors JSON")
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(fj_protocol::crypto::sha256(&[data]))
    }

    #[wasm_bindgen_test]
    fn vectors_key_schedule() {
        let v = vectors();
        let root = crate::FjCore::derive_root_hex(
            v["spake_shared_secret_hex"].as_str().unwrap(),
            v["sid_hex"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(root, v["k_root_hex"].as_str().unwrap());
    }

    #[wasm_bindgen_test]
    fn vectors_frames_byte_for_byte() {
        let v = vectors();
        let sid = v["sid_hex"].as_str().unwrap();
        let root =
            crate::FjCore::derive_root_hex(v["spake_shared_secret_hex"].as_str().unwrap(), sid)
                .unwrap();
        let epoch = v["epoch"].as_u64().unwrap() as u32;
        for f in v["frames"].as_array().unwrap() {
            let dir = f["dir"].as_u64().unwrap() as u32;
            let counter = f["counter"].as_u64().unwrap() as u32;
            let plain = f["plain_hex"].as_str().unwrap();
            let header = &plain[..24]; // 12 bytes hex
            let payload = &plain[24..];
            let key = crate::FjCore::derive_dir_key_hex(&root, sid, dir, epoch).unwrap();
            let ct = crate::FjCore::encrypt_frame_hex(&key, epoch, dir, counter, header, payload)
                .unwrap();
            let mut wire = String::from(header);
            wire.push_str(&ct);
            assert_eq!(
                wire,
                f["wire_hex"].as_str().unwrap(),
                "frame kind {}",
                f["kind"]
            );
        }
    }

    #[wasm_bindgen_test]
    fn vectors_receipt_verifies() {
        let v = vectors();
        let receipt = serde_json::to_string(&v["receipt"]).unwrap();
        assert!(crate::FjCore::verify_receipt(
            &receipt,
            v["passphrase"].as_str().unwrap()
        ));
        assert!(!crate::FjCore::verify_receipt(&receipt, "wrong passphrase"));
    }

    // ---------------------------------------------------------------------------
    // behavioral loopback: 3 MiB + empty file + resume
    // ---------------------------------------------------------------------------

    struct Loop {
        ini: Session,
        rsp: Session,
        pass: String,
        ini_out: std::collections::VecDeque<Vec<u8>>,
        rsp_out: std::collections::VecDeque<Vec<u8>>,
        source: Vec<u8>,
        written: std::collections::HashMap<u16, Vec<Option<Vec<u8>>>>,
        done: bool,
        failed: Option<String>,
        receipts: usize,
        verified: bool,
    }

    const OFFER: &str = "v=0\r\no=- wasm loop offer\r\ns=fj\r\n";
    const ANSWER: &str = "v=0\r\no=- wasm loop answer\r\ns=fj\r\n";

    impl Loop {
        fn new(size: usize) -> Loop {
            let mut source = Vec::with_capacity(size);
            let mut x: u64 = 0x1234_5678_9abc_def0;
            for _ in 0..size {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                source.push((x >> 32) as u8);
            }
            let mut limiter = AttemptLimiter::new();
            let (mut ini, pass, blob1) = Session::initiator_new(SessionOpts {
                words: 6,
                private3: false,
                chunk_size: 16384,
                channels: 1,
                sid: Some([0x5a; 16]),
                offer_sdp: OFFER.into(),
            })
            .unwrap();
            let (rsp, blob2) =
                Session::responder_join(&blob1, &pass, ANSWER, &mut limiter).unwrap();
            ini.initiator_accept(&blob2).unwrap();
            let empty_sha = sha256_hex(b"");
            ini.set_files(&[
                FileSpec {
                    name: "big.bin".into(),
                    path: String::new(),
                    size: source.len() as u64,
                    sha256: sha256_hex(&source),
                    gzip: false,
                },
                FileSpec {
                    name: "empty.dat".into(),
                    path: String::new(),
                    size: 0,
                    sha256: empty_sha,
                    gzip: false,
                },
            ])
            .unwrap();
            let mut l = Loop {
                ini,
                rsp,
                pass: pass.clone(),
                ini_out: Default::default(),
                rsp_out: Default::default(),
                source,
                written: Default::default(),
                done: false,
                failed: None,
                receipts: 0,
                verified: false,
            };
            let a = l.ini.on_channel_open();
            l.apply_ini(a);
            let b = l.rsp.on_channel_open();
            l.apply_rsp(b);
            l
        }

        fn apply_ini(&mut self, actions: Vec<Action>) {
            self.apply(actions, true);
        }

        fn apply_rsp(&mut self, actions: Vec<Action>) {
            self.apply(actions, false);
        }

        fn apply(&mut self, actions: Vec<Action>, ini_side: bool) {
            for a in actions {
                match a {
                    Action::Send(bytes) => {
                        if ini_side {
                            self.ini_out.push_back(bytes);
                        } else {
                            self.rsp_out.push_back(bytes);
                        }
                    }
                    Action::SaveChunk { file, index, data } => {
                        let slots = self.written.entry(file).or_default();
                        if slots.len() <= index as usize {
                            slots.resize(index as usize + 1, None);
                        }
                        slots[index as usize] = Some(data);
                    }
                    Action::HashFeed { file } => {
                        let mut buf = Vec::new();
                        for s in self.written.get(&file).into_iter().flatten().flatten() {
                            buf.extend_from_slice(s);
                        }
                        let more = self.rsp.hash_feed(file, &buf).unwrap();
                        self.apply(more, false);
                    }
                    Action::FileDone { verified, .. } => {
                        self.verified = verified;
                    }
                    Action::Receipt(_) => {
                        self.receipts += 1;
                    }
                    Action::SessionDone => {
                        self.done = true;
                    }
                    Action::Fail { code, msg } => {
                        self.failed = Some(format!("{code}: {msg}"));
                    }
                    _ => {}
                }
            }
        }

        fn deliver(&mut self) {
            while let Some(w) = self.ini_out.pop_front() {
                let acts = self.rsp.on_frame(&w).unwrap();
                self.apply_rsp(acts);
            }
            while let Some(w) = self.rsp_out.pop_front() {
                let acts = self.ini.on_frame(&w).unwrap();
                self.apply_ini(acts);
            }
        }

        fn push_chunks(&mut self, max: usize) {
            let mut pushed = 0;
            'outer: for file in self.ini.file_ids() {
                while let Some((index, len)) = self.ini.next_send_chunk(file) {
                    let start = (index * 16384) as usize;
                    let end = (start + len as usize).min(self.source.len());
                    let bytes = self.source[start..end].to_vec();
                    let (wire, actions) = self.ini.push_chunk_data(file, index, &bytes).unwrap();
                    self.ini_out.push_back(wire);
                    self.apply_ini(actions);
                    pushed += 1;
                    self.deliver();
                    if pushed >= max {
                        break 'outer;
                    }
                }
            }
        }

        fn received(&self, file: u16) -> Vec<u8> {
            let mut out = Vec::new();
            for s in self.written.get(&file).into_iter().flatten().flatten() {
                out.extend_from_slice(s);
            }
            out
        }
    }

    #[wasm_bindgen_test]
    fn loopback_3mib_and_receipts() {
        let mut l = Loop::new(3 << 20);
        l.deliver();
        l.push_chunks(usize::MAX);
        l.deliver();
        assert!(l.failed.is_none(), "no failure: {:?}", l.failed);
        assert!(l.done, "session completes");
        assert!(l.verified, "hash verified");
        assert_eq!(l.receipts, 4, "2 receipts each side");
        assert_eq!(l.received(0), l.source, "bytes identical");
        assert_eq!(l.received(1), Vec::<u8>::new());
    }

    #[wasm_bindgen_test]
    fn loopback_resume_epoch_bump() {
        let mut l = Loop::new(1 << 20);
        l.deliver();
        l.push_chunks(20); // 20 of 64 chunks, then "crash"
        l.deliver();

        let snap_ini = l.ini.snapshot();
        let snap_rsp = l.rsp.snapshot();
        let pass = l.pass.clone();

        let mut ini2 = Session::restore(&snap_ini).unwrap();
        let mut rsp2 = Session::restore(&snap_rsp).unwrap();
        let new_offer = "v=0\\r\\no=- wasm resume offer\\r\\ns=fj\\r\\n";
        let new_answer = "v=0\\r\\no=- wasm resume answer\\r\\ns=fj\\r\\n";
        let mut limiter = AttemptLimiter::new();
        let blob1 = ini2.resume_initiator(&pass, new_offer).unwrap();
        assert_eq!(ini2.epoch(), 1, "epoch bumped");
        let blob2 = rsp2
            .resume_responder(&blob1, &pass, new_answer, &mut limiter)
            .unwrap();
        ini2.initiator_accept(&blob2).unwrap();

        let mut l2 = Loop {
            ini: ini2,
            rsp: rsp2,
            ini_out: Default::default(),
            rsp_out: Default::default(),
            source: l.source.clone(),
            written: l.written.clone(),
            done: false,
            failed: None,
            receipts: 0,
            verified: false,
            pass,
        };
        let a = l2.ini.on_channel_open();
        l2.apply_ini(a);
        let b = l2.rsp.on_channel_open();
        l2.apply_rsp(b);
        l2.deliver();
        // the receiver's BITMAP says which chunks it already has; the sender
        // must observe resumed progress before pushing
        l2.push_chunks(usize::MAX);
        l2.deliver();
        assert!(l2.failed.is_none(), "no failure: {:?}", l2.failed);
        assert!(l2.done, "session completes after resume");
        assert!(l2.verified, "hash verified after resume");
        assert_eq!(l2.received(0), l2.source, "bytes identical after resume");
    }
}
