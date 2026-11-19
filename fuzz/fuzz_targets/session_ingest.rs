#![no_main]
//! Fuzz the sans-IO `Session` state machine through its REAL ingest path:
//! `Session::on_frame` = header split + AES-GCM decrypt (counter from header
//! seq, D4) + `Frame::decode` + state transition. Outbound actions and
//! snapshot/restore are driven as well. Goal: panics/unwraps in the state
//! machine under attacker input; logical properties (auth, traversal) belong
//! to review, not to this harness.
//!
//! Input layout: data[0] selects a mode.
//!  0 = raw attacker bytes -> on_frame of a paired, post-HELO responder
//!  1 = raw attacker bytes -> on_frame of a paired, pre-HELO responder
//!      (decrypt failure must surface as SEC_PAKE_FAILED, not a panic)
//!  2 = scripted: record stream building properly-encrypted attacker frames
//!      (responder is the receiver under attack) + outbound API calls
//!  3 = arbitrary string -> Session::restore
use fj_protocol::crypto::{self, Dir, Key32};
use fj_protocol::frame::Frame;
use fj_protocol::manifest::{FileEntry, FileSpec, GzipPolicy, Manifest};
use fj_protocol::pake::AttemptLimiter;
use fj_protocol::receipt::ReceiptMsg;
use fj_protocol::session::{Action, Session, SessionOpts};
use fj_protocol::ErrorCode;
use fj_protocol_fuzz::{fake_sha256, hex_decode, Rd, ANSWER_SDP, OFFER_SDP, TEST_SID};
use libfuzzer_sys::fuzz_target;

const MAX_RECORDS: usize = 200;

/// Pair a fresh initiator + responder (same shape as tests/common/mod.rs,
/// p2 mode, fixed sid). Setup failures end the input, not the fuzzer.
fn pair() -> Option<(Session, Session)> {
    let mut limiter = AttemptLimiter::new();
    let (mut ini, passphrase, blob1) = Session::initiator_new(SessionOpts {
        words: 6,
        private3: false,
        chunk_size: 16384,
        channels: 1,
        sid: Some(TEST_SID),
        offer_sdp: OFFER_SDP.to_string(),
    })
    .ok()?;
    let (rsp, blob2) =
        Session::responder_join(&blob1, &passphrase, ANSWER_SDP, &mut limiter).ok()?;
    ini.initiator_accept(&blob2).ok()?;
    Some((ini, rsp))
}

/// Cross-deliver actions: every Send goes to the peer's real ingest path.
fn deliver(dst: &mut Session, actions: Vec<Action>) {
    for a in actions {
        if let Action::Send(w) = a {
            let _ = dst.on_frame(&w);
        }
    }
}

/// Build an attacker-controlled frame, encrypt it with the REAL initiator
/// direction key (epoch 0) and feed it to the responder's ingest path.
/// Per D4 the nonce counter rides in the header seq field, so any counter
/// value produces a well-formed frame the decrypt layer must accept.
fn craft(rsp: &mut Session, ini: &mut Session, key: &Key32, frame: &Frame, counter: u32) {
    let mut plain = Vec::new();
    frame.encode(&mut plain, counter);
    let mut header = [0u8; 12];
    header.copy_from_slice(&plain[..12]);
    let ct = crypto::encrypt_frame(
        key,
        0,
        Dir::InitiatorToResponder,
        counter,
        &header,
        &plain[12..],
    );
    let mut wire = plain[..12].to_vec();
    wire.extend_from_slice(&ct);
    let actions = rsp.on_frame(&wire).unwrap_or_default();
    deliver(ini, actions);
}

/// Initiator->responder direction key for epoch 0 from the test accessor.
fn peer_key(ini: &Session) -> Option<Key32> {
    let hex = ini.k_root_hex_for_test()?;
    let root = crypto::derive_root(&hex_decode(&hex), &TEST_SID);
    Some(crypto::derive_dir_key(&root, &TEST_SID, Dir::InitiatorToResponder, 0))
}

fn entry(r: &mut Rd) -> FileEntry {
    let name_len = (r.u8() % 64) as usize;
    let path_len = (r.u8() % 64) as usize;
    FileEntry {
        id: r.u16(),
        name: r.str(name_len),
        path: r.str(path_len),
        size: r.u64() % 1_000_000,
        chunks: r.u64() % 70_000,
        chunk_size: 16384,
        sha256: fake_sha256(r.u64()),
        supersedes: if r.u8() & 1 == 0 {
            None
        } else {
            Some(r.u16())
        },
    }
}

fn mode_raw(data: &[u8], open_channel: bool) {
    let Some((mut ini, mut rsp)) = pair() else { return };
    if open_channel {
        let a = ini.on_channel_open();
        let b = rsp.on_channel_open();
        deliver(&mut rsp, a);
        deliver(&mut ini, b);
    }
    let _ = rsp.on_frame(data);
}

fn mode_scripted(data: &[u8]) {
    let Some((mut ini, mut rsp)) = pair() else { return };
    let mut r = Rd::new(data);

    // attacker-influenced sender file set (invalid names just fail set_files)
    let n = (r.u8() % 5) as usize;
    let specs: Vec<FileSpec> = (0..n)
        .map(|i| {
            let fixed_name = r.u8() & 1 == 0;
            let name_len = (r.u8() % 64) as usize;
            let path_len = (r.u8() % 64) as usize;
            FileSpec {
                name: if fixed_name {
                    format!("f{i}.bin")
                } else {
                    r.str(name_len)
                },
                path: r.str(path_len),
                size: r.u64() % 100_000,
                sha256: fake_sha256(r.u64()),
                gzip: r.u8() & 1 == 1,
                supersedes: None,
            }
        })
        .collect();
    let _ = ini.set_files(&specs);

    let a = ini.on_channel_open();
    let b = rsp.on_channel_open();
    deliver(&mut rsp, a);
    deliver(&mut ini, b);

    let Some(key) = peer_key(&ini) else { return };

    for _ in 0..MAX_RECORDS {
        if r.done() {
            break;
        }
        let counter = r.u32();
        match r.u8() % 21 {
            0 => {
                let data = r.bytes(2048).to_vec();
                craft(&mut rsp, &mut ini, &key,
                    &Frame::Chunk { file: r.u16(), index: r.u64(), gzip: r.u8() & 1 == 1, data }, counter)
            }
            1 => {
                let runs = (0..r.u8() % 8).map(|_| (r.u64(), r.u64())).collect();
                craft(&mut rsp, &mut ini, &key, &Frame::Bitmap { file: r.u16(), runs }, counter)
            }
            2 => craft(&mut rsp, &mut ini, &key, &Frame::Pause { file: r.u16() }, counter),
            3 => craft(&mut rsp, &mut ini, &key, &Frame::Resume { file: r.u16() }, counter),
            4 => craft(&mut rsp, &mut ini, &key, &Frame::Cancel { file: r.u16() }, counter),
            5 => craft(&mut rsp, &mut ini, &key, &Frame::Done { file: r.u16() }, counter),
            6 => craft(&mut rsp, &mut ini, &key, &Frame::Remove { file: r.u16() }, counter),
            7 => {
                let (file, from, to) = (r.u16(), r.u64(), r.u64());
                craft(&mut rsp, &mut ini, &key, &Frame::ChunkReq { file, from, to }, counter)
            }
            8 => {
                let msg = ReceiptMsg {
                    file: r.u16(),
                    sha256: fake_sha256(r.u64()),
                    bytes: r.u64(),
                    ts: r.u64() as i64,
                    mac: r.str(88),
                };
                craft(&mut rsp, &mut ini, &key, &Frame::Receipt(msg), counter)
            }
            9 => craft(&mut rsp, &mut ini, &key, &Frame::Text(r.str(600)), counter),
            10 => {
                let msg = r.str(64);
                craft(&mut rsp, &mut ini, &key,
                    &Frame::Error { code: ErrorCode::ProtoMalformed, msg }, counter)
            }
            11 => craft(&mut rsp, &mut ini, &key, &Frame::Bye, counter),
            12 => {
                let files = (0..r.u8() % 4).map(|_| entry(&mut r)).collect();
                craft(&mut rsp, &mut ini, &key, &Frame::Append(files), counter)
            }
            13 => {
                let files = (0..r.u8() % 4).map(|_| entry(&mut r)).collect();
                let m = Manifest {
                    v: 1,
                    sid: "42".repeat(16),
                    epoch: r.u32(),
                    gzip: match r.u8() % 3 {
                        0 => GzipPolicy::Auto,
                        1 => GzipPolicy::On,
                        _ => GzipPolicy::Off,
                    },
                    files,
                    total: r.u64(),
                    live: r.u8() & 1 == 1,
                };
                craft(&mut rsp, &mut ini, &key, &Frame::Manifest(m), counter)
            }
            14 => {
                let mut fp = [0u8; 32];
                let b = r.bytes(32);
                fp[..b.len()].copy_from_slice(b);
                let (role, version, caps) = (r.u8(), r.u8(), r.u8());
                craft(&mut rsp, &mut ini, &key,
                    &Frame::Hello { role, version, fp, caps }, counter)
            }
            15 => {
                let raw = r.bytes(1024).to_vec();
                let _ = rsp.on_frame(&raw);
            }
            16 => {
                // outbound actions on the initiator (real sender path)
                let file = r.u16();
                match r.u8() % 5 {
                    0 => deliver(&mut rsp, ini.pause(file)),
                    1 => deliver(&mut rsp, ini.resume(file)),
                    2 => deliver(&mut rsp, ini.cancel(file)),
                    3 => {
                        if let Ok(w) = ini.send_text(&r.str(600)) {
                            let _ = rsp.on_frame(&w);
                        }
                    }
                    _ => {
                        if let Ok(a) = ini.end_session() {
                            deliver(&mut rsp, a);
                        }
                    }
                }
            }
            17 => {
                // sender chunk push (real encrypt + rx path)
                let bytes = r.bytes(2048).to_vec();
                if let Ok((w, a)) = ini.push_chunk_data(r.u16(), r.u64(), &bytes) {
                    let _ = rsp.on_frame(&w);
                    deliver(&mut rsp, a);
                }
            }
            18 => {
                // receiver hash feed (glue re-reads written bytes)
                let bytes = r.bytes(2048).to_vec();
                if let Ok(a) = rsp.hash_feed(r.u16(), &bytes) {
                    deliver(&mut ini, a);
                }
            }
            19 => {
                // snapshot roundtrip + arbitrary restore
                let snap = ini.snapshot();
                if let Ok(restored) = Session::restore(&snap) {
                    let _ = restored.snapshot();
                }
                let _ = Session::restore(&r.str(256));
            }
            _ => {
                // outbound actions on the responder
                let file = r.u16();
                match r.u8() % 4 {
                    0 => deliver(&mut ini, rsp.pause(file)),
                    1 => deliver(&mut ini, rsp.resume(file)),
                    2 => deliver(&mut ini, rsp.cancel(file)),
                    _ => {
                        if let Ok(w) = rsp.send_text(&r.str(600)) {
                            let _ = ini.on_frame(&w);
                        }
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(&mode) = data.first() else { return };
    let body = &data[1..];
    match mode % 4 {
        0 => mode_raw(body, true),
        1 => mode_raw(body, false),
        2 => mode_scripted(body),
        _ => {
            let _ = Session::restore(&String::from_utf8_lossy(body));
        }
    }
});
