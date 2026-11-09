//! Dev tasks: `cargo xtask gen-vectors` writes tests/vectors/protocol.json.
//!
//! The vectors pin the protocol PRIMITIVES byte-for-byte with a fixed
//! passphrase + sid: the SPAKE2 exchange is run once here and its shared
//! secret is recorded (test-only disclosure), so both the native and the
//! WASM suites can re-derive the exact key schedule (HKDF chain), re-encrypt
//! the canonical frame set (AES-GCM, nonce = epoch|dir|counter, AAD =
//! header), and compare ciphertexts byte-for-byte. Session-level behavior is
//! covered identically on both platforms by the in-memory loopback tests.

use fj_protocol::crypto::{self, Dir};
use fj_protocol::pake::AttemptLimiter;
use fj_protocol::pake::{PakeSide, canonical_passphrase};
use serde_json::json;

use fj_protocol::ErrorCode;
use fj_protocol::frame::Frame;
use fj_protocol::manifest::{FileSpec, build_manifest};
use fj_protocol::receipt::{receipt_mac, receipt_mac_pf};
use fj_protocol::session::{Session, SessionOpts};

fn main() {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "gen-vectors" => gen_vectors(),
        other => {
            eprintln!("usage: cargo xtask <gen-vectors>");
            eprintln!("unknown task {other:?}");
            std::process::exit(2);
        }
    }
}

const PASSPHRASE: &str = "alpha bravo charlie delta vector";
const SID: [u8; 16] = [0x42; 16];
const EPOCH: u32 = 0;
const OFFER: &str = "v=0\r\no=- vector offer sdp\r\ns=fj-vector\r\n";
const ANSWER: &str = "v=0\r\no=- vector answer sdp\r\ns=fj-vector\r\n";
const FILE_DATA: &[u8] = b"filejaunt protocol vector payload - 0123456789abcdef";
const CHUNK_SIZE: u32 = 16384;
const TS: i64 = 1_700_000_000;

fn gen_vectors() {
    let canon = canonical_passphrase(PASSPHRASE);

    // ---- PAKE pairing (recorded once) ----
    let a = PakeSide::start_initiator(canon.as_bytes(), &SID);
    let b = PakeSide::start_responder(canon.as_bytes(), &SID);
    let msg_a = a.message().to_vec();
    let msg_b = b.message().to_vec();
    let secret = a.finish(&msg_b).expect("pake a");
    let secret_b = b.finish(&msg_a).expect("pake b");
    assert_eq!(&*secret, &*secret_b, "SPAKE2 sides must agree");

    // ---- key schedule ----
    let k_root = crypto::derive_root(&secret, &SID);
    let k_confirm = crypto::derive_confirm(&k_root, &SID);
    let k_receipt = crypto::derive_receipt(&k_root, &SID);
    let k_pf = crypto::derive_receipt_pf(canon.as_bytes(), &SID);
    let k_env_o = crypto::derive_env_offer(&k_root, &SID);
    let k_env_a = crypto::derive_env_answer(&k_root, &SID);

    // ---- envelopes (same shapes the Session emits) ----
    let env1 = fj_protocol::envelope::Envelope1 {
        v: 1,
        sid: hex::encode(SID),
        pake: fj_protocol::envelope::b64(&msg_a),
        sdp: Some(OFFER.into()),
        ep: EPOCH,
        mode: "p2".into(),
        ch: 1,
    };
    let blob1 = fj_protocol::envelope::serialize(&env1).unwrap();
    let ct_answer = crypto::encrypt_sdp(&k_env_a, "sdp-answer", ANSWER);
    let env2 = fj_protocol::envelope::Envelope2 {
        v: 1,
        pake: fj_protocol::envelope::b64(&msg_b),
        sdpe: Some(fj_protocol::envelope::b64(&ct_answer)),
    };
    let blob2 = fj_protocol::envelope::serialize(&env2).unwrap();
    // p3 private envelopes: offer encrypted
    let ct_offer = crypto::encrypt_sdp(&k_env_o, "sdp-offer", OFFER);
    let env3 = fj_protocol::envelope::Envelope3 {
        v: 1,
        sdpe: fj_protocol::envelope::b64(&ct_offer),
    };
    let blob3 = fj_protocol::envelope::serialize(&env3).unwrap();

    // ---- canonical frame set ----
    let manifest = build_manifest(
        &SID,
        EPOCH,
        &[FileSpec {
            name: "vector.bin".into(),
            path: String::new(),
            size: FILE_DATA.len() as u64,
            sha256: hex::encode(crypto::sha256(&[FILE_DATA])),
            gzip: false,
            supersedes: None,
        }],
        CHUNK_SIZE,
    )
    .unwrap();
    let fp = crypto::confirm_fp(&k_confirm, OFFER, ANSWER, &SID);
    let sha_hex = hex::encode(crypto::sha256(&[FILE_DATA]));
    let rmsg_mac = receipt_mac(&k_receipt, 0, &sha_hex, FILE_DATA.len() as u64, TS);
    let rmsg_macpf = receipt_mac_pf(&k_pf, 0, &sha_hex, FILE_DATA.len() as u64, TS);

    // (frame, direction, control-seq) in flight order; counters assigned per
    // direction in this order.
    let script: Vec<(Frame, Dir, u32)> = vec![
        (
            Frame::Hello {
                role: 0,
                version: 1,
                fp,
                caps: 0,
            },
            Dir::InitiatorToResponder,
            0,
        ),
        (
            Frame::Hello {
                role: 1,
                version: 1,
                fp,
                caps: 0,
            },
            Dir::ResponderToInitiator,
            0,
        ),
        (
            Frame::Manifest(manifest.clone()),
            Dir::InitiatorToResponder,
            1,
        ),
        (
            Frame::Chunk {
                file: 0,
                index: 0,
                gzip: false,
                data: FILE_DATA.to_vec(),
            },
            Dir::InitiatorToResponder,
            0,
        ),
        (Frame::Done { file: 0 }, Dir::InitiatorToResponder, 2),
        (
            Frame::Receipt(fj_protocol::ReceiptMsg {
                file: 0,
                sha256: sha_hex.clone(),
                bytes: FILE_DATA.len() as u64,
                ts: TS,
                mac: rmsg_mac.clone(),
            }),
            Dir::ResponderToInitiator,
            1,
        ),
        (
            Frame::Text("vector text".into()),
            Dir::ResponderToInitiator,
            2,
        ),
        (
            Frame::Error {
                code: ErrorCode::PeerCancel,
                msg: "vector error".into(),
            },
            Dir::ResponderToInitiator,
            3,
        ),
    ];

    let mut counters = std::collections::HashMap::<u32, u32>::new(); // dir -> next counter
    let frames: Vec<serde_json::Value> = script
        .iter()
        .map(|(frame, dir, seq)| {
            let counter = *counters.entry(dir.as_u32()).or_insert(0);
            counters.insert(dir.as_u32(), counter + 1);
            let mut plain = Vec::new();
            frame.encode(&mut plain, *seq);
            let mut header = [0u8; 12];
            header.copy_from_slice(&plain[..12]);
            let key = crypto::derive_dir_key(&k_root, &SID, *dir, EPOCH);
            let ct = crypto::encrypt_frame(&key, EPOCH, *dir, counter, &header, &plain[12..]);
            let mut wire = plain[..12].to_vec();
            wire.extend_from_slice(&ct);
            json!({
                "dir": dir.as_u32(),
                "epoch": EPOCH,
                "counter": counter,
                "kind": frame.kind() as u8,
                "plain_hex": hex::encode(&plain),
                "wire_hex": hex::encode(&wire),
            })
        })
        .collect();

    // ---- receipt (exported shape) ----
    let receipt = fj_protocol::Receipt::from_msg(
        &fj_protocol::ReceiptMsg {
            file: 0,
            sha256: sha_hex.clone(),
            bytes: FILE_DATA.len() as u64,
            ts: TS,
            mac: rmsg_mac,
        },
        &hex::encode(SID),
        &fj_protocol::envelope::b64(&msg_a),
        &fj_protocol::envelope::b64(&msg_b),
        &rmsg_macpf,
    );
    assert!(receipt.verify(PASSPHRASE), "exported receipt verifies");

    // ---- sanity: the Session accepts the recorded blob pair ----
    let mut limiter = AttemptLimiter::new();
    let (mut ini, _gen, _live_blob1) = Session::initiator_new(SessionOpts {
        words: 6,
        private3: false,
        chunk_size: CHUNK_SIZE,
        channels: 1,
        sid: Some(SID),
        offer_sdp: OFFER.into(),
    })
    .unwrap();
    let _ = &mut ini;
    let (rsp, live2) = Session::responder_join(&blob1, PASSPHRASE, ANSWER, &mut limiter)
        .expect("recorded blob1 parses and joins");
    let _ = (rsp, live2);

    let vectors = json!({
        "v": 1,
        "_note": "TEST VECTORS ONLY: passphrase, sid and the SPAKE2 shared secret are fixed test values pinned to these recorded frames. They unlock nothing outside this file - real sessions derive fresh keys from fresh SPAKE2 runs.",
        "passphrase": PASSPHRASE,
        "passphrase_canonical": canon,
        "sid_hex": hex::encode(SID),
        "epoch": EPOCH,
        "offer_sdp": OFFER,
        "answer_sdp": ANSWER,
        "chunk_size": CHUNK_SIZE,
        "spake_msg_a_b64": fj_protocol::envelope::b64(&msg_a),
        "spake_msg_b_b64": fj_protocol::envelope::b64(&msg_b),
        "spake_shared_secret_hex": hex::encode(&*secret),
        "k_root_hex": hex::encode(*k_root),
        "confirm_fp_hex": hex::encode(fp),
        "file": {
            "name": "vector.bin",
            "data_hex": hex::encode(FILE_DATA),
            "sha256": sha_hex,
        },
        "blob1": blob1,
        "blob2": blob2,
        "blob3": blob3,
        "frames": frames,
        "receipt": serde_json::to_value(&receipt).unwrap(),
    });

    let out = std::path::Path::new("tests/vectors/protocol.json");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(out, serde_json::to_string_pretty(&vectors).unwrap()).unwrap();
    println!("wrote {} ({} frames)", out.display(), frames.len());
}
