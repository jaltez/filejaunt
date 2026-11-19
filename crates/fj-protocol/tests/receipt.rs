//! Receipt export shape and verification (F14): no `mac` in exports, old
//! receipts with `mac` still verify, malformed PAKE transcripts rejected.

use base64::Engine;
use fj_protocol::crypto::derive_receipt_pf;
use fj_protocol::pake::{PAKE_MSG_LEN, canonical_passphrase};
use fj_protocol::receipt::{Receipt, receipt_mac_pf};

fn pake_b64(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([seed; PAKE_MSG_LEN])
}

#[test]
fn export_omits_mac_and_old_receipts_still_verify() {
    let sid = [5u8; 16];
    let pass = canonical_passphrase("word one word two");
    let k_pf = derive_receipt_pf(pass.as_bytes(), &sid);
    let sha256 = "cd".repeat(32);
    let macpf = receipt_mac_pf(&k_pf, 3, &sha256, 777, 1_700_000_000);

    let r = Receipt {
        v: 1,
        sid: hex::encode(sid),
        pake1: pake_b64(1),
        pake2: pake_b64(2),
        file: 3,
        sha256: sha256.clone(),
        bytes: 777,
        ts: 1_700_000_000,
        macpf,
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(
        !json.contains("\"mac\":"),
        "export carries no K_receipt mac"
    );
    assert!(json.contains("\"macpf\""));

    // old-format receipt JSON (arbitrary `mac`) deserializes and verifies
    // only with the right passphrase
    let old = serde_json::json!({
        "v": 1,
        "sid": hex::encode(sid),
        "pake1": pake_b64(1),
        "pake2": pake_b64(2),
        "file": 3,
        "sha256": sha256,
        "bytes": 777,
        "ts": 1_700_000_000,
        "mac": "totally-arbitrary-old-mac=",
        "macpf": r.macpf,
    });
    let old: Receipt = serde_json::from_value(old).unwrap();
    assert!(
        old.verify("  Word One  word-TWO  "),
        "canonical forms verify"
    );
    assert!(!old.verify("wrong passphrase"));
}

#[test]
fn malformed_pake_transcript_never_verifies() {
    let sid = [6u8; 16];
    let pass = canonical_passphrase("valid passphrase here");
    let k_pf = derive_receipt_pf(pass.as_bytes(), &sid);
    let sha256 = "ef".repeat(32);
    let macpf = receipt_mac_pf(&k_pf, 0, &sha256, 1, 42);

    let good = Receipt {
        v: 1,
        sid: hex::encode(sid),
        pake1: pake_b64(1),
        pake2: pake_b64(2),
        file: 0,
        sha256: sha256.clone(),
        bytes: 1,
        ts: 42,
        macpf: macpf.clone(),
    };
    assert!(good.verify("valid passphrase here"));

    // pake1 of the wrong length: MAC would match, must still be false
    let mut bad = good.clone();
    bad.pake1 = base64::engine::general_purpose::STANDARD.encode([1u8; 10]);
    assert!(!bad.verify("valid passphrase here"), "short pake1 rejected");

    let mut bad = good.clone();
    bad.pake2 = "not-base64!!".to_string();
    assert!(
        !bad.verify("valid passphrase here"),
        "non-b64 pake2 rejected"
    );
}
