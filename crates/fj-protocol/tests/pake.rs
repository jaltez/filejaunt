//! PAKE canonicalization and shared-secret tests.

mod common;

use fj_protocol::crypto::derive_root;
use fj_protocol::pake::{AttemptLimiter, PakeSide, canonical_passphrase};

fn kroot_both(pass: &str, sid: &[u8; 16]) -> (String, String) {
    let canon = canonical_passphrase(pass);
    let a = PakeSide::start_initiator(canon.as_bytes(), sid);
    let b = PakeSide::start_responder(canon.as_bytes(), sid);
    let msg_a = a.message().to_vec();
    let msg_b = b.message().to_vec();
    let sa = a.finish(&msg_b).unwrap();
    let sb = b.finish(&msg_a).unwrap();
    let ka = derive_root(&sa, sid);
    let kb = derive_root(&sb, sid);
    (hex::encode(*ka), hex::encode(*kb))
}

#[test]
fn canonical_table() {
    let cases = [
        ("  alpha  bravo  charlie ", "alpha-bravo-charlie"),
        ("alpha-bravo-charlie", "alpha-bravo-charlie"),
        ("Alpha BRavo---CHARLIE", "alpha-bravo-charlie"),
        ("ALPHA-BRAVO", "alpha-bravo"),
        ("-alpha-bravo-", "alpha-bravo"),
        ("alpha\tbravo\ncharlie", "alpha-bravo-charlie"),
        ("café-bravo", "cafe-bravo"), // NFKD e + combining acute -> e
        ("CAFÉ-BRAVO", "cafe-bravo"),
        ("", ""),
        ("   ", ""),
        ("śpiołki-ŻÓŁW", "spiołki-zołw"), // ś/Ż decompose; ł has no NFKD decomposition
    ];
    for (input, expect) in cases {
        assert_eq!(canonical_passphrase(input), expect, "input {input:?}");
    }
}

#[test]
fn kroot_equal_both_sides() {
    let sid = [42u8; 16];
    let (ka, kb) = kroot_both("alpha bravo charlie delta echo foxtrot", &sid);
    assert_eq!(ka, kb);
    assert_eq!(ka.len(), 64);
}

#[test]
fn kroot_differs_by_passphrase_and_sid() {
    let s1 = [1u8; 16];
    let s2 = [2u8; 16];
    let (a1, _) = kroot_both("pass one here", &s1);
    let (a2, _) = kroot_both("pass two here", &s1);
    let (a3, _) = kroot_both("pass one here", &s2);
    assert_ne!(a1, a2, "passphrase changes key");
    assert_ne!(a1, a3, "sid salts the derivation");
}

#[test]
fn pake_finish_rejects_bad_messages() {
    let sid = [9u8; 16];
    let a = PakeSide::start_initiator(b"passphrase-x", &sid);
    assert!(a.finish(&[0u8; 5]).is_err(), "wrong length");
    let a = PakeSide::start_initiator(b"passphrase-x", &sid);
    assert!(a.finish(&[1u8; 33]).is_err(), "garbage point");
}

#[test]
fn shared_secret_is_fresh_per_run() {
    // CDH: two honest runs with the same passphrase derive DIFFERENT secrets
    // (fresh scalars per run); only the live session knows its own key.
    let sid = [5u8; 16];
    let pass = canonical_passphrase("reproducible passphrase");
    let k1 = {
        let canon = canonical_passphrase("reproducible passphrase");
        let a = PakeSide::start_initiator(canon.as_bytes(), &sid);
        let b = PakeSide::start_responder(canon.as_bytes(), &sid);
        let msg_a = a.message().to_vec();
        let msg_b = b.message().to_vec();
        let sa = a.finish(&msg_b).unwrap();
        let sb = b.finish(&msg_a).unwrap();
        assert_eq!(&*sa, &*sb, "same run, both sides agree");
        (sa, ())
    };
    k2;
    let canon2 = pass;
    let a2 = PakeSide::start_initiator(canon2.as_bytes(), &sid);
    let b2 = PakeSide::start_responder(canon2.as_bytes(), &sid);
    let mb = b2.message().to_vec();
    let sa2 = a2.finish(&mb).unwrap();
    assert_ne!(&*k1, &*sa2, "second run derives an independent secret");
}

#[test]
fn receipt_mac_pf_verify() {
    use fj_protocol::crypto::derive_receipt_pf;
    use fj_protocol::receipt::{Receipt, ReceiptMsg, receipt_mac_pf};
    let sid = [5u8; 16];
    let pass = canonical_passphrase("receipt passphrase words");
    let k = derive_receipt_pf(pass.as_bytes(), &sid);
    let msg = ReceiptMsg {
        file: 0,
        sha256: "ab".repeat(32),
        bytes: 123,
        ts: 1_700_000_000,
        mac: "session-mac".into(),
    };
    let macpf = receipt_mac_pf(&k, msg.file, &msg.sha256, msg.bytes, msg.ts);
    let r = Receipt::from_msg(&msg, &hex::encode(sid), "cGFrZTE=", "cGFrZTI=", &macpf);
    assert!(r.verify(&pass), "correct passphrase verifies");
    assert!(!r.verify("wrong passphrase"), "wrong passphrase rejected");
    // structural tamper: change bytes
    let mut bad = r.clone();
    bad.bytes += 1;
    assert!(!bad.verify(&pass), "tampered field rejected");
}

#[test]
fn three_failures_limit() {
    let mut limiter = AttemptLimiter::new();
    let sid = [1u8; 16];
    assert!(limiter.record_failure(&sid).is_ok());
    assert!(limiter.record_failure(&sid).is_ok());
    assert_eq!(
        limiter.record_failure(&sid).unwrap_err().code(),
        fj_protocol::ErrorCode::SecAttemptLimit
    );
}
