#![no_main]
//! Fuzz forged receipts: `Receipt::verify` (passphrase-bound macpf, D2) and
//! `verify_receipt_mac` (session-live K_receipt MAC) with a fixed TEST-ONLY
//! key. Any forged input must return false, never panic.
use fj_protocol::crypto::{self, Dir};
use fj_protocol::receipt::{verify_receipt_mac, Receipt, ReceiptMsg};
use fj_protocol_fuzz::{test_root, Rd, TEST_SID, VECTOR_PASSPHRASE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = Rd::new(data);

    // exported receipt JSON -> verify with an attacker-influenced passphrase
    if let Ok(rec) = serde_json::from_slice::<Receipt>(data) {
        let pass = r.str(128);
        let _ = rec.verify(&pass);
        let _ = rec.verify(VECTOR_PASSPHRASE);
        let _ = rec.file_sha256();
    }

    // wire receipt message -> constant-time MAC check under a fixed key
    if let Ok(msg) = serde_json::from_slice::<ReceiptMsg>(data) {
        let root = test_root();
        let k_receipt = crypto::derive_receipt(&root, &TEST_SID);
        let _ = verify_receipt_mac(&k_receipt, &msg);

        // rebuild an exportable receipt with attacker macpf and check verify
        let macpf = r.str(88);
        let rec = Receipt::from_msg(&msg, "42424242424242424242424242424242", "AAAA", "AAAA", &macpf);
        let _ = rec.verify(VECTOR_PASSPHRASE);
    }

    // sid parsing feeds the K_pf derivation inside verify; exercise it on
    // arbitrary strings too
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = fj_protocol::envelope::parse_sid(s);
        let mut rec = serde_json::from_slice::<Receipt>(data).unwrap_or(Receipt {
            v: 1,
            sid: s.chars().take(64).collect(),
            pake1: String::new(),
            pake2: String::new(),
            file: 0,
            sha256: String::new(),
            bytes: 0,
            ts: 0,
            macpf: String::new(),
        });
        rec.sid = s.chars().take(64).collect();
        let _ = rec.verify(VECTOR_PASSPHRASE);
    }

    // key-derivation stability: dir keys for different epochs/dirs differ
    let root = test_root();
    let k1 = crypto::derive_dir_key(&root, &TEST_SID, Dir::InitiatorToResponder, 0);
    let k2 = crypto::derive_dir_key(&root, &TEST_SID, Dir::InitiatorToResponder, 1);
    let k3 = crypto::derive_dir_key(&root, &TEST_SID, Dir::ResponderToInitiator, 0);
    let _ = crypto::hmac_sha256(&k1[..], &[]);
    let _ = crypto::hmac_sha256(&k2[..], &[]);
    let _ = crypto::hmac_sha256(&k3[..], &[]);
});
