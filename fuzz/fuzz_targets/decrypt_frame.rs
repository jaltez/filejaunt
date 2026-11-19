#![no_main]
//! Fuzz the AEAD/MAC core with a fixed TEST-ONLY key (vector material from
//! tests/vectors/protocol.json). Goal: panics in the authentication and
//! derivation paths, never a logical bypass (GCM forgery is infeasible; the
//! target verifies error handling on tampered/truncated ciphertexts).
//!
//! Layout: data[0] -> epoch seed, data[1] -> direction, data[2..6] -> epoch,
//! data[6..10] -> counter, data[10..22] -> AAD header, rest -> ciphertext.
use fj_protocol::crypto::{self, Dir};
use fj_protocol_fuzz::{test_root, Rd, TEST_SID};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = Rd::new(data);
    let dir = if r.u8() & 1 == 0 {
        Dir::InitiatorToResponder
    } else {
        Dir::ResponderToInitiator
    };
    let epoch = r.u32();
    let counter = r.u32();

    let root = test_root();
    let key = crypto::derive_dir_key(&root, &TEST_SID, dir, epoch);

    // tampered / truncated ciphertext: must Err, never panic
    let mut header = [0u8; 12];
    let aad = r.bytes(12);
    header[..aad.len()].copy_from_slice(aad);
    let ct = r.bytes(usize::MAX).to_vec();
    let _ = crypto::decrypt_frame(&key, epoch, dir, counter, &header, &ct);

    // roundtrip: encrypt then decrypt the same attacker-chosen "plaintext"
    // (also covers the empty-payload edge when ct is empty)
    let sealed = crypto::encrypt_frame(&key, epoch, dir, counter, &header, &ct);
    // nonce sensitivity: same key/counter, flipped AAD bit must fail auth
    if sealed.len() >= 16 {
        let mut h2 = header;
        h2[0] ^= 0x01;
        let flipped = crypto::decrypt_frame(&key, epoch, dir, counter, &h2, &sealed);
        assert!(flipped.is_err(), "GCM must reject a modified AAD header");
    }

    // SDP envelope AEAD (zero-nonce path, D1 subkeys)
    let k_offer = crypto::derive_env_offer(&root, &TEST_SID);
    let k_answer = crypto::derive_env_answer(&root, &TEST_SID);
    let label = if r.u8() & 1 == 0 { "sdp-offer" } else { "sdp-answer" };
    let _ = crypto::decrypt_sdp(&k_offer, label, &ct);
    let sdp = String::from_utf8_lossy(&ct).into_owned();
    let enc = crypto::encrypt_sdp(&k_offer, label, &sdp);
    if let Ok(dec) = crypto::decrypt_sdp(&k_offer, label, &enc) {
        assert_eq!(dec, sdp, "sdp roundtrip must be lossless");
    }
    // cross-subkey: answer key must not open an offer-sealed blob (D1)
    assert!(
        crypto::decrypt_sdp(&k_answer, "sdp-offer", &enc).is_err(),
        "K_env_o and K_env_a must be distinct keys"
    );

    // MAC / fingerprint helpers
    let k_confirm = crypto::derive_confirm(&root, &TEST_SID);
    let _ = crypto::confirm_fp(&k_confirm, &sdp, &sdp, &TEST_SID);
    let k_receipt = crypto::derive_receipt(&root, &TEST_SID);
    let mac = crypto::hmac_sha256(&k_receipt[..], &ct);
    assert!(crypto::ct_eq(&mac, &mac));
    assert!(!crypto::ct_eq(&mac, b""));
    let _ = crypto::sha256(&[&ct, &mac, &header]);
});
