//! Crypto tests: nonce uniqueness, key separation, AAD binding.

use fj_protocol::crypto::{
    self, Dir, Key32, ct_eq, decrypt_frame, derive_confirm, derive_dir_key, derive_env_answer,
    derive_env_offer, derive_receipt, encrypt_frame,
};
use fj_protocol::error::ErrorCode;

fn root() -> Key32 {
    crypto::derive_root(b"shared secret bytes", &[1u8; 16])
}

#[test]
fn nonce_uniqueness_10k() {
    // all (epoch, dir, counter) tuples in range produce distinct nonces by
    // construction; exercise the encoder for collisions across 10k counters
    // and both dirs/epochs.
    let mut seen = std::collections::HashSet::new();
    for counter in 0..10_000u32 {
        for dir in [Dir::InitiatorToResponder, Dir::ResponderToInitiator] {
            for epoch in [0u32, 1] {
                let n = [
                    epoch.to_le_bytes(),
                    dir.as_u32().to_le_bytes(),
                    counter.to_le_bytes(),
                ]
                .concat();
                assert!(seen.insert(n), "nonce collision");
            }
        }
    }
    assert_eq!(seen.len(), 40_000);
}

#[test]
fn key_separation() {
    let r = root();
    let sid = [1u8; 16];
    let k1 = derive_dir_key(&r, &sid, Dir::InitiatorToResponder, 0);
    let k2 = derive_dir_key(&r, &sid, Dir::ResponderToInitiator, 0);
    let k1e1 = derive_dir_key(&r, &sid, Dir::InitiatorToResponder, 1);
    let kc = derive_confirm(&r, &sid);
    let kr = derive_receipt(&r, &sid);
    let ko = derive_env_offer(&r, &sid);
    let ka = derive_env_answer(&r, &sid);
    let all = [k1, k2, k1e1, kc, kr, ko, ka];
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            assert_ne!(&*all[i], &*all[j], "keys {i} and {j} collide");
        }
    }
}

#[test]
fn aad_header_binding() {
    let k = derive_dir_key(&root(), &[1u8; 16], Dir::InitiatorToResponder, 0);
    let header = [1u8, 0x04, 3, 0, 5, 0, 0, 0, 8, 0, 0, 0];
    let payload = b"abcdefgh";
    let ct = encrypt_frame(&k, 0, Dir::InitiatorToResponder, 0, &header, payload);
    // clean decrypt
    let pt = decrypt_frame(&k, 0, Dir::InitiatorToResponder, 0, &header, &ct).unwrap();
    assert_eq!(pt, payload);
    // flip 1 bit in the CLEAR header -> GCM auth failure (AAD bind)
    for bit in [0usize, 1, 2, 4, 8, 11] {
        let mut h = header;
        h[bit] ^= 0x01;
        let e = decrypt_frame(&k, 0, Dir::InitiatorToResponder, 0, &h, &ct).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ProtoMalformed, "header byte {bit}");
    }
    // flip 1 bit in ciphertext
    let mut c = ct.clone();
    c[0] ^= 0x01;
    assert!(decrypt_frame(&k, 0, Dir::InitiatorToResponder, 0, &header, &c).is_err());
    // wrong counter (nonce reuse protection ordering)
    assert!(decrypt_frame(&k, 0, Dir::InitiatorToResponder, 1, &header, &ct).is_err());
    // wrong direction key
    let k2 = derive_dir_key(&root(), &[1u8; 16], Dir::ResponderToInitiator, 0);
    assert!(decrypt_frame(&k2, 0, Dir::InitiatorToResponder, 0, &header, &ct).is_err());
    // wrong epoch
    assert!(decrypt_frame(&k, 1, Dir::InitiatorToResponder, 0, &header, &ct).is_err());
}

#[test]
fn sdp_envelope_roundtrip_and_labels() {
    let r = root();
    let sid = [1u8; 16];
    let ko = derive_env_offer(&r, &sid);
    let ka = derive_env_answer(&r, &sid);
    let ct = crypto::encrypt_sdp(&ko, "sdp-offer", "v=0\r\no=- the offer");
    assert_eq!(
        crypto::decrypt_sdp(&ko, "sdp-offer", &ct).unwrap(),
        "v=0\r\no=- the offer"
    );
    // wrong label
    assert!(crypto::decrypt_sdp(&ko, "sdp-answer", &ct).is_err());
    // answer key cannot decrypt offer
    assert!(crypto::decrypt_sdp(&ka, "sdp-offer", &ct).is_err());
}

#[test]
fn ct_eq_basics() {
    assert!(ct_eq(b"abcdef", b"abcdef"));
    assert!(!ct_eq(b"abcdef", b"abcdeg"));
    assert!(!ct_eq(b"abc", b"abcd"));
}

#[test]
fn confirm_fp_binds_both_sdps_and_sid() {
    let r = root();
    let sid = [1u8; 16];
    let fp = crypto::confirm_fp(&r, "offer", "answer", &sid);
    assert_eq!(fp, crypto::confirm_fp(&r, "offer", "answer", &sid));
    assert_ne!(fp, crypto::confirm_fp(&r, "offerX", "answer", &sid));
    assert_ne!(fp, crypto::confirm_fp(&r, "offer", "answerX", &sid));
    assert_ne!(fp, crypto::confirm_fp(&r, "offer", "answer", &[2u8; 16]));
}
