//! Envelope tests: roundtrip, malformed inputs, p2/p3 flows deriving equal
//! K_root on both sides.

mod common;

use common::{ANSWER, OFFER};
use fj_protocol::ErrorCode;
use fj_protocol::envelope::{Envelope, Envelope1, Envelope3};
use fj_protocol::pake::AttemptLimiter;
use fj_protocol::session::{Session, SessionOpts};

#[test]
fn roundtrip_env1_p2() {
    let e = Envelope1 {
        v: 1,
        sid: "ab".repeat(16),
        pake: "cGFraw==".into(),
        sdp: Some("v=0 offer".into()),
        ep: 0,
        mode: "p2".into(),
        ch: 1,
    };
    let raw = fj_protocol::envelope::serialize(&e).unwrap();
    assert!(raw.starts_with("FJ1."));
    match Envelope::parse(&raw).unwrap() {
        Envelope::One(back) => assert_eq!(back, e),
        _ => panic!("wrong shape"),
    }
}

#[test]
fn roundtrip_env3() {
    let e = Envelope3 {
        v: 1,
        sdpe: "c2RwZQ==".into(),
    };
    let raw = fj_protocol::envelope::serialize(&e).unwrap();
    match Envelope::parse(&raw).unwrap() {
        Envelope::Three(back) => assert_eq!(back, e),
        _ => panic!("wrong shape"),
    }
}

#[test]
fn malformed_inputs() {
    // no prefix
    assert!(Envelope::parse("XXXX.YQ").is_err());
    // garbage b64
    assert!(Envelope::parse("FJ1.!!!").is_err());
    // valid b64, invalid gzip
    use base64::Engine;
    let not_gzip = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not gzip at all");
    assert!(Envelope::parse(&format!("FJ1.{not_gzip}")).is_err());
    // valid gzip, broken JSON
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    enc.write_all(b"{broken").unwrap();
    let gz = enc.finish().unwrap();
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&gz);
    let e = Envelope::parse(&format!("FJ1.{b}")).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProtoMalformed);
    // decompression bomb: > 64 KiB
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&vec![0u8; 70_000]).unwrap();
    let gz = enc.finish().unwrap();
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&gz);
    assert!(Envelope::parse(&format!("FJ1.{b}")).is_err());
}

fn opts_p2() -> SessionOpts {
    SessionOpts {
        words: 6,
        private3: false,
        chunk_size: 16384,
        channels: 1,
        sid: Some([3u8; 16]),
        offer_sdp: OFFER.into(),
    }
}

fn opts_p3() -> SessionOpts {
    SessionOpts {
        words: 6,
        private3: true,
        chunk_size: 16384,
        channels: 1,
        sid: Some([3u8; 16]),
        offer_sdp: OFFER.into(),
    }
}

#[test]
fn p2_flow_same_kroot() {
    let mut limiter = AttemptLimiter::new();
    let (mut ini, pass, blob1) = Session::initiator_new(opts_p2()).unwrap();
    let (rsp, _blob2) = Session::responder_join(&blob1, &pass, ANSWER, &mut limiter).unwrap();
    ini.initiator_accept(&_blob2).unwrap();
    assert_eq!(ini.k_root_hex_for_test(), rsp.k_root_hex_for_test());
}

#[test]
fn p3_flow_same_kroot_and_private_sdp() {
    let mut limiter = AttemptLimiter::new();
    let (mut ini, pass, blob1) = Session::initiator_new(opts_p3()).unwrap();
    assert!(!blob1.contains("offer"), "p3 blob1 carries no SDP");
    let (mut rsp, _blob2) = Session::responder_join(&blob1, &pass, "", &mut limiter).unwrap();
    ini.initiator_accept(&_blob2).unwrap();
    let blob3 = ini.initiator_private_blob3().unwrap();
    assert!(!blob3.contains("v=0"), "blob3 is encrypted");
    let offer = rsp.responder_private_offer(&blob3, &mut limiter).unwrap();
    assert_eq!(offer, OFFER);
    let blob4 = rsp.responder_private_blob4(ANSWER).unwrap();
    ini.initiator_private_final(&blob4).unwrap();
    assert_eq!(ini.k_root_hex_for_test(), rsp.k_root_hex_for_test());
}

#[test]
fn p3_wrong_passphrase_detected() {
    let mut limiter = AttemptLimiter::new();
    let (mut ini, _pass, blob1) = Session::initiator_new(opts_p3()).unwrap();
    let (mut rsp, _blob2) =
        Session::responder_join(&blob1, "wrong-passphrase-here", "", &mut limiter).unwrap();
    ini.initiator_accept(&_blob2).unwrap();
    let blob3 = ini.initiator_private_blob3().unwrap();
    let e = rsp
        .responder_private_offer(&blob3, &mut limiter)
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::SecPakeFailed);
    // limiter sees the failure
    assert_eq!(limiter.failures(&[3u8; 16]), 1);
}

#[test]
fn attempt_limit() {
    let mut limiter = AttemptLimiter::new();
    let sid = [7u8; 16];
    assert!(limiter.record_failure(&sid).is_ok());
    assert!(limiter.record_failure(&sid).is_ok());
    let e = limiter.record_failure(&sid).unwrap_err();
    assert_eq!(e.code(), ErrorCode::SecAttemptLimit);
    limiter.clear(&sid);
    assert!(limiter.record_failure(&sid).is_ok());
}

#[test]
fn tampered_envelope_fails() {
    // flip one byte in the middle of blob1's base64 body
    let mut limiter = AttemptLimiter::new();
    let (_ini, pass, blob1) = Session::initiator_new(opts_p2()).unwrap();
    let mut chars: Vec<u8> = blob1.bytes().collect();
    let mid = chars.len() / 2;
    chars[mid] = match chars[mid] {
        b'A' => b'B',
        _ => b'A',
    };
    let tampered = String::from_utf8(chars).unwrap();
    let r = Session::responder_join(&tampered, &pass, ANSWER, &mut limiter);
    assert!(r.is_err());
}
