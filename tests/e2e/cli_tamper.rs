//! e2e: tampered blob-1 (SDP substitution) fails BOTH sides with
//! SEC_HELLO_MISMATCH; wrong passphrase fails the sender with
//! SEC_PAKE_FAILED.

use fj_e2e::cli::{PairOpts, run_transfer};

/// Flip one character in the (clear) SDP carried inside blob-1: an attacker
/// who controls the blob channel substitutes the offer. Both sides must
/// detect the fingerprint mismatch at HELO.
fn substitute_sdp(blob1: &str) -> String {
    use std::io::Read;
    use std::io::Write;
    let body = blob1.strip_prefix("FJ1.").unwrap();
    let gz = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .unwrap()
    };
    let mut json = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut json)
        .unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let sdp = v["sdp"].as_str().unwrap().to_string();
    // unknown attribute: byte-different but structurally valid SDP
    let flipped = format!("{sdp}a=x-filejaunt-tampered\r\n");
    v["sdp"] = serde_json::Value::String(flipped);
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(v.to_string().as_bytes()).unwrap();
    let gz = enc.finish().unwrap();
    use base64::Engine;
    format!(
        "FJ1.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(gz)
    )
}

#[test]
#[ignore]
fn cli_tamper() {
    let out = "/tmp/fj-e2e-tamper";
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).unwrap();

    let outcome = run_transfer(
        &["../fixtures/random.bin"],
        out,
        PairOpts {
            tamper_blob1: Some(substitute_sdp),
            ..Default::default()
        },
    );
    // both sides fail with a security error (exit 3)
    assert_eq!(outcome.sender.exit_code(), 3, "sender must exit 3 (SEC_*)");
    assert_eq!(
        outcome.receiver.exit_code(),
        3,
        "receiver must exit 3 (SEC_*)"
    );
    // nothing transferred
    assert!(outcome.receiver.json_events("fileDone").is_empty());
    assert!(!std::path::Path::new(&format!("{out}/random.bin")).exists());
}

#[test]
#[ignore]
fn cli_wrong_passphrase() {
    let out = "/tmp/fj-e2e-wrongpass";
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).unwrap();

    let outcome = run_transfer(
        &["../fixtures/random.bin"],
        out,
        PairOpts {
            receiver_passphrase: Some("totally-wrong-passphrase-here".into()),
            ..Default::default()
        },
    );
    // the receiver typed the wrong passphrase: its blob-2 answer cannot be
    // decrypted by the sender -> SEC_PAKE_FAILED (exit 3)
    assert_eq!(outcome.sender.exit_code(), 3);
    assert!(outcome.receiver.exit_code() != 0);
    assert!(outcome.receiver.json_events("fileDone").is_empty());
}
