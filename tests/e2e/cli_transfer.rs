//! e2e: full CLI transfer over loopback host candidates (real DTLS/SCTP).

use fj_e2e::cli::{PairOpts, bin_path, run_transfer, sha256_file};

#[test]
#[ignore] // e2e: run with `cargo test --test cli_transfer -- --ignored`
fn cli_transfer_50mib() {
    let out = "/tmp/fj-e2e-transfer";
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).unwrap();

    let outcome = run_transfer(&["../fixtures/big.bin"], out, PairOpts::default());
    assert_eq!(outcome.sender.exit_code(), 0, "sender exit");
    assert_eq!(outcome.receiver.exit_code(), 0, "receiver exit");

    // byte-identical file
    assert_eq!(
        sha256_file(&format!("{out}/big.bin")),
        sha256_file("../fixtures/big.bin"),
        "sha256 must match"
    );

    // receiver verified the file
    let done = outcome.receiver.json_events("fileDone");
    assert_eq!(done.len(), 1);
    assert_eq!(done[0]["verified"], serde_json::Value::Bool(true));
    assert_eq!(
        done[0]["sha256"].as_str().unwrap(),
        sha256_file("../fixtures/big.bin")
    );

    // path event: direct, host candidates only (no STUN)
    let path = outcome.receiver.json_events("path");
    assert_eq!(path.len(), 1);
    assert_eq!(path[0]["kind"], "direct");

    // receipt exists and verifies with the passphrase
    let receipts = std::fs::read_dir(
        std::env::var("HOME")
            .map(|h| format!("{h}/.local/share/filejaunt/receipts"))
            .unwrap(),
    )
    .unwrap()
    .filter_map(|e| e.ok())
    .map(|e| e.path())
    .filter(|p| {
        let t = p.metadata().ok().and_then(|m| m.modified().ok());
        matches!(t, Some(t) if t.elapsed().map(|e| e.as_secs() < 120).unwrap_or(false))
    })
    .collect::<Vec<_>>();
    assert!(!receipts.is_empty(), "a fresh receipt was saved");
    let v = std::process::Command::new(fj_e2e::cli::BIN)
        .args(["verify", "--receipt"])
        .arg(receipts[0].to_str().unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin
                .take()
                .unwrap()
                .write_all(outcome.passphrase.as_bytes())
                .ok();
            c.wait_with_output()
        })
        .unwrap();
    assert!(v.status.success(), "verify VALID exit 0");
    assert!(String::from_utf8_lossy(&v.stdout).contains("VALID"));
}
