//! e2e: gzip auto policy (CSV compresses on the wire; random data does not).

use fj_e2e::cli::{PairOpts, run_transfer, sha256_file};

fn last_wire_bytes(outcome: &fj_e2e::cli::RunResult) -> u64 {
    outcome
        .json_events("progress")
        .last()
        .and_then(|p| p["wire_bytes"].as_u64())
        .expect("progress events")
}

#[test]
#[ignore]
fn cli_gzip_csv_compresses() {
    let out = "/tmp/fj-e2e-gzip-csv";
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).unwrap();
    let size = std::fs::metadata("../fixtures/compressible.csv")
        .unwrap()
        .len();
    let outcome = run_transfer(&["../fixtures/compressible.csv"], out, PairOpts::default());
    assert_eq!(outcome.sender.exit_code(), 0);
    assert_eq!(outcome.receiver.exit_code(), 0);
    let wire = last_wire_bytes(&outcome.receiver);
    assert!(
        (wire as f64) < 0.6 * size as f64,
        "CSV must compress on the wire: wire={wire} size={size}"
    );
    assert_eq!(
        sha256_file(&format!("{out}/compressible.csv")),
        sha256_file("../fixtures/compressible.csv")
    );
}

#[test]
#[ignore]
fn cli_gzip_random_stays_raw() {
    let out = "/tmp/fj-e2e-gzip-random";
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).unwrap();
    let size = std::fs::metadata("../fixtures/random.bin").unwrap().len();
    let outcome = run_transfer(&["../fixtures/random.bin"], out, PairOpts::default());
    assert_eq!(outcome.sender.exit_code(), 0);
    assert_eq!(outcome.receiver.exit_code(), 0);
    let wire = last_wire_bytes(&outcome.receiver);
    assert!(
        wire >= size && (wire as f64) < 1.05 * size as f64,
        "random data must stay ~raw: wire={wire} size={size}"
    );
}
