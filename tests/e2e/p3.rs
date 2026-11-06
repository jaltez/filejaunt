//! P3 e2e: resume (epoch+1), pause/resume via SIGUSR1/2, fan-out,
//! multi-channel, doctor offline, and key-leak scan.

use fj_e2e::cli::{PairOpts, bin_path, run_transfer, sha256_file};
use std::process::Command;

fn fresh_dir(p: &str) {
    let _ = std::fs::remove_dir_all(p);
    std::fs::create_dir_all(p).unwrap();
}

#[test]
#[ignore]
fn cli_doctor_offline() {
    let out = Command::new(fj_e2e::cli::bin_path())
        .args(["doctor", "--stun", "none"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "exit 0, got {}",
        out.status.code().unwrap_or(-1)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("UNKNOWN"),
        "no STUN -> UNKNOWN class: {stdout}"
    );
}

#[test]
#[ignore]
fn cli_pause_resume_signals() {
    let out = "/tmp/fj-e2e-pause";
    fresh_dir(out);
    // SIGUSR1 (pause) at 10% of a 50 MiB transfer, SIGUSR2 (resume) at 25%
    let outcome = run_transfer(
        &["../fixtures/big.bin"],
        out,
        PairOpts {
            signal_sender_at: Some((0.10, 10)),
            signal_sender_at2: Some((0.25, 12)),
            ..Default::default()
        },
    );
    assert_eq!(
        outcome.sender.exit_code(),
        0,
        "completes after pause+resume"
    );
    assert_eq!(outcome.receiver.exit_code(), 0);
    assert_eq!(
        outcome.sender.json_events("paused").len(),
        1,
        "paused event"
    );
    assert_eq!(
        outcome.sender.json_events("resumed").len(),
        1,
        "resumed event"
    );
    assert_eq!(
        sha256_file(&format!("{out}/big.bin")),
        sha256_file("../fixtures/big.bin")
    );
}

#[test]
#[ignore]
fn cli_channels_4() {
    let out = "/tmp/fj-e2e-channels";
    fresh_dir(out);
    // 100 MiB random file generated on the fly
    let big = "/tmp/fj-e2e-100mib.bin";
    if !std::path::Path::new(big).exists() {
        let f = std::fs::File::create(big).unwrap();
        let mut cmd = Command::new("head")
            .args(["-c", "104857600", "/dev/urandom"])
            .stdout(f)
            .spawn()
            .unwrap();
        cmd.wait().unwrap();
    }
    let outcome = run_transfer(
        &[big],
        out,
        PairOpts {
            sender_args: vec!["--channels".into(), "4".into()],
            ..Default::default()
        },
    );
    assert_eq!(outcome.sender.exit_code(), 0, "sender with 4 channels");
    assert_eq!(outcome.receiver.exit_code(), 0, "receiver with 4 channels");
    assert_eq!(
        sha256_file(&format!("{out}/fj-e2e-100mib.bin")),
        sha256_file(big)
    );
}

#[test]
#[ignore]
fn cli_resume_after_kill() {
    let out = "/tmp/fj-e2e-resume";
    fresh_dir(out);

    // phase 1: kill the receiver at 30%; the sender dies on connection loss
    // with its state saved
    let phase1 = run_transfer(
        &["../fixtures/big.bin"],
        out,
        PairOpts {
            kill_receiver_at: Some(0.30),
            ..Default::default()
        },
    );
    assert!(phase1.receiver.exit_code() != 0, "receiver killed");
    assert!(phase1.sender.exit_code() != 0, "sender loses its peer");

    // phase 2: resume both sides (epoch+1, same sid + passphrase)
    let sid = phase1.sid.clone();
    let pass = phase1.passphrase.clone();
    let sender_cmd = vec![
        "resume".to_string(),
        sid.clone(),
        "--send".to_string(),
        "--json".to_string(),
        "--stun".to_string(),
        "none".to_string(),
    ];
    let receiver_cmd = vec![
        "resume".to_string(),
        sid.clone(),
        "--out".to_string(),
        out.to_string(),
        "--json".to_string(),
        "--yes".to_string(),
        "--stun".to_string(),
        "none".to_string(),
    ];
    let phase2 = run_transfer(
        &[],
        out,
        PairOpts {
            sender_cmd: Some(sender_cmd),
            receiver_cmd: Some(receiver_cmd),
            sender_passphrase: Some(pass.clone()),
            receiver_passphrase: Some(pass),
            ..Default::default()
        },
    );
    assert_eq!(phase2.sender.exit_code(), 0, "resume sender completes");
    assert_eq!(phase2.receiver.exit_code(), 0, "resume receiver completes");
    assert_eq!(
        sha256_file(&format!("{out}/big.bin")),
        sha256_file("../fixtures/big.bin"),
        "file identical after resume"
    );
    // resume evidence: the receiver saw resumed progress (BITMAP round-trip)
    let resumed_progress = phase2
        .receiver
        .json_events("progress")
        .into_iter()
        .any(|p| p["resumed"] == serde_json::Value::Bool(true));
    assert!(resumed_progress, "progress with resumed=true after resume");
}

#[test]
#[ignore]
fn cli_no_key_material_in_outputs() {
    let out = "/tmp/fj-e2e-keys";
    fresh_dir(out);
    let outcome = run_transfer(&["../fixtures/random.bin"], out, PairOpts::default());
    assert_eq!(outcome.sender.exit_code(), 0);
    // allowed 64-hex strings: the file sha256 (events + receipts)
    let file_sha = sha256_file("../fixtures/random.bin");
    let allowed: Vec<String> = vec![file_sha.clone()];
    let hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    for line in outcome
        .sender
        .stdout
        .iter()
        .chain(outcome.receiver.stdout.iter())
    {
        for word in line.split(|c: char| !c.is_ascii_alphanumeric()) {
            if hex64(word) && !allowed.iter().any(|a| a == word) {
                panic!("unexpected 64-hex token in output (potential key leak): {word}");
            }
        }
    }
}

#[test]
#[ignore]
fn cli_fanout_two_receivers() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Stdio};
    use std::sync::{Arc, Mutex};
    use std::thread;

    let out1 = "/tmp/fj-e2e-fanout-1";
    let out2 = "/tmp/fj-e2e-fanout-2";
    fresh_dir(out1);
    fresh_dir(out2);

    let bin = bin_path();
    let sender_bin = bin.clone();
    let mut sender = Command::new(sender_bin)
        .args([
            "send",
            "../fixtures/random.bin",
            "--json",
            "--stun",
            "none",
            "--receivers",
            "2",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mk = |out: &str| {
        let b = bin.clone();
        Command::new(b)
            .args(["receive", "--out", out, "--json", "--yes", "--stun", "none"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let mut receivers: Vec<Child> = vec![mk(out1), mk(out2)];

    let sender_stdin = Arc::new(Mutex::new(sender.stdin.take().unwrap()));
    let mut rx_stores: Vec<Vec<String>> = vec![vec![], vec![]];

    // per-receiver pump threads: forward joined/blob4 to the sender, record the rest
    let mut handles = vec![];
    for (i, r) in receivers.iter_mut().enumerate() {
        let stdout = r.stdout.take().unwrap();
        let stdin = Arc::new(Mutex::new(r.stdin.take().unwrap()));
        let sender_stdin = sender_stdin.clone();
        let store = Arc::new(Mutex::new(std::mem::take(&mut rx_stores[i])));
        handles.push((
            stdin,
            thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let t = line.clone();
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t)
                                && matches!(v["type"].as_str(), Some("joined") | Some("blob4"))
                            {
                                let _ = writeln!(sender_stdin.lock().unwrap(), "{}", t.trim());
                                let _ = sender_stdin.lock().unwrap().flush();
                            } else {
                                store.lock().unwrap().push(t.trim().to_string());
                            }
                        }
                    }
                }
            }),
        ));
    }

    // main: read sender stdout; route the two hello events to the receivers
    let sender_stdout = sender.stdout.take().unwrap();
    let mut reader = BufReader::new(sender_stdout);
    let mut line = String::new();
    let mut hello_no = 0usize;
    let mut sender_lines: Vec<String> = vec![];
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let t = line.trim().to_string();
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t)
                    && v["type"].as_str() == Some("hello")
                {
                    hello_no += 1;
                    let idx = hello_no - 1;
                    let hello = serde_json::json!({"type": "hello", "blob1": v["blob1"]});
                    let stdin = handles[idx].0.clone();
                    {
                        let mut g = stdin.lock().unwrap();
                        let _ = writeln!(g, "{hello}");
                        let _ = writeln!(g, "{}", v["passphrase"].as_str().unwrap_or(""));
                        let _ = g.flush();
                    }
                } else {
                    sender_lines.push(t);
                }
            }
        }
    }

    let scode = sender.wait().unwrap().code().unwrap_or(-1);
    let mut rcodes = vec![];
    for r in receivers.iter_mut() {
        rcodes.push(r.wait().unwrap().code().unwrap_or(-1));
    }
    assert_eq!(scode, 0, "fan-out sender exit 0");
    assert!(
        rcodes.iter().all(|c| *c == 0),
        "both receivers exit 0: {rcodes:?}"
    );

    // both receivers hold the identical verified file
    let sha = sha256_file("../fixtures/random.bin");
    for (out, i) in [(out1, 0usize), (out2, 1)] {
        assert_eq!(
            sha256_file(&format!("{out}/random.bin")),
            sha,
            "receiver {i} file"
        );
    }
    let _ = handles; // receiver stores recorded inside threads; files prove completion
}

#[test]
#[ignore = "networked: probes public STUN"]
fn cli_doctor_public() {
    let out = Command::new(fj_e2e::cli::bin_path())
        .args(["doctor", "--stun", "public"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        ["DIRECT", "CONE", "SYMMETRIC", "UDP-BLOCKED"]
            .iter()
            .any(|c| stdout.contains(c)),
        "some class reported: {stdout}"
    );
}

#[test]
#[ignore]
fn cli_private_transfer() {
    let out = "/tmp/fj-e2e-private";
    fresh_dir(out);
    let outcome = run_transfer(
        &["../fixtures/random.bin"],
        out,
        PairOpts {
            sender_args: vec!["--private".into()],
            ..Default::default()
        },
    );
    assert_eq!(outcome.sender.exit_code(), 0, "p3 sender");
    assert_eq!(outcome.receiver.exit_code(), 0, "p3 receiver");
    assert_eq!(
        sha256_file(&format!("{out}/random.bin")),
        sha256_file("../fixtures/random.bin")
    );
    assert!(
        outcome.receiver.json_events("fileDone")[0]["verified"] == serde_json::Value::Bool(true)
    );
}

#[test]
#[ignore]
fn cli_empty_file() {
    let out = "/tmp/fj-e2e-empty";
    fresh_dir(out);
    let empty = "/tmp/fj-e2e-empty-src.dat";
    std::fs::write(empty, b"").unwrap();
    let outcome = run_transfer(&[empty], out, PairOpts::default());
    assert_eq!(outcome.sender.exit_code(), 0);
    assert_eq!(outcome.receiver.exit_code(), 0);
    let landed = format!("{out}/fj-e2e-empty-src.dat");
    assert_eq!(
        std::fs::metadata(&landed).unwrap().len(),
        0,
        "empty file created"
    );
    assert_eq!(
        outcome.receiver.json_events("fileDone")[0]["verified"],
        serde_json::Value::Bool(true)
    );
}

#[test]
#[ignore]
fn cli_cancel_sigint() {
    let out = "/tmp/fj-e2e-cancel";
    fresh_dir(out);
    // SIGINT the receiver mid-transfer: it cancels cleanly (exit 0) and the
    // sender sees PEER_CANCEL (exit 1 with a structured error event).
    let outcome = run_transfer(
        &["../fixtures/big.bin"],
        out,
        PairOpts {
            signal_receiver_at: Some((0.10, 2)),
            ..Default::default()
        },
    );
    assert_eq!(outcome.receiver.exit_code(), 0, "own cancel is clean");
    assert_eq!(outcome.sender.exit_code(), 1, "sender PEER_CANCEL exit 1");
    let errs = outcome.sender.json_events("error");
    assert!(
        errs.iter().any(|e| e["code"] == "PEER_CANCEL"),
        "sender got PEER_CANCEL: {errs:?}"
    );
    // a fresh receive from scratch still works afterwards
    let out2 = "/tmp/fj-e2e-cancel2";
    fresh_dir(out2);
    let again = run_transfer(&["../fixtures/random.bin"], out2, PairOpts::default());
    assert_eq!(again.sender.exit_code(), 0);
    assert_eq!(again.receiver.exit_code(), 0);
}

#[test]
fn cli_relay_pairing() {
    relay_transfer(false);
}

#[test]
fn cli_relay_private_pairing() {
    // p3 (all SDP encrypted) over the signaling relay: blob-3/blob-4 must
    // flow through the relay room on BOTH sides, not stdin/stdout.
    relay_transfer(true);
}

fn relay_transfer(private3: bool) {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU16, Ordering};

    // Each relay test binds its own port: the harness runs tests in parallel
    // and a hardcoded port would make sibling runs fail on AddrInUse.
    static NEXT_PORT: AtomicU16 = AtomicU16::new(18099);
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let port = port.to_string();

    let out = "/tmp/fj-e2e-relay";
    fresh_dir(out);
    let sender_bin = fj_e2e::cli::bin_path();
    let relay_bin = fj_e2e::cli::relay_bin_path();
    // Drop guard: kill the relay even if an assertion panics early, so the
    // hardcoded port never stays bound by an orphan process.
    struct RelayGuard(std::process::Child);
    impl Drop for RelayGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let relay = RelayGuard(
        Command::new(&relay_bin)
            .args([&port])
            .spawn()
            .expect("spawn relay"),
    );
    std::thread::sleep(std::time::Duration::from_millis(300));

    let mut sender_args = vec![
        "send".to_string(),
        "../fixtures/random.bin".to_string(),
        "--json".to_string(),
        "--stun".to_string(),
        "none".to_string(),
        "--relay".to_string(),
        format!("ws://127.0.0.1:{port}/ws"),
    ];
    if private3 {
        sender_args.push("--private".to_string());
    }
    let mut sender = Command::new(sender_bin.clone())
        .args(&sender_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sender");
    let mut receiver = Command::new(sender_bin)
        .args([
            "receive",
            "--out",
            out,
            "--json",
            "--yes",
            "--stun",
            "none",
            "--relay",
            &format!("ws://127.0.0.1:{port}/ws"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn receiver");

    let mut hello_line = String::new();
    {
        let mut r = std::io::BufReader::new(sender.stdout.take().unwrap());
        while hello_line.is_empty() || !hello_line.contains("hello") {
            hello_line.clear();
            let n = r.read_line(&mut hello_line).unwrap();
            if n == 0 {
                panic!("sender stdout closed before hello: is the relay up?");
            }
        }
    }
    let hello: serde_json::Value = serde_json::from_str(hello_line.trim()).unwrap();
    let code = hello["code"].as_str().unwrap().to_string();
    assert!(
        code.starts_with("fj-"),
        "combined pairing code emitted: {code}"
    );

    {
        // relay mode: the receiver only needs this single code
        let mut w = receiver.stdin.take().unwrap();
        writeln!(w, "{code}").unwrap();
        w.flush().unwrap();
    }

    let serr = sender.stderr.take().unwrap();
    let rerr = receiver.stderr.take().unwrap();
    let serr_t = std::thread::spawn(move || {
        let mut buf = String::new();
        for line in std::io::BufRead::lines(std::io::BufReader::new(serr)) {
            buf.push_str(&line.unwrap_or_default());
            buf.push('\n');
        }
        buf
    });
    let rerr_t = std::thread::spawn(move || {
        let mut buf = String::new();
        for line in std::io::BufRead::lines(std::io::BufReader::new(rerr)) {
            buf.push_str(&line.unwrap_or_default());
            buf.push('\n');
        }
        buf
    });

    let scode = sender.wait().unwrap();
    let rcode = receiver.wait().unwrap();
    let _ = serr_t;
    let rerr_out = rerr_t.join().unwrap_or_default();
    let sc = scode.code().unwrap_or(-1);
    let rc = rcode.code().unwrap_or(-1);
    if sc != 0 || rc != 0 {
        panic!(
            "relay transfer failed (private3={private3}): sender={sc} receiver={rc}\n--- receiver stderr ---\n{rerr_out}"
        );
    }
    drop(relay);
    assert_eq!(
        sha256_file(&format!("{out}/random.bin")),
        sha256_file("../fixtures/random.bin"),
        "bytes identical via relay"
    );
}
