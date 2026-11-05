//! Multi-process CLI e2e harness: wires `filejaunt send` and
//! `filejaunt receive` through pipes exactly like a human would (blobs +
//! passphrase out-of-band), draining both stdouts continuously.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;

/// Path to the freshly built `filejaunt` binary (workspace build happens
/// before any test runs; profile follows this test binary's profile).
pub fn bin_path() -> &'static str {
    if cfg!(debug_assertions) {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../target/debug/filejaunt")
    } else {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../target/release/filejaunt")
    }
}

pub const BIN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/debug/filejaunt");

pub struct RunResult {
    pub code: Option<i32>,
    pub stdout: Vec<String>,
    pub stderr: String,
}

impl RunResult {
    pub fn json_events(&self, ty: &str) -> Vec<serde_json::Value> {
        self.stdout
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["type"] == ty)
            .collect()
    }

    pub fn exit_code(&self) -> i32 {
        self.code.unwrap_or(-1)
    }
}

struct Shared {
    rx_stdin: Mutex<Option<ChildStdin>>,
    tx_stdin: Mutex<Option<ChildStdin>>,
}

impl Shared {
    /// Close both stdin pipes (peer reads get EOF).
    fn close_all(&self) {
        self.rx_stdin.lock().unwrap().take();
        self.tx_stdin.lock().unwrap().take();
    }

    fn write_to(&self, which: bool, line: &str) {
        let mut guard = if which {
            self.rx_stdin.lock().unwrap()
        } else {
            self.tx_stdin.lock().unwrap()
        };
        if let Some(stdin) = guard.as_mut() {
            let _ = writeln!(stdin, "{line}");
            let _ = stdin.flush();
        }
    }
}

#[derive(Default)]
pub struct PairOpts {
    pub sender_args: Vec<String>,
    pub receiver_args: Vec<String>,
    /// Tamper the blob-1 before it reaches the receiver (SDP substitution).
    pub tamper_blob1: Option<fn(&str) -> String>,
    /// Passphrase fed to the receiver (defaults to the real one).
    pub receiver_passphrase: Option<String>,
    /// Kill the receiver once progress passes this fraction (0..1), None=off.
    pub kill_receiver_at: Option<f64>,
}

pub struct PairOutcome {
    pub sender: RunResult,
    pub receiver: RunResult,
    pub passphrase: String,
    pub sid: String,
}

pub fn run_transfer(paths: &[&str], out_dir: &str, opts: PairOpts) -> PairOutcome {
    let mut sender_cmd = Command::new(bin_path());
    sender_cmd
        .arg("send")
        .args(paths)
        .arg("--json")
        .arg("--stun")
        .arg("none")
        .args(&opts.sender_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut receiver_cmd = Command::new(bin_path());
    receiver_cmd
        .arg("receive")
        .arg("--out")
        .arg(out_dir)
        .arg("--json")
        .arg("--yes")
        .arg("--stun")
        .arg("none")
        .args(&opts.receiver_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut sender = sender_cmd.spawn().expect("spawn sender");
    let mut receiver = receiver_cmd.spawn().expect("spawn receiver");
    let shared = Arc::new(Shared {
        rx_stdin: Mutex::new(receiver.stdin.take()),
        tx_stdin: Mutex::new(sender.stdin.take()),
    });

    type LineChan = (mpsc::SyncSender<(bool, String)>, Receiver<(bool, String)>);
    let (line_tx, line_rx): LineChan = mpsc::sync_channel(4096);
    let main_tx = line_tx.clone();

    // reader threads: (is_receiver, line)
    let spawn_reader = |child: &mut Child, is_receiver: bool, chan: bool| {
        let stdout = child.stdout.take().expect("stdout");
        let tx = line_tx.clone();
        thread::spawn(move || {
            let r = BufReader::new(stdout);
            for line in r.lines().map_while(Result::ok) {
                let _ = tx.send((is_receiver, line));
            }
            let _ = chan;
        });
    };
    spawn_reader(&mut receiver, true, true);
    spawn_reader(&mut sender, false, false);

    let mut sender_lines: Vec<String> = vec![];
    let mut receiver_lines: Vec<String> = vec![];
    let mut passphrase = String::new();
    let mut sid = String::new();
    let kill_at = opts.kill_receiver_at;
    let mut killed = false;

    // single routing loop
    let shared_router = shared.clone();
    let router = thread::spawn(move || {
        while let Ok((is_receiver, line)) = line_rx.recv() {
            let parsed = serde_json::from_str::<serde_json::Value>(&line).ok();
            let ty = parsed
                .as_ref()
                .and_then(|v| v["type"].as_str())
                .unwrap_or("");
            if std::env::var("FJ_E2E_DEBUG").is_ok() {
                eprintln!("[e2e] {} {ty}", if is_receiver { "RX" } else { "TX" });
            }
            if is_receiver {
                receiver_lines.push(line.clone());
                match ty {
                    "joined" => {
                        shared_router.write_to(false, &line);
                    }
                    "blob4" => shared_router.write_to(false, &line),
                    "progress" => {
                        if let Some(limit) = kill_at
                            && !killed
                            && let (Some(done), Some(total)) = (
                                parsed.as_ref().unwrap()["done"].as_u64(),
                                parsed.as_ref().unwrap()["total"].as_u64(),
                            )
                            && total > 0
                            && done as f64 / total as f64 >= limit
                        {
                            killed = true;
                        }
                    }
                    _ => {}
                }
            } else {
                sender_lines.push(line.clone());
                match ty {
                    "hello" => {
                        let v = parsed.unwrap();
                        passphrase = v["passphrase"].as_str().unwrap_or("").to_string();
                        sid = v["sid"].as_str().unwrap_or("").to_string();
                        let blob1 = v["blob1"].as_str().unwrap_or("").to_string();
                        let blob1 = match opts.tamper_blob1 {
                            Some(f) => f(&blob1),
                            None => blob1,
                        };
                        let hello = serde_json::json!({"type": "hello", "blob1": blob1});
                        shared_router.write_to(true, &hello.to_string());
                        let pass = opts
                            .receiver_passphrase
                            .clone()
                            .unwrap_or_else(|| passphrase.clone());
                        shared_router.write_to(true, &pass);
                    }
                    "blob3" => shared_router.write_to(true, &line),
                    _ => {}
                }
            }
        }
        (sender_lines, receiver_lines, passphrase, sid)
    });

    // wait for both; as soon as one exits, close BOTH stdins so the peer's
    // blob read hits EOF and fails fast instead of hanging
    let mut scode = None;
    let mut rcode = None;
    loop {
        if scode.is_none()
            && let Some(st) = sender.try_wait().unwrap()
        {
            scode = st.code();
            shared.close_all();
        }
        if rcode.is_none()
            && let Some(st) = receiver.try_wait().unwrap()
        {
            rcode = st.code();
            shared.close_all();
        }
        if scode.is_some() && rcode.is_some() {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
    if std::env::var("FJ_E2E_DEBUG").is_ok() {
        eprintln!("[e2e] children exited: sender={scode:?} receiver={rcode:?}");
    }
    let scode = scode.unwrap_or(-1);
    let rcode = rcode.unwrap_or(-1);
    drop(main_tx);
    drop(line_tx);
    let _ = killed;

    if std::env::var("FJ_E2E_DEBUG").is_ok() {
        eprintln!("[e2e] joining router");
    }
    let (sender_lines, receiver_lines, passphrase, sid) = router.join().unwrap();
    if std::env::var("FJ_E2E_DEBUG").is_ok() {
        eprintln!("[e2e] router joined, returning");
    }
    PairOutcome {
        sender: RunResult {
            code: Some(scode),
            stdout: sender_lines,
            stderr: String::new(),
        },
        receiver: RunResult {
            code: Some(rcode),
            stdout: receiver_lines,
            stderr: String::new(),
        },
        passphrase,
        sid,
    }
}

/// Read stderr of a finished child is not possible post-wait with piped
/// stderr; tests that need stderr assertions spawn their own processes.
pub fn sha256_file(path: &str) -> String {
    use sha2::Digest;
    let mut f = std::fs::File::open(path).unwrap();
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    use std::io::Read;
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    hex::encode(h.finalize())
}
