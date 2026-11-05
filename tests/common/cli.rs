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
    /// Send a signal to the receiver once progress passes this fraction.
    pub signal_receiver_at: Option<(f64, i32)>,
    /// Send a signal to the sender once progress passes this fraction:
    /// (fraction, signal number e.g. SIGUSR1=10).
    pub signal_sender_at: Option<(f64, i32)>,
    /// Second signal, sent 3 s after the first (e.g. SIGUSR2 resume).
    pub signal_sender_at2: Option<(f64, i32)>,
    /// Replace the whole sender command (e.g. `resume <sid> --send`).
    pub sender_cmd: Option<Vec<String>>,
    /// Replace the whole receiver command (e.g. `resume <sid>`).
    pub receiver_cmd: Option<Vec<String>>,
    /// Passphrase written to the SENDER stdin up-front (resume --send).
    pub sender_passphrase: Option<String>,
}

pub struct PairOutcome {
    pub sender: RunResult,
    pub receiver: RunResult,
    pub passphrase: String,
    pub sid: String,
}

pub fn run_transfer(paths: &[&str], out_dir: &str, opts: PairOpts) -> PairOutcome {
    let mut sender_cmd = Command::new(bin_path());
    if let Some(cmd) = &opts.sender_cmd {
        sender_cmd.args(cmd);
    } else {
        sender_cmd
            .arg("send")
            .args(paths)
            .arg("--json")
            .arg("--stun")
            .arg("none")
            .args(&opts.sender_args);
    }
    sender_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut receiver_cmd = Command::new(bin_path());
    if let Some(cmd) = &opts.receiver_cmd {
        receiver_cmd.args(cmd);
    } else {
        receiver_cmd
            .arg("receive")
            .arg("--out")
            .arg(out_dir)
            .arg("--json")
            .arg("--yes")
            .arg("--stun")
            .arg("none")
            .args(&opts.receiver_args);
    }
    receiver_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut sender = sender_cmd.spawn().expect("spawn sender");
    if let Some(pass) = &opts.sender_passphrase {
        use std::io::Write;
        if let Some(stdin) = sender.stdin.as_mut() {
            let _ = writeln!(stdin, "{pass}");
            let _ = stdin.flush();
        }
    }
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
    let signal_at = opts.signal_sender_at;
    let receiver_pid = receiver.id() as i32;
    let sender_pid = sender.id() as i32;
    let mut killed = false;
    let mut signaled = false;
    let sig_rx_at = opts.signal_receiver_at;
    let mut signaled_rx = false;
    let signal_at2 = opts.signal_sender_at2;

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
                        if let Some(done) = parsed.as_ref().unwrap()["done"].as_u64()
                            && let Some(total) = parsed.as_ref().unwrap()["total"].as_u64()
                            && total > 0
                        {
                            let frac = done as f64 / total as f64;
                            if let Some(limit) = kill_at
                                && !killed
                                && frac >= limit
                            {
                                killed = true;
                                unsafe {
                                    libc_kill(receiver_pid, 9);
                                }
                            }
                            if let Some((limit, sig)) = sig_rx_at
                                && !signaled_rx
                                && frac >= limit
                            {
                                signaled_rx = true;
                                unsafe {
                                    libc_kill(receiver_pid, sig);
                                }
                            }
                            if let Some((limit, sig)) = signal_at
                                && !signaled
                                && frac >= limit
                            {
                                signaled = true;
                                unsafe {
                                    libc_kill(sender_pid, sig);
                                }
                                // second signal fires on a timer (progress
                                // stops while paused)
                                if let Some((_, sig2)) = signal_at2 {
                                    let pid = sender_pid;
                                    thread::spawn(move || {
                                        thread::sleep(std::time::Duration::from_secs(3));
                                        unsafe {
                                            libc_kill(pid, sig2);
                                        }
                                    });
                                }
                            }
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

    // wait for both via blocking wait-threads (try_wait proved unreliable
    // here); as soon as one exits, close BOTH stdins so the peer's blob read
    // hits EOF and fails fast instead of hanging
    let (done_tx, done_rx) = mpsc::channel::<(bool, i32)>();
    {
        let tx = done_tx.clone();
        thread::spawn(move || {
            let code = sender.wait().ok().and_then(|st| st.code()).unwrap_or(-1);
            let _ = tx.send((false, code));
        });
    }
    {
        let tx = done_tx.clone();
        thread::spawn(move || {
            let code = receiver.wait().ok().and_then(|st| st.code()).unwrap_or(-1);
            let _ = tx.send((true, code));
        });
    }
    let mut scode: Option<i32> = None;
    let mut rcode: Option<i32> = None;
    while scode.is_none() || rcode.is_none() {
        let (is_receiver, code) = done_rx.recv().unwrap_or((true, -1));
        if is_receiver {
            rcode = Some(code);
        } else {
            scode = Some(code);
        }
        shared.close_all();
    }
    let (scode, rcode) = (scode.unwrap_or(-1), rcode.unwrap_or(-1));
    if std::env::var("FJ_E2E_DEBUG").is_ok() {
        eprintln!("[e2e] children exited: sender={scode} receiver={rcode}");
    }
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
#[cfg(target_os = "linux")]
unsafe fn libc_kill(pid: i32, sig: i32) {
    // direct syscall via std (no libc dependency in the test package)
    let r = std::process::Command::new("kill")
        .args([
            "-9".to_string().replace('9', &sig.to_string()),
            pid.to_string(),
        ])
        .status();
    let _ = r;
}

#[cfg(not(target_os = "linux"))]
unsafe fn libc_kill(pid: i32, sig: i32) {
    let _ = (pid, sig);
}

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
