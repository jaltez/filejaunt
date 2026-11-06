//! Output helpers: human progress lines (stderr) and NDJSON events (stdout).

use std::io::Write;

use fj_protocol::ErrorCode;

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Human,
    Json,
}

pub struct Out {
    pub mode: Mode,
    pub quiet: bool,
}

pub fn mib_pub(bytes: u64) -> String {
    mib(bytes)
}

fn mib(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

impl Out {
    pub fn json(&self, value: serde_json::Value) {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{value}");
        let _ = stdout.flush();
    }

    pub fn stderr_line(&self, msg: &str) {
        if self.quiet {
            return;
        }
        if self.mode == Mode::Human {
            eprintln!("{msg}");
        }
    }

    /// One updating progress line per file (human mode, stderr).
    pub fn progress(&self, name: &str, done: u64, total: u64, wire: u64, path: &str) {
        if self.quiet || self.mode != Mode::Human {
            return;
        }
        let pct = if total == 0 {
            100
        } else {
            (done / total.div_ceil(100)).min(100)
        };
        let name_disp: String = name.chars().take(24).collect();
        eprint!(
            "\r{name_disp:<24} {pct:>3}% {:>9}/{:<9} wire {:>9} {path:<12}",
            mib(done),
            mib(total),
            mib(wire)
        );
        let _ = std::io::stderr().flush();
    }

    pub fn progress_end(&self) {
        if !self.quiet && self.mode == Mode::Human {
            eprintln!();
        }
    }
}

pub fn human_error(code: &ErrorCode, msg: &str) {
    eprintln!("error [{code}]: {}", sanitize(msg));
}

/// Peer-controlled strings (TEXT/ERROR payloads) must not carry terminal
/// escape sequences: strip C0 controls and DEL before printing.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}
