//! filejaunt CLI.

mod engine;
mod signals;
mod store;
mod ui;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use ui::{Mode, Out};

use engine::Engine;

#[derive(Parser)]
#[command(
    name = "filejaunt",
    version,
    about = "Encrypted P2P file transfer, no server, no relay",
    disable_help_subcommand = true
)]
struct Cli {
    /// NDJSON events on stdout
    #[arg(long, global = true)]
    json: bool,

    /// quiet (no progress lines)
    #[arg(short = 'q', long, global = true)]
    quiet: bool,

    /// verbose
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send files (you are the offer side)
    Send {
        /// Files or directories
        paths: Vec<PathBuf>,

        /// Words in the generated passphrase (4..=12)
        #[arg(long, default_value_t = 6)]
        words: u8,

        /// Private 3-step pairing (SDP never in clear; 4 pastes)
        #[arg(long)]
        private: bool,

        /// STUN servers: none | public | stun:host:port[,..]
        #[arg(long, default_value = "none")]
        stun: String,

        /// TURN server USER:PASS@HOST:PORT
        #[arg(long)]
        turn: Option<String>,

        /// gzip: auto | on | off
        #[arg(long, default_value = "auto")]
        gzip: String,

        /// Data channels (1 or 4)
        #[arg(long, default_value_t = 1)]
        channels: u8,

        /// Fan-out to N receivers (1..=4)
        #[arg(long, default_value_t = 1)]
        receivers: u8,
    },
    /// Receive files (you are the answer side)
    Receive {
        /// Output directory
        #[arg(long, default_value = ".")]
        out: PathBuf,

        /// STUN servers: none | public | stun:host:port[,..]
        #[arg(long, default_value = "none")]
        stun: String,

        /// TURN server USER:PASS@HOST:PORT
        #[arg(long)]
        turn: Option<String>,

        /// Overwrite existing files without asking
        #[arg(long)]
        yes: bool,
    },
    /// Resume an interrupted transfer (same passphrase as the original)
    Resume {
        /// Session id (hex) shown when the session started
        sid: String,

        /// Output directory (receive side)
        #[arg(long, default_value = ".")]
        out: PathBuf,

        /// STUN servers
        #[arg(long, default_value = "none")]
        stun: String,

        /// TURN server USER:PASS@HOST:PORT
        #[arg(long)]
        turn: Option<String>,

        /// Overwrite without asking (receive side)
        #[arg(long)]
        yes: bool,

        /// Send side: resume as sender
        #[arg(long)]
        send: bool,
    },
    /// Diagnose NAT behavior via STUN
    Doctor {
        /// STUN servers: public | stun:host:port[,..]
        #[arg(long)]
        stun: Option<String>,
    },
    /// Verify a receipt file
    Verify {
        /// Receipt JSON file
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Shell completions
    Completions { shell: Shell },
}

fn ice_from(stun: &str, turn: &Option<String>) -> fj_webrtc::IceConfig {
    if stun == "public" {
        eprintln!("note: public STUN sees your IP");
    }
    fj_webrtc::IceConfig {
        stun: engine::parse_stun(stun),
        turn: turn.as_deref().and_then(engine::parse_turn),
    }
}

fn main() {
    let cli = Cli::parse();
    let mode = if cli.json { Mode::Json } else { Mode::Human };
    let out = Out {
        mode,
        quiet: cli.quiet,
    };
    let store = match store::Store::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot create state dir: {e}");
            std::process::exit(5);
        }
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let code = rt.block_on(run(cli, out, store));
    std::process::exit(code);
}

async fn run(cli: Cli, out: Out, store: store::Store) -> i32 {
    match cli.cmd {
        Cmd::Send {
            paths,
            words,
            private,
            stun,
            turn,
            gzip,
            channels,
            receivers,
        } => {
            if paths.is_empty() {
                eprintln!("no paths given");
                return 2;
            }
            if !matches!(channels, 1 | 4) {
                eprintln!("--channels must be 1 or 4");
                return 2;
            }
            if !(1..=fj_protocol::RECEIVERS_MAX as u8).contains(&receivers) {
                eprintln!("--receivers must be 1..={}", fj_protocol::RECEIVERS_MAX);
                return 2;
            }
            if !(fj_protocol::WORDS_MIN as u8..=fj_protocol::WORDS_MAX as u8).contains(&words) {
                eprintln!("--words must be 4..=12");
                return 2;
            }
            if !matches!(gzip.as_str(), "auto" | "on" | "off") {
                eprintln!("--gzip must be auto|on|off");
                return 2;
            }
            let engine = Engine {
                out,
                store,
                ice: ice_from(&stun, &turn),
                channels: channels as usize,
                yes: true,
                passphrase_prompt: None,
                sources: std::cell::RefCell::new(vec![]),
            };
            match engine
                .send(
                    &paths,
                    words as usize,
                    private,
                    &gzip,
                    receivers as usize,
                    None,
                )
                .await
            {
                Ok(_) => 0,
                Err(code) => {
                    ui::human_error(&code, "send failed");
                    code.exit_code()
                }
            }
        }
        Cmd::Receive {
            out: dir,
            stun,
            turn,
            yes,
        } => {
            let engine = Engine {
                out,
                store,
                ice: ice_from(&stun, &turn),
                channels: 1,
                yes,
                passphrase_prompt: None,
                sources: std::cell::RefCell::new(vec![]),
            };
            match engine.receive(&dir, None).await {
                Ok(_) => 0,
                Err(code) => {
                    ui::human_error(&code, "receive failed");
                    code.exit_code()
                }
            }
        }
        Cmd::Resume {
            sid,
            out: dir,
            stun,
            turn,
            yes,
            send,
        } => {
            if send {
                // sender resume: no blob to read first, prompt up-front
                let passphrase =
                    engine::read_line_prompt("passphrase (same as the original session): ");
                if passphrase.is_empty() {
                    eprintln!("no passphrase given");
                    return 3;
                }
                let engine = Engine {
                    out,
                    store,
                    ice: ice_from(&stun, &turn),
                    channels: 1,
                    yes: true,
                    passphrase_prompt: Some(passphrase),
                    sources: std::cell::RefCell::new(vec![]),
                };
                // sender resume: no paths needed, manifest comes from state
                match engine
                    .send(
                        &[],
                        6,
                        false,
                        "auto",
                        1,
                        Some((&sid, engine.passphrase_prompt.as_deref().unwrap_or(""))),
                    )
                    .await
                {
                    Ok(_) => 0,
                    Err(code) => {
                        ui::human_error(&code, "resume failed");
                        code.exit_code()
                    }
                }
            } else {
                let engine = Engine {
                    out,
                    store,
                    ice: ice_from(&stun, &turn),
                    channels: 1,
                    yes,
                    passphrase_prompt: None,
                    sources: std::cell::RefCell::new(vec![]),
                };
                match engine.receive(&dir, Some(&sid)).await {
                    Ok(_) => 0,
                    Err(code) => {
                        ui::human_error(&code, "resume failed");
                        code.exit_code()
                    }
                }
            }
        }
        Cmd::Doctor { stun } => {
            let urls: Vec<String> = match &stun {
                None => engine::PUBLIC_STUN.iter().map(|s| s.to_string()).collect(),
                Some(s) => engine::parse_stun(s),
            };
            if urls.is_empty() {
                // --stun none: no probe possible, report and exit cleanly
                match out.mode {
                    Mode::Json => out.json(serde_json::json!({
                        "type": "doctor", "class": "UNKNOWN",
                        "results": [], "description":
                        "no STUN servers configured; LAN-direct sessions still work with host candidates",
                    })),
                    Mode::Human => {
                        println!("UNKNOWN (no STUN servers configured)");
                        println!("LAN-direct sessions still work with host candidates");
                    }
                }
                return 0;
            }
            let results = fj_webrtc::stun::stun_probe(&urls);
            let class = fj_webrtc::classify(&results);
            match out.mode {
                Mode::Json => out.json(serde_json::json!({
                    "type": "doctor",
                    "class": class.short(),
                    "results": results.iter().map(|r| match r {
                        Some(a) => serde_json::Value::String(a.to_string()),
                        None => serde_json::Value::Null,
                    }).collect::<Vec<_>>(),
                    "description": class.description(),
                })),
                Mode::Human => {
                    println!("{}", class.short());
                    println!("{}", class.description());
                    for (i, r) in results.iter().enumerate() {
                        match r {
                            Some(a) => println!("  server {}: {}", i + 1, a),
                            None => println!("  server {}: no response", i + 1),
                        }
                    }
                }
            }
            0
        }
        Cmd::Verify { receipt } => {
            let raw = match std::fs::read_to_string(&receipt) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("cannot read {}: {e}", receipt.display());
                    return 2;
                }
            };
            let r: fj_protocol::Receipt = match serde_json::from_str(&raw) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid receipt: {e}");
                    return 3;
                }
            };
            let passphrase = engine::read_line_prompt("passphrase: ");
            if r.verify(&passphrase) {
                println!("VALID");
                println!("file {} sha256 {} bytes {}", r.file, r.sha256, r.bytes);
                0
            } else {
                println!("INVALID");
                3
            }
        }
        Cmd::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "filejaunt", &mut std::io::stdout());
            0
        }
    }
}
