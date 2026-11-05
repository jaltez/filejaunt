//! Shared test helpers: an in-memory loopback driver for `Session`.

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};

use fj_protocol::ErrorCode;
use fj_protocol::session::{Action, Role, Session, SessionOpts};

pub const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=filejaunt-test-offer\r\n";
pub const ANSWER: &str = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=filejaunt-test-answer\r\n";

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// Deterministic pseudo-random data (xorshift) so tests are reproducible.
pub fn prand(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x >> 24) as u8);
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Progress {
        file: u16,
        done: u64,
        total: u64,
        wire_bytes: u64,
        resumed: bool,
    },
    FileDone {
        file: u16,
        verified: bool,
    },
    Receipt,
    Text(String),
    SessionDone,
    Fail {
        code: ErrorCode,
        msg: String,
    },
}

pub struct Loop {
    pub ini: Session,
    pub rsp: Session,
    ini_out: VecDeque<Vec<u8>>,
    rsp_out: VecDeque<Vec<u8>>,
    pub source: HashMap<u16, Vec<u8>>, // sender-side file contents
    pub written: HashMap<u16, Vec<Option<Vec<u8>>>>, // receiver chunk slots
    pub events_ini: Vec<Event>,
    pub events_rsp: Vec<Event>,
    pub receipts: Vec<fj_protocol::Receipt>,
}

impl Loop {
    /// Build a paired, channel-open pair of sessions with the given file
    /// contents (ids 0..n). Gzip off for determinism.
    pub fn new(files: &[(String, Vec<u8>)], private3: bool) -> Loop {
        let mut limiter = fj_protocol::pake::AttemptLimiter::new();
        let (mut ini, passphrase, blob1) = Session::initiator_new(SessionOpts {
            words: 6,
            private3,
            chunk_size: 16384,
            sid: Some([9u8; 16]),
            offer_sdp: OFFER.to_string(),
        })
        .expect("initiator");
        let (rsp, blob2, blob3, blob4) = if private3 {
            let (rsp, blob2) =
                Session::responder_join(&blob1, &passphrase, ANSWER, &mut limiter).expect("join");
            ini.initiator_accept(&blob2)
                .expect("accept (p3: keys only)");
            let blob3 = ini.initiator_private_blob3().expect("blob3");
            let (mut rsp, _blob4) = (rsp, String::new());
            let offer = rsp
                .responder_private_offer(&blob3, &mut limiter)
                .expect("offer decrypt");
            assert_eq!(offer, OFFER);
            // responder glue would create its answer now; we already know it
            let blob4 = rsp.responder_private_blob4(ANSWER).expect("blob4");
            ini.initiator_private_final(&blob4).expect("final");
            (rsp, blob2, blob3, blob4)
        } else {
            let (rsp, blob2) =
                Session::responder_join(&blob1, &passphrase, ANSWER, &mut limiter).expect("join");
            ini.initiator_accept(&blob2).expect("accept");
            (rsp, blob2, String::new(), String::new())
        };
        let _ = (blob2, blob3, blob4);

        // files
        let specs: Vec<fj_protocol::manifest::FileSpec> = files
            .iter()
            .map(|(name, data)| fj_protocol::manifest::FileSpec {
                name: name.clone(),
                path: String::new(),
                size: data.len() as u64,
                sha256: sha256_hex(data),
                gzip: false,
            })
            .collect();
        ini.set_files(&specs).expect("set_files");
        let mut source = HashMap::new();
        for (i, (_, data)) in files.iter().enumerate() {
            source.insert(i as u16, data.clone());
        }

        let mut l = Loop {
            ini_out: Default::default(),
            rsp_out: Default::default(),
            ini,
            rsp,
            source,
            written: HashMap::new(),
            events_ini: vec![],
            events_rsp: vec![],
            receipts: vec![],
        };
        let a = l.ini.on_channel_open();
        let b = l.rsp.on_channel_open();
        l.apply(Role::Initiator, a);
        l.apply(Role::Responder, b);
        l
    }

    pub fn apply(&mut self, role: Role, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Send(bytes) => match role {
                    Role::Initiator => self.ini_out.push_back(bytes),
                    Role::Responder => self.rsp_out.push_back(bytes),
                },
                Action::SaveState => {}
                Action::SaveChunk { file, index, data } => {
                    let slots = self.written.entry(file).or_default();
                    if slots.len() <= index as usize {
                        slots.resize(index as usize + 1, None);
                    }
                    slots[index as usize] = Some(data);
                }
                Action::HashFeed { .. } => {
                    // handled by run_receiver_hash() before apply()
                }
                Action::Progress {
                    file,
                    done,
                    total,
                    wire_bytes,
                    resumed,
                } => {
                    self.events(
                        role,
                        Event::Progress {
                            file,
                            done,
                            total,
                            wire_bytes,
                            resumed,
                        },
                    );
                }
                Action::FileDone { file, verified, .. } => {
                    self.events(role, Event::FileDone { file, verified });
                }
                Action::EmitText(t) => self.events(role, Event::Text(t)),
                Action::Receipt(r) => {
                    self.receipts.push(r);
                    self.events(role, Event::Receipt);
                }
                Action::SessionDone => self.events(role, Event::SessionDone),
                Action::Fail { code, msg } => self.events(role, Event::Fail { code, msg }),
            }
        }
    }

    fn events(&mut self, role: Role, e: Event) {
        match role {
            Role::Initiator => self.events_ini.push(e),
            Role::Responder => self.events_rsp.push(e),
        }
    }

    /// Deliver all queued frames in both directions; sender keeps pushing
    /// chunks whenever it can. Runs until quiescent.
    pub fn pump(&mut self) {
        loop {
            let mut moved = 0usize;
            // initiator -> responder
            while let Some(wire) = self.ini_out.pop_front() {
                moved += 1;
                let actions = match self.rsp.on_frame(&wire) {
                    Ok(a) => a,
                    Err(e) => {
                        self.events_rsp.push(Event::Fail {
                            code: e.code(),
                            msg: e.msg().to_string(),
                        });
                        vec![]
                    }
                };
                // intercept HashFeed: receiver must re-read and feed
                self.run_receiver_hash(&actions);
                self.apply(Role::Responder, actions);
            }
            // responder -> initiator
            while let Some(wire) = self.rsp_out.pop_front() {
                moved += 1;
                match self.ini.on_frame(&wire) {
                    Ok(a) => self.apply(Role::Initiator, a),
                    Err(e) => self.events_ini.push(Event::Fail {
                        code: e.code(),
                        msg: e.msg().to_string(),
                    }),
                }
            }
            // sender drive
            let pushed = self.drive_sender();
            if moved == 0 && pushed == 0 {
                break;
            }
        }
    }

    pub fn run_receiver_hash(&mut self, actions: &[Action]) {
        for a in actions {
            if let Action::HashFeed { file } = a {
                let slots = self.written.get(file).cloned().unwrap_or_default();
                let mut buf = Vec::new();
                for s in slots.iter().flatten() {
                    buf.extend_from_slice(s);
                }
                let more = self.rsp.hash_feed(*file, &buf).expect("hash_feed ok");
                self.apply(Role::Responder, more);
            }
        }
    }

    /// Push at most one batch of pending chunks (all files, one chunk each
    /// round) so tests can stop mid-transfer.
    pub fn drive_sender(&mut self) -> usize {
        let ids = self.ini.file_ids();
        let mut pushed = 0usize;
        for id in ids {
            while let Some((index, len)) = self.ini.next_send_chunk(id) {
                let src = self.source[&id].clone();
                let start = (index * 16384) as usize;
                let end = start + len as usize;
                let bytes = src[start..end].to_vec();
                let (wire, actions) = self.ini.push_chunk_data(id, index, &bytes).expect("push");
                self.ini_out.push_back(wire);
                self.apply(Role::Initiator, actions);
                pushed += 1;
                if pushed >= 8 {
                    return pushed;
                }
            }
        }
        pushed
    }

    /// Push exactly `n` chunks total (for mid-transfer interruption tests).
    pub fn push_n_chunks(&mut self, n: usize) {
        let mut done = 0;
        self.deliver_pending();
        while done < n {
            let ids = self.ini.file_ids();
            let before = done;
            for id in ids {
                if done >= n {
                    break;
                }
                if let Some((index, len)) = self.ini.next_send_chunk(id) {
                    let src = self.source[&id].clone();
                    let start = (index * 16384) as usize;
                    let bytes = src[start..start + len as usize].to_vec();
                    let (wire, actions) =
                        self.ini.push_chunk_data(id, index, &bytes).expect("push");
                    self.ini_out.push_back(wire);
                    self.apply(Role::Initiator, actions);
                    done += 1;
                }
            }
            // deliver what we queued so the receiver advances
            while let Some(w) = self.ini_out.pop_front() {
                if let Ok(actions) = self.rsp.on_frame(&w) {
                    self.run_receiver_hash(&actions);
                    self.apply(Role::Responder, actions);
                }
            }
            while let Some(w) = self.rsp_out.pop_front() {
                if let Ok(actions) = self.ini.on_frame(&w) {
                    self.apply(Role::Initiator, actions);
                }
            }
            if done == before {
                break;
            }
        }
    }

    fn deliver_pending(&mut self) {
        while let Some(w) = self.ini_out.pop_front() {
            if let Ok(actions) = self.rsp.on_frame(&w) {
                self.run_receiver_hash(&actions);
                self.apply(Role::Responder, actions);
            }
        }
        while let Some(w) = self.rsp_out.pop_front() {
            if let Ok(actions) = self.ini.on_frame(&w) {
                self.apply(Role::Initiator, actions);
            }
        }
    }

    pub fn received_file(&self, file: u16) -> Vec<u8> {
        let mut out = Vec::new();
        for s in self.written.get(&file).into_iter().flatten().flatten() {
            out.extend_from_slice(s);
        }
        out
    }

    pub fn has_fail(&self, code: ErrorCode) -> bool {
        self.events_ini
            .iter()
            .chain(self.events_rsp.iter())
            .any(|e| matches!(e, Event::Fail { code: c, .. } if *c == code))
    }
}

/// 1 MiB in exactly 64 chunks of 16384.
pub fn file_1mib() -> Vec<u8> {
    prand(0xF00D, 1 << 20)
}

/// 3 MiB (192 chunks).
pub fn file_3mib() -> Vec<u8> {
    prand(0xBEEF, 3 << 20)
}
