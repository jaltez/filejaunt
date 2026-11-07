//! filejaunt signaling relay.
//!
//! Room-based WebSocket relay for pairing blobs. Clients join a room by id
//! (derived client-side from the passphrase hash — the relay cannot invert
//! it); the relay forwards opaque text messages between the two peers of a
//! room and sees NOTHING else:
//!
//! - no passphrase, no keys, no decrypted SDP, no file metadata
//! - only the room id, opaque ciphertext blobs, sizes and timing
//!
//! Protocol (JSON text frames):
//!   client → server: {"t":"join","room":"<hex>"} | {"t":"msg","data":"<text>"}
//!   server → client: {"t":"joined","slot":N} | {"t":"peer-joined"}
//!                    | {"t":"peer-left"} | {"t":"msg","data":"<text>"}
//!                    | {"t":"error","msg":"..."}
//!
//! Limits: room id ≤ 64 hex chars, message ≤ 256 KiB, max 2 peers/room,
//! rooms (with no connected peers) reaped after 10 minutes idle. Run behind a TLS-terminating reverse
//! proxy in production (clients use wss://).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

const MAX_ROOM_ID: usize = 64;
const MAX_MSG: usize = 256 * 1024;
const MAX_PEERS: usize = 2;
const MAX_ROOMS: usize = 10_000;
const IDLE: Duration = Duration::from_secs(10 * 60);

struct Peer {
    tx: mpsc::UnboundedSender<String>,
}

#[derive(Default)]
struct Registry {
    rooms: HashMap<String, Room>,
}

struct Room {
    /// Peer slots in join order; `None` = disconnected slot (kept so peer
    /// indexes remain stable).
    peers: Vec<Option<Peer>>,
    last: Instant,
}

impl Room {
    fn new() -> Room {
        Room {
            peers: Vec::new(),
            last: Instant::now(),
        }
    }
}

impl Room {
    fn broadcast(&self, line: &str) {
        for p in self.peers.iter().flatten() {
            let _ = p.tx.send(line.to_string());
        }
    }

    fn full(&self) -> bool {
        self.peers.iter().flatten().count() >= MAX_PEERS
    }
}

#[derive(Clone, Default)]
struct AppState {
    registry: Arc<Mutex<Registry>>,
}

fn now_line(kind: &str, extra: &str) -> String {
    if extra.is_empty() {
        serde_json::json!({ "t": kind }).to_string()
    } else {
        // serde_json escapes client-supplied data: a hostile peer cannot
        // forge fields or emit invalid JSON downstream.
        serde_json::json!({ "t": kind, "data": extra }).to_string()
    }
}

fn valid_room(room: &str) -> bool {
    !room.is_empty()
        && room.len() <= MAX_ROOM_ID
        && room
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

async fn reap(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let mut count = 0usize;
        {
            let mut reg = state.registry.lock().unwrap();
            let ids: Vec<String> = reg
                .rooms
                .iter()
                .filter(|(_, r)| r.last.elapsed() > IDLE && r.peers.iter().flatten().count() == 0)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ids {
                // Filter guarantees no connected peers remain.
                if reg.rooms.remove(id).is_some() {
                    count += 1;
                }
            }
        }
        if count > 0 {
            eprintln!("reaped {count} idle room(s)");
        }
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| peer_socket(socket, state))
}

async fn peer_socket(socket: WebSocket, state: AppState) {
    let (mut tx, mut rx) = socket.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

    let pump = tokio::spawn(async move {
        // Cloudflare's proxy drops idle WebSocket connections after ~100 s.
        // A protocol-level ping every 30 s keeps the hop alive (browsers and
        // tokio-tungstenite answer pings automatically); peers waiting
        // minutes to pair would otherwise be cut mid-handshake.
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    if tx.send(Message::Ping(vec![])).await.is_err() {
                        break;
                    }
                }
                line = out_rx.recv() => {
                    let Some(line) = line else { break };
                    if tx.send(Message::Text(line)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let my: Arc<Mutex<Option<(String, usize)>>> = Arc::new(Mutex::new(None));
    let my_cl = my.clone();

    let read = async {
        while let Some(Ok(msg)) = rx.next().await {
            let line = match msg {
                Message::Text(t) => t,
                Message::Close(_) => break,
                _ => continue,
            };
            if line.len() > MAX_MSG {
                let _ = out_tx.send(now_line("error", "message too large"));
                break;
            }
            let v: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    let _ = out_tx.send(now_line("error", "bad json"));
                    continue;
                }
            };
            match v.get("t").and_then(|t| t.as_str()) {
                Some("join") => {
                    let room = v.get("room").and_then(|r| r.as_str()).unwrap_or("");
                    if !valid_room(room) {
                        let _ = out_tx.send(now_line(
                            "error",
                            "room id must be 1..64 lowercase hex chars",
                        ));
                        continue;
                    }
                    let mut me = my_cl.lock().unwrap();
                    if me.is_some() {
                        let _ = out_tx.send(now_line("error", "already joined"));
                        continue;
                    }
                    let mut reg = state.registry.lock().unwrap();
                    if reg.rooms.len() >= MAX_ROOMS {
                        let _ = out_tx.send(now_line("error", "relay full"));
                        continue;
                    }
                    let r = reg.rooms.entry(room.to_string()).or_insert_with(|| {
                        eprintln!("room open: {}…", &room[..room.len().min(8)]);
                        Room::new()
                    });
                    if r.full() {
                        let _ = out_tx.send(now_line("error", "room full"));
                        continue;
                    }
                    let mut slot = r.peers.len();
                    let waiting = r.peers.iter().flatten().count();
                    for (i, p) in r.peers.iter().enumerate() {
                        if p.is_none() {
                            slot = i;
                            break;
                        }
                    }
                    if slot >= r.peers.len() {
                        r.peers.push(None);
                    }
                    r.peers[slot] = Some(Peer { tx: out_tx.clone() });
                    r.last = Instant::now();
                    *me = Some((room.to_string(), slot));
                    drop(reg);
                    let _ = out_tx.send(format!("{{\"t\":\"joined\",\"slot\":{slot}}}"));
                    if waiting > 0 {
                        let reg = state.registry.lock().unwrap();
                        if let Some(r) = reg.rooms.get(room) {
                            r.broadcast("{\"t\":\"peer-joined\"}");
                        }
                    }
                }
                Some("msg") => {
                    let data = v.get("data").and_then(|d| d.as_str()).unwrap_or("");
                    if data.len() > MAX_MSG {
                        let _ = out_tx.send(now_line("error", "message too large"));
                        continue;
                    }
                    let guard = my.lock().unwrap();
                    let Some((room, slot)) = guard.as_ref().map(|(r, s)| (r.clone(), *s)) else {
                        let _ = out_tx.send(now_line("error", "not in a room"));
                        continue;
                    };
                    drop(guard);
                    let mut reg = state.registry.lock().unwrap();
                    let Some(r) = reg.rooms.get_mut(&room) else {
                        let _ = out_tx.send(now_line("error", "room gone"));
                        continue;
                    };
                    r.last = Instant::now();
                    for (i, p) in r.peers.iter().enumerate() {
                        if i == slot {
                            continue;
                        }
                        if let Some(p) = p {
                            let _ = p.tx.send(now_line("msg", data));
                        }
                    }
                }
                _ => {
                    let _ = out_tx.send(now_line("error", "unknown type"));
                }
            }
        }
    };

    let mut pump_handle = pump;
    tokio::select! {
        _ = read => {},
        _ = &mut pump_handle => {},
    }

    // leave room: clear my slot, notify the peer, reap if empty
    let (room, slot) = my.lock().unwrap().take().unwrap_or_default();
    let mut reg = state.registry.lock().unwrap();
    if let Some(r) = reg.rooms.get_mut(&room) {
        if slot < r.peers.len() {
            r.peers[slot] = None;
        }
        r.broadcast("{\"t\":\"peer-left\"}");
        if r.peers.iter().flatten().count() == 0 {
            reg.rooms.remove(&room);
        }
    }
    pump_handle.abort();
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(8088);
    let state = AppState::default();
    tokio::spawn(reap(state.clone()));
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("bind");
    eprintln!("fj-relay listening on 0.0.0.0:{port} (ws://host:{port}/ws)");
    axum::serve(listener, app).await.unwrap();
}
