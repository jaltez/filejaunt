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
//! rooms (with no connected peers) reaped after 10 minutes idle, per-peer
//! outbound queue bounded (32 msgs / 256 KiB — slow peers are dropped, never
//! buffered), join timeout 30 s, 20 joins/min/IP. Run behind a
//! TLS-terminating reverse proxy in production (clients use wss://).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

const MAX_ROOM_ID: usize = 64;
const MAX_MSG: usize = 256 * 1024;
const MAX_PEERS: usize = 2;
const MAX_ROOMS: usize = 10_000;
/// Per-IP concurrent sockets: one pairing needs 2 (rarely 4 across resume
/// generations). Without a cap a single client can exhaust MAX_ROOMS by
/// opening rooms it never fills.
const MAX_PEERS_PER_IP: usize = 8;
const MAX_TOTAL_PEERS: usize = MAX_ROOMS * MAX_PEERS;
const IDLE: Duration = Duration::from_secs(10 * 60);
/// F2: per-peer outbound queue caps. A slow peer is dropped (its pump sees
/// the closed channel) instead of growing server memory without bound.
const PEER_QUEUE_MSGS: usize = 32;
const PEER_QUEUE_BYTES: usize = MAX_MSG;
/// F10: a socket must join a room within this window or get dropped
/// (anti room-squatting: connect-and-never-join holds a slot forever).
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
/// F10: join rate per client IP.
const JOIN_WINDOW: Duration = Duration::from_secs(60);
const MAX_JOINS_PER_MIN: u32 = 20;

struct Peer {
    tx: mpsc::Sender<String>,
    /// Bytes queued and not yet written to the socket (pump decrements).
    bytes: Arc<AtomicUsize>,
}

/// Deliver to a peer without ever blocking or growing past caps (F2).
/// Returns false when the peer is over cap/closed and must be dropped.
fn try_deliver(p: &Peer, line: &str) -> bool {
    if p.bytes.load(Ordering::Relaxed) + line.len() > PEER_QUEUE_BYTES {
        return false;
    }
    match p.tx.try_send(line.to_string()) {
        Ok(()) => {
            p.bytes.fetch_add(line.len(), Ordering::Relaxed);
            true
        }
        Err(_) => false,
    }
}

#[derive(Default)]
struct Registry {
    rooms: HashMap<String, Room>,
    /// Concurrent sockets per client IP (abuse cap; see MAX_PEERS_PER_IP).
    peers_by_ip: HashMap<IpAddr, usize>,
    total_peers: usize,
    /// F10: join attempts per client IP inside the sliding window.
    joins_by_ip: HashMap<IpAddr, (Instant, u32)>,
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

    fn full(&self) -> bool {
        self.peers.iter().flatten().count() >= MAX_PEERS
    }

    /// Deliver `line` to every connected peer; peers over cap are dropped
    /// (slot cleared — releasing their last Sender breaks their pump) and
    /// the survivors are told they left (F2).
    fn broadcast(&mut self, line: &str) {
        let mut over_cap = false;
        for slot in self.peers.iter_mut() {
            if let Some(p) = slot
                && !try_deliver(p, line)
            {
                *slot = None;
                over_cap = true;
            }
        }
        if over_cap {
            let left = now_line("peer-left", "");
            for p in self.peers.iter_mut().flatten() {
                let _ = try_deliver(p, &left);
            }
        }
    }
}

#[derive(Clone, Default)]
struct AppState {
    registry: Arc<Mutex<Registry>>,
    /// F3: how many reverse proxy hops in front of this relay are trusted
    /// to have appended honest X-Forwarded-For entries.
    trusted_proxies: usize,
}

fn valid_room(room: &str) -> bool {
    !room.is_empty()
        && room.len() <= MAX_ROOM_ID
        && room
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
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
            reg.joins_by_ip
                .retain(|_, (t, _)| t.elapsed() <= JOIN_WINDOW);
        }
        if count > 0 {
            eprintln!("reaped {count} idle room(s)");
        }
    }
}

/// Client IP behind `trusted` reverse proxies (F3). X-Forwarded-For lists
/// hops in order, each proxy appending the address it saw; with `trusted`
/// trusted proxies, the entry `trusted` positions from the END was appended
/// by the outermost trusted proxy and names the hop it received the request
/// from — a client cannot move itself anywhere but the FRONT of the list.
/// `trusted == 0` ignores the header entirely (direct deployment).
fn client_ip(headers: &HeaderMap, sock: SocketAddr, trusted: usize) -> IpAddr {
    if trusted == 0 {
        return sock.ip();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').nth_back(trusted - 1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| sock.ip())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(sock): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let ip = client_ip(&headers, sock, state.trusted_proxies);
    {
        let mut reg = state.registry.lock().unwrap();
        let per_ip = *reg.peers_by_ip.entry(ip).or_insert(0);
        if per_ip >= MAX_PEERS_PER_IP || reg.total_peers >= MAX_TOTAL_PEERS {
            eprintln!(
                "refusing socket from {ip}: per-ip {per_ip}, total {}",
                reg.total_peers
            );
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        *reg.peers_by_ip.get_mut(&ip).unwrap() += 1;
        reg.total_peers += 1;
    }
    let failed_state = state.clone();
    ws
        // F7: enforce the protocol's message cap at the websocket layer too
        // (frame + reassembled message), before any allocation-heavy work.
        .max_message_size(MAX_MSG + 1024)
        .max_frame_size(MAX_MSG + 1024)
        .on_failed_upgrade(move |_| {
            // upgrade never ran peer_socket: give the slot back
            let mut reg = failed_state.registry.lock().unwrap();
            reg.total_peers = reg.total_peers.saturating_sub(1);
            if let Some(n) = reg.peers_by_ip.get_mut(&ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    reg.peers_by_ip.remove(&ip);
                }
            }
        })
        .on_upgrade(move |socket| peer_socket(socket, state, ip))
}

async fn peer_socket(socket: WebSocket, state: AppState, ip: IpAddr) {
    let (mut tx, mut rx) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<String>(PEER_QUEUE_MSGS);
    let out_bytes = Arc::new(AtomicUsize::new(0));
    let pump_bytes = out_bytes.clone();

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
                    let len = line.len();
                    if tx.send(Message::Text(line)).await.is_err() {
                        break;
                    }
                    pump_bytes.fetch_sub(len, Ordering::Relaxed);
                }
            }
        }
    });

    let my: Arc<Mutex<Option<(String, usize)>>> = Arc::new(Mutex::new(None));
    let my_cl = my.clone();

    let read = async {
        // F2: even self-addressed errors go through the bounded queue; if
        // the peer's own queue is full it is stalled and gets dropped.
        let deliver_own = |line: &str| -> bool {
            try_deliver(
                &Peer {
                    tx: out_tx.clone(),
                    bytes: out_bytes.clone(),
                },
                line,
            )
        };
        loop {
            // F10: a socket that never joins a room is squatting — drop it.
            let msg = if my_cl.lock().unwrap().is_none() {
                match tokio::time::timeout(JOIN_TIMEOUT, rx.next()).await {
                    Ok(m) => m,
                    Err(_) => break,
                }
            } else {
                rx.next().await
            };
            let Some(Ok(msg)) = msg else { break };
            let line = match msg {
                Message::Text(t) => t,
                Message::Close(_) => break,
                _ => continue,
            };
            if line.len() > MAX_MSG {
                if !deliver_own(&now_line("error", "message too large")) {
                    break;
                }
                break;
            }
            let v: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    if !deliver_own(&now_line("error", "bad json")) {
                        break;
                    }
                    continue;
                }
            };
            match v.get("t").and_then(|t| t.as_str()) {
                Some("join") => {
                    let room = v.get("room").and_then(|r| r.as_str()).unwrap_or("");
                    if !valid_room(room) {
                        if !deliver_own(&now_line(
                            "error",
                            "room id must be 1..64 lowercase hex chars",
                        )) {
                            break;
                        }
                        continue;
                    }
                    let mut me = my_cl.lock().unwrap();
                    if me.is_some() {
                        if !deliver_own(&now_line("error", "already joined")) {
                            break;
                        }
                        continue;
                    }
                    let mut reg = state.registry.lock().unwrap();
                    // F10: sliding-window join rate per IP.
                    let now = Instant::now();
                    let entry = reg.joins_by_ip.entry(ip).or_insert((now, 0));
                    if now.duration_since(entry.0) > JOIN_WINDOW {
                        *entry = (now, 0);
                    }
                    entry.1 += 1;
                    if entry.1 > MAX_JOINS_PER_MIN {
                        drop(reg);
                        drop(me);
                        let _ = deliver_own(&now_line("error", "too many joins"));
                        break;
                    }
                    if reg.rooms.len() >= MAX_ROOMS {
                        if !deliver_own(&now_line("error", "relay full")) {
                            break;
                        }
                        continue;
                    }
                    let r = reg.rooms.entry(room.to_string()).or_insert_with(|| {
                        eprintln!("room open: {}…", &room[..room.len().min(8)]);
                        Room::new()
                    });
                    if r.full() {
                        if !deliver_own(&now_line("error", "room full")) {
                            break;
                        }
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
                    r.peers[slot] = Some(Peer {
                        tx: out_tx.clone(),
                        bytes: out_bytes.clone(),
                    });
                    r.last = Instant::now();
                    *me = Some((room.to_string(), slot));
                    drop(reg);
                    if !deliver_own(&format!("{{\"t\":\"joined\",\"slot\":{slot}}}")) {
                        break;
                    }
                    if waiting > 0 {
                        let mut reg = state.registry.lock().unwrap();
                        if let Some(r) = reg.rooms.get_mut(room) {
                            r.broadcast(&now_line("peer-joined", ""));
                        }
                    }
                }
                Some("msg") => {
                    let data = v.get("data").and_then(|d| d.as_str()).unwrap_or("");
                    if data.len() > MAX_MSG {
                        if !deliver_own(&now_line("error", "message too large")) {
                            break;
                        }
                        continue;
                    }
                    let guard = my.lock().unwrap();
                    let Some((room, slot)) = guard.as_ref().map(|(r, s)| (r.clone(), *s)) else {
                        if !deliver_own(&now_line("error", "not in a room")) {
                            break;
                        }
                        continue;
                    };
                    drop(guard);
                    let line = now_line("msg", data);
                    let mut reg = state.registry.lock().unwrap();
                    let Some(r) = reg.rooms.get_mut(&room) else {
                        if !deliver_own(&now_line("error", "room gone")) {
                            break;
                        }
                        continue;
                    };
                    r.last = Instant::now();
                    // F2: a slow peer over cap is dropped from the room and
                    // the survivor hears peer-left.
                    let mut over_cap = Vec::new();
                    for (i, p) in r.peers.iter().enumerate() {
                        if i == slot {
                            continue;
                        }
                        if let Some(p) = p
                            && !try_deliver(p, &line)
                        {
                            over_cap.push(i);
                        }
                    }
                    for i in over_cap {
                        r.peers[i] = None;
                        r.broadcast(&now_line("peer-left", ""));
                    }
                }
                _ => {
                    if !deliver_own(&now_line("error", "unknown type")) {
                        break;
                    }
                }
            }
        }
    };

    let mut pump_handle = pump;
    tokio::select! {
        _ = read => {},
        _ = &mut pump_handle => {},
    }

    // leave room: clear my slot, notify the peer, reap if empty; give the
    // per-ip/total connection slot back
    let (room, slot) = my.lock().unwrap().take().unwrap_or_default();
    let mut reg = state.registry.lock().unwrap();
    reg.total_peers = reg.total_peers.saturating_sub(1);
    if let Some(n) = reg.peers_by_ip.get_mut(&ip) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            reg.peers_by_ip.remove(&ip);
        }
    }
    // F10: forget the join-rate window once it has gone stale
    if matches!(reg.joins_by_ip.get(&ip), Some((t, _)) if t.elapsed() > JOIN_WINDOW) {
        reg.joins_by_ip.remove(&ip);
    }
    if let Some(r) = reg.rooms.get_mut(&room) {
        if slot < r.peers.len() {
            r.peers[slot] = None;
        }
        r.broadcast(&now_line("peer-left", ""));
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
    // F3: 1 = deployed behind exactly one trusted reverse proxy (the
    // documented setup); 0 = direct exposure, ignore X-Forwarded-For.
    let trusted_proxies = std::env::var("FJ_TRUSTED_PROXIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    let state = AppState {
        trusted_proxies,
        ..Default::default()
    };
    tokio::spawn(reap(state.clone()));
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("bind");
    eprintln!(
        "fj-relay listening on 0.0.0.0:{port} (ws://host:{port}/ws, caps: {MAX_PEERS_PER_IP}/ip, {MAX_TOTAL_PEERS} total, trusted_proxies={trusted_proxies})"
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(v: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = v {
            h.insert(
                "x-forwarded-for",
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn sock() -> SocketAddr {
        "9.9.9.9:4242".parse().unwrap()
    }

    #[test]
    fn client_ip_single_trusted_proxy_takes_last_hop() {
        // the proxy appends the real client at the END; a spoofed prefix
        // cannot move itself behind it
        assert_eq!(
            client_ip(&headers(Some("1.1.1.1, 2.2.2.2")), sock(), 1),
            "2.2.2.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(&headers(Some("3.3.3.3")), sock(), 1),
            "3.3.3.3".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_zero_trusted_ignores_header() {
        let me: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(client_ip(&headers(Some("1.1.1.1, 2.2.2.2")), sock(), 0), me);
        assert_eq!(client_ip(&headers(None), sock(), 0), me);
    }

    #[test]
    fn client_ip_two_trusted_proxies() {
        // chain: client -> proxyA (appends client) -> proxyB (appends proxyA)
        // header at relay: "client, proxyA"; the client hop is 2 from the end
        assert_eq!(
            client_ip(&headers(Some("1.1.1.1, 2.2.2.2")), sock(), 2),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
        // shorter list than the trust depth: fall back to the socket
        let me: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(client_ip(&headers(Some("3.3.3.3")), sock(), 2), me);
    }

    #[test]
    fn client_ip_falls_back_to_socket() {
        let me: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(client_ip(&headers(None), sock(), 1), me);
        assert_eq!(client_ip(&headers(Some("not-an-ip, ")), sock(), 1), me);
    }

    fn peer_with_cap(cap_msgs: usize, queued_bytes: usize) -> (Peer, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel::<String>(cap_msgs);
        (
            Peer {
                tx,
                bytes: Arc::new(AtomicUsize::new(queued_bytes)),
            },
            rx,
        )
    }

    #[tokio::test]
    async fn try_deliver_fails_when_channel_full() {
        let (p, mut rx) = peer_with_cap(1, 0);
        assert!(try_deliver(&p, "one"));
        assert!(
            !try_deliver(&p, "two"),
            "bounded channel: second delivery while the first is queued must fail"
        );
        assert_eq!(rx.recv().await.unwrap(), "one");
    }

    #[tokio::test]
    async fn try_deliver_fails_over_byte_cap() {
        let (p, _rx) = peer_with_cap(32, PEER_QUEUE_BYTES);
        assert!(!try_deliver(&p, "x"), "already at the byte cap");
        let (p, _rx) = peer_with_cap(32, PEER_QUEUE_BYTES - 1);
        assert!(try_deliver(&p, "x"), "exactly at the cap still delivers");
        assert_eq!(p.bytes.load(Ordering::Relaxed), PEER_QUEUE_BYTES);
    }
}
