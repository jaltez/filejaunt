//! webrtc-rs wrapper: one `PeerHandle` per RTCPeerConnection.
//!
//! - Offer/answer with ICE-gathering wait (`GATHER_TIMEOUT_MS`; continues
//!   with whatever was gathered on timeout).
//! - N ordered+reliable DataChannels labeled `fj-0..n-1` (offer side creates
//!   them; answer side receives them via `on_data_channel`).
//! - Frame callbacks per channel, backpressure via `buffered_amount()` (the
//!   send loop waits until the queue drains; webrtc-rs 0.14 exposes the
//!   async `buffered_amount()` so a timed poll of 10 ms is used around it).
//! - Selected candidate type + basic stats for the UI badge.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, Notify};

use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::stats::{StatsReport, StatsReportType};

use fj_protocol::{BACKPRESSURE_HIGH_BYTES, GATHER_TIMEOUT_MS};

/// STUN/TURN configuration.
#[derive(Debug, Clone, Default)]
pub struct IceConfig {
    /// `stun:host:port` URLs.
    pub stun: Vec<String>,
    /// (url, username, credential).
    pub turn: Option<(String, String, String)>,
}

impl IceConfig {
    fn to_rtc(&self) -> RTCConfiguration {
        let mut servers = Vec::new();
        for s in &self.stun {
            servers.push(RTCIceServer {
                urls: vec![s.clone()],
                ..Default::default()
            });
        }
        if let Some((url, user, pass)) = &self.turn {
            servers.push(RTCIceServer {
                urls: vec![url.clone()],
                username: user.clone(),
                credential: pass.clone(),
            });
        }
        RTCConfiguration {
            ice_servers: servers,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub rtt_ms: Option<f64>,
    /// Outgoing bitrate estimate in Mbit/s.
    pub mbps: Option<f64>,
    /// "host" | "srflx" | "relay" of the selected pair.
    pub candidate: Option<String>,
}

type FrameCb = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// State shared with channel callbacks (no Arc cycles with PeerHandle).
struct PeerState {
    channels: Mutex<Vec<Option<Arc<webrtc::data_channel::RTCDataChannel>>>>,
    cbs: Mutex<Vec<Option<FrameCb>>>,
    expected: AtomicUsize,
    opened: AtomicUsize,
    connected: AtomicBool,
    notify: Notify,
}

pub struct PeerHandle {
    pc: Arc<RTCPeerConnection>,
    state: Arc<PeerState>,
}

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("data channel(s) did not open")]
    ChannelOpen,
    #[error("peer connection failed")]
    Failed,
    #[error("channel index out of range")]
    NoChannel,
    #[error("{0}")]
    Webrtc(#[from] webrtc::Error),
}

pub type PResult<T> = std::result::Result<T, PeerError>;

fn channel_index(label: &str) -> Option<usize> {
    label.strip_prefix("fj-")?.parse().ok()
}

impl PeerHandle {
    pub async fn new(ice: &IceConfig) -> PResult<Arc<PeerHandle>> {
        let mut me = MediaEngine::default();
        me.register_default_codecs()?;
        let mut se = webrtc::api::setting_engine::SettingEngine::default();
        // CLI-to-CLI on one host: skip mDNS (.local names do not resolve
        // across processes here) and include loopback candidates so pure
        // `--stun none` sessions connect on localhost.
        se.set_ice_multicast_dns_mode(webrtc::ice::mdns::MulticastDnsMode::Disabled);
        se.set_include_loopback_candidate(true);
        let api = APIBuilder::new()
            .with_media_engine(me)
            .with_setting_engine(se)
            .build();
        let pc = api.new_peer_connection(ice.to_rtc()).await?;
        let state = Arc::new(PeerState {
            channels: Mutex::new(vec![]),
            cbs: Mutex::new(vec![]),
            expected: AtomicUsize::new(0),
            opened: AtomicUsize::new(0),
            connected: AtomicBool::new(false),
            notify: Notify::new(),
        });

        if std::env::var("FJ_DEBUG").is_ok() {
            pc.on_ice_connection_state_change(Box::new(|st| {
                Box::pin(async move {
                    eprintln!("[fj-debug pid={}] ice state: {st:?}", std::process::id());
                })
            }));
            pc.on_peer_connection_state_change(Box::new(|st| {
                Box::pin(async move {
                    eprintln!("[fj-debug pid={}] pc state: {st:?}", std::process::id());
                })
            }));
        }

        // answer side: channels arrive via on_data_channel
        {
            let state = state.clone();
            pc.on_data_channel(Box::new(move |dc| {
                let state = state.clone();
                Box::pin(async move {
                    if let Some(idx) = channel_index(dc.label()) {
                        wire_channel(&dc, idx, &state);
                        let mut channels = state.channels.lock().await;
                        if idx >= channels.len() {
                            channels.resize(idx + 1, None);
                        }
                        channels[idx] = Some(dc.clone());
                    }
                })
            }));
        }

        Ok(Arc::new(PeerHandle {
            pc: pc.into(),
            state,
        }))
    }

    /// Offer side: create N channels, produce the offer SDP (waits for ICE
    /// gathering up to GATHER_TIMEOUT_MS, then continues with the candidates
    /// gathered so far).
    pub async fn create_offer(&self, channels: usize) -> PResult<String> {
        self.state.expected.store(channels, Ordering::SeqCst);
        {
            let mut ch = self.state.channels.lock().await;
            let mut cbs = self.state.cbs.lock().await;
            ch.clear();
            cbs.clear();
            ch.resize(channels, None);
            cbs.resize(channels, None);
        }
        self.state.opened.store(0, Ordering::SeqCst);
        for i in 0..channels {
            let init = RTCDataChannelInit {
                ordered: Some(true),
                ..Default::default()
            };
            let dc = self
                .pc
                .create_data_channel(&format!("fj-{i}"), Some(init))
                .await?;
            wire_channel(&dc, i, &self.state);
            let mut ch = self.state.channels.lock().await;
            ch[i] = Some(dc);
        }
        let offer = self.pc.create_offer(None).await?;
        self.pc.set_local_description(offer).await?;
        self.wait_gathering().await;
        let desc = self.pc.local_description().await.ok_or(PeerError::Failed)?;
        Ok(desc.sdp)
    }

    /// Answer side: apply the offer, answer, wait for gathering.
    pub async fn accept_offer(&self, offer_sdp: &str, channels: usize) -> PResult<String> {
        self.state.expected.store(channels, Ordering::SeqCst);
        {
            // keep any callbacks already installed (glue registers them
            // before applying the offer); just size the registry
            let mut cbs = self.state.cbs.lock().await;
            cbs.resize(channels, None);
        }
        self.pc
            .set_remote_description(RTCSessionDescription::offer(offer_sdp.to_string())?)
            .await?;
        let answer = self.pc.create_answer(None).await?;
        self.pc.set_local_description(answer).await?;
        self.wait_gathering().await;
        let desc = self.pc.local_description().await.ok_or(PeerError::Failed)?;
        Ok(desc.sdp)
    }

    /// Offer side: apply the remote answer.
    pub async fn set_answer(&self, answer_sdp: &str) -> PResult<()> {
        if std::env::var("FJ_DEBUG").is_ok() {
            let d = self.pc.local_description().await;
            let cands = d.map(|d| d.sdp.matches("candidate").count()).unwrap_or(0);
            eprintln!(
                "[fj-debug pid={}] set_answer: answer has {} candidate lines; local offer had {cands}",
                std::process::id(),
                answer_sdp.matches("candidate").count()
            );
        }
        self.pc
            .set_remote_description(RTCSessionDescription::answer(answer_sdp.to_string())?)
            .await?;
        Ok(())
    }

    async fn wait_gathering(&self) {
        let mut done = self.pc.gathering_complete_promise().await;
        let _ = tokio::time::timeout(Duration::from_millis(GATHER_TIMEOUT_MS), async move {
            let _ = done.recv().await;
        })
        .await;
        // on timeout: continue with the candidates gathered so far
    }

    /// Wait until all expected channels are open.
    pub async fn wait_channels_open(&self, timeout: Duration) -> PResult<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let expected = self.state.expected.load(Ordering::SeqCst);
            if expected > 0
                && self.state.opened.load(Ordering::SeqCst) >= expected
                && self.state.connected.load(Ordering::SeqCst)
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(PeerError::ChannelOpen);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Install a frame callback for channel `ch` (binary messages only).
    pub async fn on_frame(&self, ch: usize, cb: impl Fn(Vec<u8>) + Send + Sync + 'static) {
        let mut cbs = self.state.cbs.lock().await;
        if ch >= cbs.len() {
            cbs.resize(ch + 1, None);
        }
        cbs[ch] = Some(Arc::new(cb));
    }

    /// Send bytes on channel `ch`, honoring the backpressure watermark.
    pub async fn send_backpressured(&self, ch: usize, bytes: Vec<u8>) -> PResult<usize> {
        loop {
            let dc = self
                .state
                .channels
                .lock()
                .await
                .get(ch)
                .cloned()
                .flatten()
                .ok_or(PeerError::NoChannel)?;
            if (dc.buffered_amount().await as u64) < BACKPRESSURE_HIGH_BYTES {
                return Ok(dc.send(&bytes.into()).await?);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn buffered_amount(&self, ch: usize) -> PResult<usize> {
        let dc = self
            .state
            .channels
            .lock()
            .await
            .get(ch)
            .cloned()
            .flatten()
            .ok_or(PeerError::NoChannel)?;
        Ok(dc.buffered_amount().await)
    }

    /// Selected pair's local candidate type: "host" | "srflx" | "relay".
    pub async fn selected_candidate_type(&self) -> Option<String> {
        let report = self.pc.get_stats().await;
        selected_candidate_type(&report)
    }

    /// Transport stats for the UI.
    pub async fn stats(&self) -> Stats {
        let report = self.pc.get_stats().await;
        let mut out = Stats::default();
        for s in report.reports.values() {
            if let StatsReportType::CandidatePair(cp) = s {
                if let Some(rtt) =
                    (cp.current_round_trip_time > 0.0).then_some(cp.current_round_trip_time)
                {
                    out.rtt_ms = Some(rtt * 1000.0);
                }
                if cp.available_outgoing_bitrate > 0.0 {
                    out.mbps = Some(cp.available_outgoing_bitrate / 1_000_000.0);
                }
            }
        }
        out.candidate = selected_candidate_type(&report);
        out
    }

    pub async fn close(&self) -> PResult<()> {
        self.pc.close().await?;
        Ok(())
    }
}

/// Wire open/message handlers of a data channel into shared state.
fn wire_channel(
    dc: &Arc<webrtc::data_channel::RTCDataChannel>,
    idx: usize,
    state: &Arc<PeerState>,
) {
    {
        let state = state.clone();
        let dc2 = dc.clone();
        dc.on_open(Box::new(move || {
            let state = state.clone();
            Box::pin(async move {
                state.opened.fetch_add(1, Ordering::SeqCst);
                state.connected.store(true, Ordering::SeqCst);
                state.notify.notify_waiters();
                let _ = dc2;
            })
        }));
    }
    {
        let state = state.clone();
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            if !msg.is_string {
                let bytes = msg.data.to_vec();
                let cb = match state.cbs.try_lock() {
                    Ok(guard) => guard.get(idx).cloned().flatten(),
                    Err(_) => None,
                };
                if let Some(cb) = cb {
                    cb(bytes);
                }
            }
            Box::pin(async {})
        }));
    }
}

fn selected_candidate_type(report: &StatsReport) -> Option<String> {
    let mut local_id = None;
    for s in report.reports.values() {
        if let StatsReportType::CandidatePair(cp) = s
            && cp.nominated
            && format!("{:?}", cp.state).eq_ignore_ascii_case("succeeded")
        {
            local_id = Some(cp.local_candidate_id.clone());
        }
    }
    let local_id = local_id?;
    for s in report.reports.values() {
        if let StatsReportType::LocalCandidate(c) = s
            && c.id == local_id
        {
            return Some(format!("{:?}", c.candidate_type).to_lowercase());
        }
    }
    None
}

/// Loopback smoke: two peers in one process over host candidates.
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_host_candidates() {
        let a = PeerHandle::new(&IceConfig::default()).await.unwrap();
        let b = PeerHandle::new(&IceConfig::default()).await.unwrap();

        // NOTE: frame callbacks must never block (they run on runtime
        // threads); bridge out via a non-blocking std channel.
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        b.on_frame(0, move |bytes| {
            let _ = tx.send(bytes);
        })
        .await;

        let offer = a.create_offer(1).await.unwrap();
        assert!(offer.contains("m=application"), "SCTP data channel in SDP");
        let answer = b.accept_offer(&offer, 1).await.unwrap();
        a.set_answer(&answer).await.unwrap();

        a.wait_channels_open(Duration::from_secs(10)).await.unwrap();
        b.wait_channels_open(Duration::from_secs(10)).await.unwrap();

        a.send_backpressured(0, b"hello filejaunt".to_vec())
            .await
            .unwrap();
        let got = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(10)))
            .await
            .expect("join")
            .expect("frame arrives");
        assert_eq!(got, b"hello filejaunt");

        let cand = a.selected_candidate_type().await;
        assert!(
            cand.as_deref().is_none_or(|c| c == "host"),
            "host candidates only (no STUN), got {cand:?}"
        );
        a.close().await.unwrap();
        b.close().await.unwrap();
    }
}
