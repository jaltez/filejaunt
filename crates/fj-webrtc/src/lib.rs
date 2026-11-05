//! fj-webrtc: WebRTC transport glue for filejaunt.
//!
//! - [`stun`]: minimal RFC 5389 STUN client (Binding Request, XOR-MAPPED-
//!   ADDRESS parsing) used by `doctor`.
//! - [`nat`]: NAT classification from two STUN probes.
//! - [`peer`]: webrtc-rs wrapper (`PeerHandle`) with host/srflx/relay
//!   candidates, N ordered reliable DataChannels and backpressure.

pub mod nat;
pub mod peer;
pub mod stun;

pub use nat::{NatClass, classify};
pub use peer::{IceConfig, PeerHandle, Stats};
