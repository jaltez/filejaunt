//! NAT classification from STUN probe results.

use std::net::SocketAddr;

use fj_protocol::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClass {
    /// No response needed / same address: direct connection likely.
    Direct,
    /// Same public ip:port seen from two servers: full/cone NAT, direct P2P
    /// should work.
    Cone,
    /// Different mapping per destination: symmetric NAT; direct P2P will
    /// probably fail; TURN or another network needed.
    Symmetric,
    /// UDP blocked entirely.
    UdpBlocked,
}

/// Classify from two probe results (`None` = server did not answer).
pub fn classify(results: &[Option<SocketAddr>]) -> NatClass {
    let answered: Vec<&SocketAddr> = results.iter().flatten().collect();
    if answered.is_empty() {
        return NatClass::UdpBlocked;
    }
    let first = answered[0];
    if answered.len() == 1 {
        // only one server answered: cannot distinguish, assume cone-ish
        return NatClass::Cone;
    }
    let all_same = answered.iter().all(|a| **a == *first);
    if all_same {
        NatClass::Cone
    } else {
        let same_ip = answered.iter().all(|a| a.ip() == first.ip());
        if same_ip {
            // same ip, different port per destination -> symmetric behavior
            NatClass::Symmetric
        } else {
            NatClass::Symmetric
        }
    }
}

impl NatClass {
    /// Human explanation (product strings, English).
    pub fn description(&self) -> &'static str {
        match self {
            NatClass::Direct => "Direct: no NAT traversal needed; direct P2P will work.",
            NatClass::Cone => {
                "Cone NAT: same public address from multiple servers; direct P2P should work."
            }
            NatClass::Symmetric => {
                "Symmetric NAT likely: direct P2P will probably fail; use a TURN server or another network."
            }
            NatClass::UdpBlocked => {
                "UDP blocked: WebRTC cannot connect; try another network or a TURN server over TCP."
            }
        }
    }

    pub fn short(&self) -> &'static str {
        match self {
            NatClass::Direct => "DIRECT",
            NatClass::Cone => "CONE",
            NatClass::Symmetric => "SYMMETRIC",
            NatClass::UdpBlocked => "UDP-BLOCKED",
        }
    }
}

/// Convenience: classify(results) + Result of the probe run.
pub fn classify_result(results: Vec<Option<SocketAddr>>) -> Result<NatClass> {
    Ok(classify(&results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(a: u8, b: u8) -> Option<SocketAddr> {
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(77, 12, a, b),
            40000,
        )))
    }

    #[test]
    fn classification() {
        let none: Option<SocketAddr> = None;
        assert_eq!(classify(&[none, none]), NatClass::UdpBlocked);
        assert_eq!(classify(&[addr(1, 1), addr(1, 1)]), NatClass::Cone);
        // same ip, different port
        let p1 = Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(77, 12, 1, 1),
            40001,
        )));
        let p2 = Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(77, 12, 1, 1),
            40002,
        )));
        assert_eq!(classify(&[p1, p2]), NatClass::Symmetric);
        assert_eq!(classify(&[addr(1, 1), addr(2, 2)]), NatClass::Symmetric);
        assert_eq!(classify(&[addr(1, 1), none]), NatClass::Cone);
    }
}
