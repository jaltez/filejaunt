//! Minimal STUN client (RFC 5389 subset): Binding Request with the magic
//! cookie 0x2112A442 and a random 16-byte transaction id, XOR-MAPPED-ADDRESS
//! (IPv4/IPv6) parsing. Timeout 500 ms, 2 retransmits.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use fj_protocol::error::{ErrorCode, Result};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const STUN_TIMEOUT: Duration = Duration::from_millis(500);
pub const STUN_RETRIES: usize = 2;

/// Binding Request (20 bytes): type 0x0001, len 0, cookie, txid.
fn binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&0x0001u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg
}

fn io_err(ctx: &str, e: std::io::Error) -> fj_protocol::Error {
    fj_protocol::Error::new(ErrorCode::IceFailed, format!("{ctx}: {e}"))
}

/// Probe one STUN server; None on timeout/failure after retries.
pub fn stun_probe_one(url: &str) -> Option<SocketAddr> {
    let host_port = url.strip_prefix("stun:").unwrap_or(url);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(3478)),
        None => (host_port.to_string(), 3478),
    };
    let addr = (host.as_str(), port).to_socket_addrs().ok()?.next()?;
    probe_addr(addr).ok().flatten()
}

fn probe_addr(server: SocketAddr) -> Result<Option<SocketAddr>> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| crate::stun::io_err("udp bind", e))?;
    socket
        .connect(server)
        .map_err(|e| crate::stun::io_err("udp connect", e))?;
    let mut txid = [0u8; 12];
    let mut r = rand::rng();
    use rand::RngCore;
    r.fill_bytes(&mut txid);
    let req = binding_request(&txid);
    for _ in 0..=STUN_RETRIES {
        socket
            .send(&req)
            .map_err(|e| crate::stun::io_err("udp send", e))?;
        let mut buf = [0u8; 1024];
        socket.set_read_timeout(Some(STUN_TIMEOUT)).ok();
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(mapped) = parse_binding_response(&buf[..n], &txid) {
                    return Ok(Some(mapped));
                }
                // wrong txid or malformed: keep retrying
            }
            Err(_) => continue,
        }
    }
    Ok(None)
}

/// Probe several servers; each entry is None when that server did not answer.
pub fn stun_probe(urls: &[String]) -> Vec<Option<SocketAddr>> {
    urls.iter().map(|u| stun_probe_one(u)).collect()
}

/// Parse a Binding Success Response and extract XOR-MAPPED-ADDRESS.
pub fn parse_binding_response(msg: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if msg.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    if msg_type != 0x0101 {
        return None; // not a success response
    }
    let cookie = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if cookie != MAGIC_COOKIE || &msg[8..20] != txid {
        return None;
    }
    let mut off = 20;
    let end = msg.len();
    while off + 4 <= end {
        let atype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let alen = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;
        let val = off + 4;
        if val + alen > end {
            return None;
        }
        if atype == 0x0020 && alen >= 8 {
            // XOR-MAPPED-ADDRESS: family(1) xport(2) xaddr(4|16)
            let family = msg[val + 1];
            let port =
                u16::from_be_bytes([msg[val + 2], msg[val + 3]]) ^ (MAGIC_COOKIE >> 16) as u16;
            match family {
                0x01 => {
                    let mut ip = [0u8; 4];
                    let cookie_b = MAGIC_COOKIE.to_be_bytes();
                    for i in 0..4 {
                        ip[i] = msg[val + 4 + i] ^ cookie_b[i];
                    }
                    return Some(SocketAddr::from((std::net::Ipv4Addr::from(ip), port)));
                }
                0x02 => {
                    if alen < 20 {
                        return None;
                    }
                    let mut ip = [0u8; 16];
                    let mut mask = [0u8; 16];
                    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                    mask[4..16].copy_from_slice(&txid[..12]);
                    for i in 0..16 {
                        ip[i] = msg[val + 4 + i] ^ mask[i];
                    }
                    return Some(SocketAddr::from((std::net::Ipv6Addr::from(ip), port)));
                }
                _ => {}
            }
        }
        // attributes are padded to 4 bytes
        off = val + alen.div_ceil(4) * 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_mapped_response(txid: &[u8; 12], ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x0101u16.to_be_bytes());
        let attr_len = 8usize; // reserved(1) family(1) xport(2) xaddr(4)
        m.extend_from_slice(&(attr_len as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(txid);
        // XOR-MAPPED-ADDRESS
        m.extend_from_slice(&0x0020u16.to_be_bytes());
        m.extend_from_slice(&(attr_len as u16).to_be_bytes());
        m.push(0);
        m.push(0x01);
        let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
        m.extend_from_slice(&xport.to_be_bytes());
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for i in 0..4 {
            m.push(ip[i] ^ cookie[i]);
        }
        m
    }

    #[test]
    fn parses_xor_mapped_v4() {
        let txid = [7u8; 12];
        let msg = xor_mapped_response(&txid, [192, 168, 1, 42], 51234);
        let addr = parse_binding_response(&msg, &txid).expect("parsed");
        assert_eq!(addr.to_string(), "192.168.1.42:51234");
    }

    #[test]
    fn rejects_wrong_txid_and_type() {
        let txid = [7u8; 12];
        let msg = xor_mapped_response(&txid, [1, 2, 3, 4], 1);
        assert!(parse_binding_response(&msg, &[8u8; 12]).is_none());
        let mut bad = msg.clone();
        bad[1] = 0x11; // error response type
        assert!(parse_binding_response(&bad, &txid).is_none());
    }

    #[test]
    fn binding_request_shape() {
        let req = binding_request(&[1u8; 12]);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
    }
}
