//! Pairing envelopes. Envelope = `"FJ1." ++ base64url_nopad(gzip(UTF-8 JSON))`.
//!
//! Two modes:
//! - **p2** (default, 2 pastes): blob1 carries the offer SDP in the clear,
//!   blob2 carries the answer encrypted under K_env_a.
//! - **p3** (private, 4 pastes): no SDP in clear anywhere; offer and answer
//!   travel encrypted (blobs 3 and 4).
//!
//! Parse path: strip prefix, strict base64url-nopad decode, gunzip with a
//! 64 KiB decompressed limit, strict JSON. Anything else is PROTO_MALFORMED.

use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::error::{ErrorCode, Result, err};
use crate::{ENVELOPE_MAX_JSON, PROTOCOL_VERSION};

pub const ENVELOPE_PREFIX: &str = "FJ1.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingMode {
    /// 2-step: offer SDP in clear inside blob-1.
    P2,
    /// 3-step private: all SDP encrypted (blobs 1..4).
    P3,
}

/// Envelope 1 (initiator -> responder).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope1 {
    pub v: u8,
    /// 32 hex chars (16-byte sid).
    pub sid: String,
    /// base64 SPAKE2 message (side A).
    pub pake: String,
    /// Clear offer SDP (p2 mode only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    pub ep: u32,
    /// "p2" | "p3".
    pub mode: String,
}

/// Envelope 2 (responder -> initiator).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope2 {
    pub v: u8,
    /// base64 SPAKE2 message (side B).
    pub pake: String,
    /// Encrypted answer SDP (p2 mode only): b64(ciphertext||tag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdpe: Option<String>,
}

/// Envelope 3 (initiator -> responder, p3 only): encrypted offer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope3 {
    pub v: u8,
    pub sdpe: String,
}

/// Envelope 4 (responder -> initiator, p3 only): encrypted answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope4 {
    pub v: u8,
    pub sdpe: String,
}

/// Any envelope (fuzz surface).
#[derive(Debug, Clone, PartialEq)]
pub enum Envelope {
    One(Envelope1),
    Two(Envelope2),
    Three(Envelope3),
    Four(Envelope4),
}

impl Envelope {
    pub fn parse(raw: &str) -> Result<Envelope> {
        let json = inflate(raw)?;
        if let Some(env1) = try_one(&json)? {
            return Ok(Envelope::One(env1));
        }
        if let Ok(e2) = serde_json::from_str::<Envelope2>(&json)
            && e2.pake.len() <= 4096
            && json.contains("\"pake\"")
        {
            return Ok(Envelope::Two(e2));
        }
        if let Ok(e3) = serde_json::from_str::<Envelope3>(&json)
            && json.contains("\"sdpe\"")
            && !json.contains("\"pake\"")
        {
            // Envelope 3 and 4 share their shape; callers validate which step
            // of the flow they are in.
            return Ok(Envelope::Three(e3));
        }
        err(
            ErrorCode::ProtoMalformed,
            "envelope JSON does not match any known shape",
        )
    }
}

fn try_one(json: &str) -> Result<Option<Envelope1>> {
    if !json.contains("\"sid\"") {
        return Ok(None);
    }
    let e: Envelope1 = serde_json::from_str(json).map_err(|e| {
        crate::error::Error::new(
            ErrorCode::ProtoMalformed,
            format!("bad envelope-1 JSON: {e}"),
        )
    })?;
    Ok(Some(e))
}

/// Envelope-1 structural validation (sid hex32, mode, ep, v).
pub fn validate_env1(e: &Envelope1) -> Result<([u8; 16], PairingMode)> {
    if e.v != PROTOCOL_VERSION {
        return err(ErrorCode::ProtoVersion, "envelope version mismatch");
    }
    let sid = parse_sid(&e.sid)?;
    let mode = match e.mode.as_str() {
        "p2" => PairingMode::P2,
        "p3" => PairingMode::P3,
        other => {
            return err(
                ErrorCode::ProtoMalformed,
                format!("unknown pairing mode {other:?}"),
            );
        }
    };
    if e.pake.len() > 4096 {
        return err(ErrorCode::ProtoMalformed, "pake message too large");
    }
    Ok((sid, mode))
}

pub fn parse_sid(hex32: &str) -> Result<[u8; 16]> {
    let mut sid = [0u8; 16];
    hex::decode_to_slice(hex32, &mut sid).map_err(|_| {
        crate::error::Error::new(ErrorCode::ProtoMalformed, "sid must be 32 hex chars")
    })?;
    Ok(sid)
}

pub fn sid_hex(sid: &[u8; 16]) -> String {
    hex::encode(sid)
}

/// gzip + base64url-nopad with the FJ1. prefix.
pub fn serialize<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_string(value).map_err(|e| {
        crate::error::Error::new(ErrorCode::StorageFailed, format!("serialize: {e}"))
    })?;
    if json.len() > ENVELOPE_MAX_JSON {
        return err(ErrorCode::ProtoMalformed, "envelope JSON exceeds 64 KiB");
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    let gz = enc
        .write_all(json.as_bytes())
        .and_then(|_| enc.finish())
        .map_err(|e| crate::error::Error::new(ErrorCode::StorageFailed, format!("gzip: {e}")))?;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&gz);
    Ok(format!("{ENVELOPE_PREFIX}{b64}"))
}

/// Strip prefix, strict b64url decode, gunzip (<= 64 KiB), return JSON string.
pub fn inflate(raw: &str) -> Result<String> {
    let raw = raw.trim();
    let body = raw.strip_prefix(ENVELOPE_PREFIX).ok_or_else(|| {
        crate::error::Error::new(ErrorCode::ProtoMalformed, "missing FJ1. prefix")
    })?;
    use base64::Engine;
    let gz = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| {
            crate::error::Error::new(ErrorCode::ProtoMalformed, "invalid base64url in envelope")
        })?;
    let dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut out = Vec::new();
    // Read at most limit+1 so oversized payloads are detected.
    let mut limited = dec.take((ENVELOPE_MAX_JSON + 1) as u64);
    limited.read_to_end(&mut out).map_err(|_| {
        crate::error::Error::new(ErrorCode::ProtoMalformed, "invalid gzip in envelope")
    })?;
    if out.len() > ENVELOPE_MAX_JSON {
        return err(
            ErrorCode::ProtoMalformed,
            "envelope decompressed exceeds 64 KiB",
        );
    }
    String::from_utf8(out).map_err(|_| {
        crate::error::Error::new(ErrorCode::ProtoMalformed, "envelope JSON is not UTF-8")
    })
}

pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| {
            crate::error::Error::new(ErrorCode::ProtoMalformed, "invalid base64 in envelope")
        })
}
