//! Wire frame format v1. 12-byte little-endian header + payload.
//!
//! ```text
//! [0]  u8  version (=1; mismatch -> PROTO_VERSION)
//! [1]  u8  type
//! [2]  u16 stream_id          (= file_id for CHUNK; 0 otherwise)
//! [4]  u32 seq               (CHUNK: chunk_index; control: monotonic per direction)
//! [8]  u32 length            (payload length; > 1<<20 -> PROTO_MALFORMED)
//! [12] payload[length]
//! ```
//!
//! One frame = one complete SCTP message. `decode` never panics on any input.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, Result, err};
use crate::frame::FrameType::*;
use crate::manifest::Manifest;
use crate::receipt::ReceiptMsg;
use crate::{FRAME_HEADER_LEN, MAX_TEXT_BYTES, PROTOCOL_VERSION};

pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    Manifest = 0x02,
    ChunkReq = 0x03,
    Chunk = 0x04,
    Bitmap = 0x05,
    Pause = 0x06,
    Resume = 0x07,
    Cancel = 0x08,
    Receipt = 0x09,
    Text = 0x0A,
    Error = 0x0B,
    Done = 0x0C,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<FrameType> {
        Some(match v {
            0x01 => Hello,
            0x02 => Manifest,
            0x03 => ChunkReq,
            0x04 => Chunk,
            0x05 => Bitmap,
            0x06 => Pause,
            0x07 => Resume,
            0x08 => Cancel,
            0x09 => Receipt,
            0x0A => Text,
            0x0B => Error,
            0x0C => Done,
            _ => return None,
        })
    }
}

/// Decoded frame. Payload-level validation is done here where cheap
/// (structure, sizes); semantic validation happens in `session`.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// HELO: first frame from each side (sent encrypted).
    Hello {
        role: u8,
        version: u8,
        fp: [u8; 32],
    },
    Manifest(Manifest),
    ChunkReq {
        file: u16,
        from: u64,
        to: u64,
    },
    Chunk {
        file: u16,
        index: u64,
        gzip: bool,
        data: Vec<u8>,
    },
    Bitmap {
        file: u16,
        runs: Vec<(u64, u64)>,
    },
    Pause {
        file: u16,
    },
    Resume {
        file: u16,
    },
    Cancel {
        file: u16,
    },
    Receipt(ReceiptMsg),
    Text(String),
    Error {
        code: ErrorCode,
        msg: String,
    },
    Done {
        file: u16,
    },
}

impl Frame {
    pub fn kind(&self) -> FrameType {
        match self {
            Frame::Hello { .. } => Hello,
            Frame::Manifest(_) => Manifest,
            Frame::ChunkReq { .. } => ChunkReq,
            Frame::Chunk { .. } => Chunk,
            Frame::Bitmap { .. } => Bitmap,
            Frame::Pause { .. } => Pause,
            Frame::Resume { .. } => Resume,
            Frame::Cancel { .. } => Cancel,
            Frame::Receipt(_) => Receipt,
            Frame::Text(_) => Text,
            Frame::Error { .. } => Error,
            Frame::Done { .. } => Done,
        }
    }

    /// stream_id header field: file id for CHUNK, 0 otherwise.
    fn stream_id(&self) -> u16 {
        match self {
            Frame::Chunk { file, .. } => *file,
            Frame::ChunkReq { file, .. }
            | Frame::Bitmap { file, .. }
            | Frame::Pause { file }
            | Frame::Resume { file }
            | Frame::Cancel { file }
            | Frame::Done { file } => *file,
            _ => 0,
        }
    }

    /// seq header field: chunk index for CHUNK; `seq` for control frames.
    fn seq(&self, seq: u32) -> u32 {
        match self {
            Frame::Chunk { index, .. } => *index as u32,
            _ => seq,
        }
    }

    /// Serialize header+payload. `seq` is the control-frame sequence number
    /// (monotonic per direction); CHUNK uses its chunk index instead.
    pub fn encode(&self, out: &mut Vec<u8>, seq: u32) {
        let payload_len_pos = out.len();
        out.resize(out.len() + FRAME_HEADER_LEN, 0);
        self.encode_payload(out);
        let payload_len = out.len() - payload_len_pos - FRAME_HEADER_LEN;
        let h = &mut out[payload_len_pos..payload_len_pos + FRAME_HEADER_LEN];
        h[0] = PROTOCOL_VERSION;
        h[1] = self.kind() as u8;
        h[2..4].copy_from_slice(&self.stream_id().to_le_bytes());
        h[4..8].copy_from_slice(&self.seq(seq).to_le_bytes());
        h[8..12].copy_from_slice(&(payload_len as u32).to_le_bytes());
    }

    pub fn encode_to_vec(&self, seq: u32) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v, seq);
        v
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Hello { role, version, fp } => {
                let j = serde_json::json!({"r": role, "v": version, "fp": b64(fp)});
                out.extend_from_slice(j.to_string().as_bytes());
            }
            Frame::Manifest(m) => {
                out.extend_from_slice(serde_json::to_string(m).unwrap().as_bytes());
            }
            Frame::ChunkReq { file, from, to } => {
                let j = serde_json::json!({"file": file, "from": from, "to": to});
                out.extend_from_slice(j.to_string().as_bytes());
            }
            Frame::Chunk {
                file,
                index,
                gzip,
                data,
            } => {
                let mut p = Vec::with_capacity(9 + data.len());
                p.extend_from_slice(&(*file as u32).to_le_bytes());
                p.extend_from_slice(&(*index as u32).to_le_bytes());
                p.push(u8::from(*gzip));
                p.extend_from_slice(&(data.len() as u16).to_le_bytes());
                p.extend_from_slice(data);
                out.extend_from_slice(&p);
            }
            Frame::Bitmap { file, runs } => {
                let j = serde_json::json!({
                    "file": file,
                    "runs": runs.iter().map(|(s, l)| vec![s, l]).collect::<Vec<_>>()
                });
                out.extend_from_slice(j.to_string().as_bytes());
            }
            Frame::Pause { file }
            | Frame::Resume { file }
            | Frame::Cancel { file }
            | Frame::Done { file } => {
                let j = serde_json::json!({"file": file});
                out.extend_from_slice(j.to_string().as_bytes());
            }
            Frame::Receipt(r) => {
                out.extend_from_slice(serde_json::to_string(r).unwrap().as_bytes());
            }
            Frame::Text(t) => out.extend_from_slice(t.as_bytes()),
            Frame::Error { code, msg } => {
                let j = serde_json::json!({"code": code.as_str(), "msg": msg});
                out.extend_from_slice(j.to_string().as_bytes());
            }
        }
    }

    /// Decode a complete frame (header + payload). Never panics.
    pub fn decode(bytes: &[u8]) -> Result<Frame> {
        if bytes.len() < FRAME_HEADER_LEN {
            return err(ErrorCode::ProtoMalformed, "frame shorter than header");
        }
        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return err(
                ErrorCode::ProtoVersion,
                format!("unsupported version {version}"),
            );
        }
        let ty = FrameType::from_u8(bytes[1]).ok_or_else(|| {
            crate::error::Error::new(
                ErrorCode::ProtoMalformed,
                format!("unknown frame type 0x{:02X}", bytes[1]),
            )
        })?;
        let length = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        if length > MAX_FRAME {
            return err(
                ErrorCode::ProtoMalformed,
                format!("frame length {length} exceeds {MAX_FRAME}"),
            );
        }
        let payload = &bytes[FRAME_HEADER_LEN..];
        if payload.len() != length {
            return err(
                ErrorCode::ProtoMalformed,
                "frame length field does not match buffer",
            );
        }
        match ty {
            Hello => {
                #[derive(Deserialize)]
                struct H {
                    r: u8,
                    v: u8,
                    fp: String,
                }
                let h: H = decode_json(payload)?;
                let fp = b64_decode(&h.fp, Some(32))?;
                let mut f = [0u8; 32];
                f.copy_from_slice(&fp);
                if h.v != PROTOCOL_VERSION {
                    return err(ErrorCode::ProtoVersion, "HELO protocol version mismatch");
                }
                Ok(Frame::Hello {
                    role: h.r,
                    version: h.v,
                    fp: f,
                })
            }
            Manifest => {
                let m: Manifest = serde_json::from_slice(payload).map_err(|e| {
                    crate::error::Error::new(
                        ErrorCode::ProtoMalformed,
                        format!("bad MANIFEST JSON: {e}"),
                    )
                })?;
                Ok(Frame::Manifest(m))
            }
            ChunkReq => {
                #[derive(Deserialize)]
                struct R {
                    file: u16,
                    from: u64,
                    to: u64,
                }
                let r: R = decode_json(payload)?;
                if r.to < r.from {
                    return err(ErrorCode::ProtoMalformed, "CHUNK_REQ range inverted");
                }
                Ok(Frame::ChunkReq {
                    file: r.file,
                    from: r.from,
                    to: r.to,
                })
            }
            Chunk => {
                if payload.len() < 9 {
                    return err(ErrorCode::ProtoMalformed, "CHUNK payload too short");
                }
                let file =
                    u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as u16;
                let index =
                    u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as u64;
                let gzip = payload[8] & 1 == 1;
                let data_len = u16::from_le_bytes([payload[9], payload[10]]) as usize;
                if payload.len() != 11 + data_len {
                    return err(
                        ErrorCode::ProtoMalformed,
                        "CHUNK data_len does not match payload",
                    );
                }
                Ok(Frame::Chunk {
                    file,
                    index,
                    gzip,
                    data: payload[11..].to_vec(),
                })
            }
            Bitmap => {
                #[derive(Deserialize)]
                struct B {
                    file: u16,
                    runs: Vec<(u64, u64)>,
                }
                let b: B = decode_json(payload)?;
                Ok(Frame::Bitmap {
                    file: b.file,
                    runs: b.runs,
                })
            }
            Pause => Ok(Frame::Pause {
                file: file_json(payload)?,
            }),
            Resume => Ok(Frame::Resume {
                file: file_json(payload)?,
            }),
            Cancel => Ok(Frame::Cancel {
                file: file_json(payload)?,
            }),
            Done => Ok(Frame::Done {
                file: file_json(payload)?,
            }),
            Receipt => {
                let r: ReceiptMsg = serde_json::from_slice(payload).map_err(|e| {
                    crate::error::Error::new(
                        ErrorCode::ProtoMalformed,
                        format!("bad RECEIPT JSON: {e}"),
                    )
                })?;
                Ok(Frame::Receipt(r))
            }
            Text => {
                if payload.len() > MAX_TEXT_BYTES {
                    return err(ErrorCode::ProtoMalformed, "TEXT exceeds 32 KiB");
                }
                let s = std::str::from_utf8(payload).map_err(|_| {
                    crate::error::Error::new(ErrorCode::ProtoMalformed, "TEXT is not UTF-8")
                })?;
                Ok(Frame::Text(s.to_string()))
            }
            Error => {
                #[derive(Deserialize)]
                struct E {
                    code: String,
                    msg: String,
                }
                let e: E = decode_json(payload)?;
                let code = ErrorCode::from_wire(&e.code).ok_or_else(|| {
                    crate::error::Error::new(
                        ErrorCode::ProtoMalformed,
                        format!("unknown error code {}", e.code),
                    )
                })?;
                Ok(Frame::Error { code, msg: e.msg })
            }
        }
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T> {
    serde_json::from_slice(payload).map_err(|e| {
        crate::error::Error::new(ErrorCode::ProtoMalformed, format!("bad JSON payload: {e}"))
    })
}

fn file_json(payload: &[u8]) -> Result<u16> {
    #[derive(Deserialize)]
    struct F {
        file: u16,
    }
    let f: F = decode_json(payload)?;
    Ok(f.file)
}

pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str, expect: Option<usize>) -> Result<Vec<u8>> {
    use base64::Engine;
    let v = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| crate::error::Error::new(ErrorCode::ProtoMalformed, "invalid base64"))?;
    if let Some(n) = expect
        && v.len() != n
    {
        return err(
            ErrorCode::ProtoMalformed,
            format!("expected {n} bytes, got {}", v.len()),
        );
    }
    Ok(v)
}

/// Serialize a UTF-8 SDP/text as (used by vectors and tests).
#[derive(Serialize, Deserialize)]
pub struct WireHello {
    pub r: u8,
    pub v: u8,
    pub fp: String,
}
