//! filejaunt core protocol (pure, sans-IO).
//!
//! Wire protocol v1: framing, crypto derivation, PAKE pairing envelopes,
//! manifest validation, chunk bitmaps, receipts and the transfer state
//! machine. This crate performs no I/O; glue crates (CLI, WASM) drive it.

pub mod bitmap;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod manifest;
pub mod pake;
pub mod receipt;
pub mod session;
pub mod words;

pub use bitmap::Bitmap;
pub use error::{Error, ErrorCode};
pub use frame::{Frame, FrameType};
pub use manifest::{FileEntry, GzipPolicy, Manifest};
pub use receipt::{Receipt, ReceiptMsg};
pub use session::{Action, Role, Session, SessionOpts};

// ---------------------------------------------------------------------------
// Protocol constants (wire v1). Exact values; do not change casually.
// ---------------------------------------------------------------------------

pub const PROTOCOL_VERSION: u8 = 1;

/// Default chunk size for file data.
pub const CHUNK_SIZE_DEFAULT: u32 = 16 * 1024;
/// Hard maximum chunk payload. 64 KiB; the 65519 variant is only negotiated
/// when the remote SCTP `maxMessageSize` >= 65553.
pub const CHUNK_SIZE_MAX: u32 = 64 * 1024;
/// Large chunk size usable only when negotiated (fits SCTP 65536 minus frame overhead).
pub const CHUNK_SIZE_LARGE: u32 = 65519;

/// Frame header: version(1) type(1) stream_id(2) seq(4) length(4).
pub const FRAME_HEADER_LEN: usize = 12;

pub const WORDS_DEFAULT: usize = 6;
pub const WORDS_MIN: usize = 4;
pub const WORDS_MAX: usize = 12;

/// Backpressure watermarks applied by glue (not the core).
pub const BACKPRESSURE_HIGH_BYTES: u64 = 1 << 20;
pub const BACKPRESSURE_LOW_BYTES: u64 = 256 << 10;

/// ICE gathering completion timeout applied by glue.
pub const GATHER_TIMEOUT_MS: u64 = 10_000;

/// Failed PAKE attempts allowed per session id (receiver side, in-memory).
pub const PAKE_ATTEMPT_LIMIT: u32 = 3;

pub const MAX_FILES: usize = 4096;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_TEXT_BYTES: usize = 32 * 1024;

pub const CHANNELS_MAX: usize = 4;
pub const RECEIVERS_MAX: usize = 4;

/// Persist a state snapshot every N chunks (applied by the session machine).
pub const SAVE_EVERY_CHUNKS: u64 = 256;

/// `file` value in PAUSE/RESUME/CANCEL meaning "all files".
pub const FILE_ALL: u16 = 65535;

/// Maximum decompressed envelope size (blob JSON after gunzip).
pub const ENVELOPE_MAX_JSON: usize = 64 * 1024;

/// Chunk size in bytes that must fit in the CHUNK payload `data_len` u16.
pub const MAX_CHUNK_DATA: usize = 65535;
