//! Error codes. The `ErrorCode` strings are EXACT wire/CLI identifiers;
//! CLI exit codes map onto them (see fj-cli).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    SecHelloMismatch,
    SecPakeFailed,
    SecAttemptLimit,
    ProtoVersion,
    ProtoMalformed,
    PathRejected,
    HashMismatch,
    BitmapCorrupt,
    PeerCancel,
    IceFailed,
    StorageFailed,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::SecHelloMismatch => "SEC_HELLO_MISMATCH",
            ErrorCode::SecPakeFailed => "SEC_PAKE_FAILED",
            ErrorCode::SecAttemptLimit => "SEC_ATTEMPT_LIMIT",
            ErrorCode::ProtoVersion => "PROTO_VERSION",
            ErrorCode::ProtoMalformed => "PROTO_MALFORMED",
            ErrorCode::PathRejected => "PATH_REJECTED",
            ErrorCode::HashMismatch => "HASH_MISMATCH",
            ErrorCode::BitmapCorrupt => "BITMAP_CORRUPT",
            ErrorCode::PeerCancel => "PEER_CANCEL",
            ErrorCode::IceFailed => "ICE_FAILED",
            ErrorCode::StorageFailed => "STORAGE_FAILED",
        }
    }

    pub fn from_wire(s: &str) -> Option<ErrorCode> {
        Some(match s {
            "SEC_HELLO_MISMATCH" => ErrorCode::SecHelloMismatch,
            "SEC_PAKE_FAILED" => ErrorCode::SecPakeFailed,
            "SEC_ATTEMPT_LIMIT" => ErrorCode::SecAttemptLimit,
            "PROTO_VERSION" => ErrorCode::ProtoVersion,
            "PROTO_MALFORMED" => ErrorCode::ProtoMalformed,
            "PATH_REJECTED" => ErrorCode::PathRejected,
            "HASH_MISMATCH" => ErrorCode::HashMismatch,
            "BITMAP_CORRUPT" => ErrorCode::BitmapCorrupt,
            "PEER_CANCEL" => ErrorCode::PeerCancel,
            "ICE_FAILED" => ErrorCode::IceFailed,
            "STORAGE_FAILED" => ErrorCode::StorageFailed,
            _ => return None,
        })
    }

    /// CLI exit code per plan: 0 ok, 2 usage (clap), 3 security, 4 ICE/network,
    /// 5 storage, 1 everything else.
    pub fn exit_code(&self) -> i32 {
        match self {
            ErrorCode::SecHelloMismatch
            | ErrorCode::SecPakeFailed
            | ErrorCode::SecAttemptLimit => 3,
            ErrorCode::IceFailed => 4,
            ErrorCode::StorageFailed => 5,
            _ => 1,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{code}: {msg}")]
    Code { code: ErrorCode, msg: String },
}

impl Error {
    pub fn new(code: ErrorCode, msg: impl Into<String>) -> Error {
        Error::Code { code, msg: msg.into() }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Code { code, .. } => code.clone(),
        }
    }

    pub fn msg(&self) -> &str {
        match self {
            Error::Code { msg, .. } => msg,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn err<T>(code: ErrorCode, msg: impl Into<String>) -> Result<T> {
    Err(Error::new(code, msg))
}
