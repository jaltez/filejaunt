//! SPAKE2 pairing (Ed25519Group) and passphrase handling.
//!
//! Roles: the initiator (sender, offer side) is SPAKE2 side A, the responder
//! is side B; identities are the 16-byte session id. The shared secret feeds
//! `crypto::derive_root`.
//!
//! Wrong passphrases do NOT fail inside SPAKE2 (garbage-in/garbage-out);
//! they surface as AES-GCM authentication failures when the derived keys are
//! first used (envelope SDP decryption, HELO fingerprint), reported as
//! SEC_PAKE_FAILED. The receiver-side in-memory `AttemptLimiter` bounds
//! online guessing per session id at PAKE_ATTEMPT_LIMIT failures.

use std::collections::HashMap;

use rand::RngCore;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::error::{err, ErrorCode, Result};
use crate::PAKE_ATTEMPT_LIMIT;

pub const PAKE_MSG_LEN: usize = 1 + 32; // side byte + Ed25519 point

/// Canonical passphrase form: NFKD, combining marks stripped, lowercased,
/// trimmed, runs of whitespace/'-' collapsed to a single '-', no leading or
/// trailing separator.
pub fn canonical_passphrase(input: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let mut s: String = input
        .nfkd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .flat_map(|c| c.to_lowercase())
        .collect();
    s = s.trim().to_string();
    // collapse [\s-]+ -> '-'
    let mut out = String::with_capacity(s.len());
    let mut in_sep = false;
    for c in s.chars() {
        if c.is_whitespace() || c == '-' {
            in_sep = true;
        } else {
            if in_sep && !out.is_empty() {
                out.push('-');
            }
            in_sep = false;
            out.push(c);
        }
    }
    out
}

/// Fresh 16-byte session id from OsRng.
pub fn new_sid() -> [u8; 16] {
    let mut sid = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut sid);
    sid
}

/// A started SPAKE2 exchange. `message()` is the public PAKE message for the
/// pairing envelope; `finish` consumes the peer message and yields the raw
/// shared secret (feed it to `crypto::derive_root`).
pub struct PakeSide {
    inner: Option<Spake2<Ed25519Group>>,
    message: Vec<u8>,
}

impl PakeSide {
    pub fn start_initiator(passphrase_canonical: &[u8], sid: &[u8; 16]) -> PakeSide {
        let id = Identity::new(sid);
        let (ctx, msg) =
            Spake2::<Ed25519Group>::start_a(&Password::new(passphrase_canonical), &id, &id);
        PakeSide { inner: Some(ctx), message: msg }
    }

    pub fn start_responder(passphrase_canonical: &[u8], sid: &[u8; 16]) -> PakeSide {
        let id = Identity::new(sid);
        let (ctx, msg) =
            Spake2::<Ed25519Group>::start_b(&Password::new(passphrase_canonical), &id, &id);
        PakeSide { inner: Some(ctx), message: msg }
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    pub fn finish(mut self, peer_message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let ctx = self.inner.take().expect("finish called once");
        let out = ctx
            .finish(peer_message)
            .map_err(|e| err(ErrorCode::SecPakeFailed, format!("PAKE exchange failed: {e}")))?;
        self.message.zeroize();
        Ok(Zeroizing::new(out))
    }
}

/// Re-derive the SPAKE2 shared secret from the passphrase and both public
/// PAKE messages. Used by receipt verification and cross-implementation
/// (WASM) parity tests: given pake1 (side A msg) and pake2 (side B msg) and
/// the correct passphrase, the result equals the live session secret.
/// Both `finish` calls yield the same secret because side A computes
/// x*(Y - N) and side B computes y*(X + M) with matching password elements.
pub fn shared_secret_from_messages(
    passphrase_canonical: &[u8],
    sid: &[u8; 16],
    pake_msg_a: &[u8],
    pake_msg_b: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if pake_msg_a.len() != PAKE_MSG_LEN || pake_msg_b.len() != PAKE_MSG_LEN {
        return err(ErrorCode::SecPakeFailed, "PAKE message length invalid");
    }
    // Side A: start_a, finish with B's message.
    let a = PakeSide::start_initiator(passphrase_canonical, sid);
    let secret_a = a.finish(pake_msg_b)?;
    // Cross-check via side B: start_b, finish with A's message.
    let b = PakeSide::start_responder(passphrase_canonical, sid);
    let secret_b = b.finish(pake_msg_a)?;
    if !crate::crypto::ct_eq(&secret_a, &secret_b) {
        return err(ErrorCode::SecPakeFailed, "PAKE messages inconsistent");
    }
    Ok(secret_a)
}

/// In-memory, per-sid failed-PAKE counter for the receiver side.
#[derive(Default)]
pub struct AttemptLimiter {
    failures: HashMap<[u8; 16], u32>,
}

impl AttemptLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a failed attempt for `sid`. Returns `Err(SEC_ATTEMPT_LIMIT)`
    /// when the limit is reached (the session must be refused and closed).
    pub fn record_failure(&mut self, sid: &[u8; 16]) -> Result<()> {
        let n = self.failures.entry(*sid).or_insert(0);
        *n += 1;
        if *n >= PAKE_ATTEMPT_LIMIT {
            err(ErrorCode::SecAttemptLimit, "too many failed pairing attempts for this session id")
        } else {
            Ok(())
        }
    }

    pub fn failures(&self, sid: &[u8; 16]) -> u32 {
        self.failures.get(sid).copied().unwrap_or(0)
    }

    pub fn clear(&mut self, sid: &[u8; 16]) {
        self.failures.remove(sid);
    }
}
