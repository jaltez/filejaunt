//! Receipts: per-file transfer attestations.
//!
//! Wire RECEIPT frame: `{"file","sha256","bytes","ts","mac"}` where
//! `mac = HMAC-SHA256(K_receipt, lenprefix(u16 file) || lenprefix(hex sha256)
//! || lenprefix(u64 bytes) || lenprefix(i64 ts))` (little-endian integers,
//! the hex string as raw bytes).
//!
//! Exported receipt JSON (what `filejaunt verify` consumes):
//! `{"v":1,"sid":hex32,"pake1":b64,"pake2":b64,"file":...,"sha256":...,
//!   "bytes":...,"ts":...,"mac":b64,"macpf":b64}`
//!
//! DEVIATION D2 (documented): K_root cannot be re-derived offline from the
//! public PAKE messages (computational Diffie-Hellman), so the exported
//! receipt carries a second MAC `macpf` under
//! `K_pf = HKDF(canonical passphrase, sid, "filejaunt/v1/receipt-pf")`.
//! `verify` checks `macpf` with the passphrase. Holders of the passphrase
//! (i.e. both participants) can forge `macpf`; it binds the receipt to the
//! session passphrase and file contents for third parties who are told the
//! passphrase. The session-live `mac` (K_receipt) is verified by the sender
//! during the session.

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::PROTOCOL_VERSION;
use crate::crypto::{self, Key32};
use crate::error::{ErrorCode, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptMsg {
    pub file: u16,
    pub sha256: String,
    pub bytes: u64,
    pub ts: i64,
    /// base64 HMAC-SHA256 under K_receipt.
    pub mac: String,
}

/// Exported receipt file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    pub v: u8,
    pub sid: String,
    #[serde(default)]
    pub pake1: String,
    #[serde(default)]
    pub pake2: String,
    pub file: u16,
    pub sha256: String,
    pub bytes: u64,
    pub ts: i64,
    pub mac: String,
    #[serde(default)]
    pub macpf: String,
}

fn mac_input(file: u16, sha256_hex: &str, bytes: u64, ts: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    let mut push = |b: &[u8]| {
        buf.extend_from_slice(&(b.len() as u64).to_le_bytes());
        buf.extend_from_slice(b);
    };
    push(&file.to_le_bytes());
    push(sha256_hex.as_bytes());
    push(&bytes.to_le_bytes());
    push(&ts.to_le_bytes());
    buf
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Compute the K_receipt MAC for a receipt.
pub fn receipt_mac(k_receipt: &Key32, file: u16, sha256_hex: &str, bytes: u64, ts: i64) -> String {
    b64(&crypto::hmac_sha256(
        k_receipt.as_slice(),
        &mac_input(file, sha256_hex, bytes, ts),
    ))
}

/// Compute the passphrase-bound MAC.
pub fn receipt_mac_pf(k_pf: &Key32, file: u16, sha256_hex: &str, bytes: u64, ts: i64) -> String {
    b64(&crypto::hmac_sha256(
        k_pf.as_slice(),
        &mac_input(file, sha256_hex, bytes, ts),
    ))
}

/// Verify the K_receipt MAC of a wire receipt (constant time).
pub fn verify_receipt_mac(k_receipt: &Key32, msg: &ReceiptMsg) -> bool {
    let expect = receipt_mac(k_receipt, msg.file, &msg.sha256, msg.bytes, msg.ts);
    crypto::ct_eq(expect.as_bytes(), msg.mac.as_bytes())
}

impl Receipt {
    pub fn from_msg(
        msg: &ReceiptMsg,
        sid_hex: &str,
        pake1_b64: &str,
        pake2_b64: &str,
        mac_pf: &str,
    ) -> Receipt {
        Receipt {
            v: PROTOCOL_VERSION,
            sid: sid_hex.to_string(),
            pake1: pake1_b64.to_string(),
            pake2: pake2_b64.to_string(),
            file: msg.file,
            sha256: msg.sha256.clone(),
            bytes: msg.bytes,
            ts: msg.ts,
            mac: msg.mac.clone(),
            macpf: mac_pf.to_string(),
        }
    }

    /// Verify this receipt against a passphrase (any separator casing/form;
    /// canonicalized internally). Checks the passphrase-bound `macpf`.
    /// Structural validity (hex64, base64) is verified first.
    pub fn verify(&self, passphrase: &str) -> bool {
        if self.v != PROTOCOL_VERSION {
            return false;
        }
        if crate::manifest::validate_sha256(&self.sha256.to_lowercase()).is_err() {
            return false;
        }
        let Ok(sid) = crate::envelope::parse_sid(&self.sid) else {
            return false;
        };
        let canon = crate::pake::canonical_passphrase(passphrase);
        let k_pf = crypto::derive_receipt_pf(canon.as_bytes(), &sid);
        let expect = receipt_mac_pf(
            &k_pf,
            self.file,
            &self.sha256.to_lowercase(),
            self.bytes,
            self.ts,
        );
        crypto::ct_eq(expect.as_bytes(), self.macpf.as_bytes())
    }

    /// SHA-256 of the receipt file bytes (integrity id for humans).
    pub fn file_sha256(&self) -> Result<String> {
        let json = serde_json::to_string(self).map_err(|e| {
            crate::error::Error::new(ErrorCode::StorageFailed, format!("serialize receipt: {e}"))
        })?;
        Ok(hex::encode(sha2::Sha256::digest(json.as_bytes())))
    }
}
