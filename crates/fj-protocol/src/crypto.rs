//! Crypto core. Nothing homegrown: SPAKE2 (Ed25519Group), HKDF-SHA256,
//! HMAC-SHA256, AES-256-GCM, constant-time comparison via `subtle`,
//! key zeroization via `zeroize`.
//!
//! Exact derivation (wire v1):
//!
//! ```text
//! sid       = 16 random bytes (initiator, OsRng)
//! K_root    = HKDF-SHA256(ikm = spake2_shared_secret, salt = sid, info = "filejaunt/v1/root", 32)
//! K_dir_ep  = HKDF-SHA256(ikm = K_root, salt = sid, info = "filejaunt/v1/dir/{d}/epoch/{e}", 32)
//!             d: 1 = initiator->responder, 2 = responder->initiator; e = epoch
//! K_confirm = HKDF-SHA256(ikm = K_root, salt = sid, info = "filejaunt/v1/confirm", 32)
//! K_receipt = HKDF-SHA256(ikm = K_root, salt = sid, info = "filejaunt/v1/receipt", 32)
//! K_env     = HKDF-SHA256(ikm = K_root, salt = sid, info = "filejaunt/v1/envelope", 32)
//! K_env_o   = HKDF-SHA256(ikm = K_env,   salt = sid, info = "filejaunt/v1/envelope/offer", 32)
//! K_env_a   = HKDF-SHA256(ikm = K_env,   salt = sid, info = "filejaunt/v1/envelope/answer", 32)
//! ```
//!
//! DEVIATION D1 (documented): the plan specified a single K_env with a fixed
//! zero nonce for both the encrypted offer and the encrypted answer in
//! private (3-step) mode. Encrypting two different plaintexts under the same
//! key+nonce breaks GCM. We keep the zero nonce (single use per key) but
//! derive separate subkeys K_env_o / K_env_a for offer and answer. Wire
//! format and UX are unchanged.
//!
//! Frame encryption: AES-256-GCM with K_dir_ep. Nonce (12 B) =
//! `epoch u32 LE || dir u32 LE || counter u32 LE`. Counter = index of the
//! encrypted frame in that direction/epoch (starts at 0, resets with a new
//! epoch — epoch is part of the nonce, so nonces are never reused).
//! AAD = the 12-byte cleartext frame header. Every frame, HELO included,
//! travels as: `header || ciphertext(payload) || tag`.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};

pub type Key32 = Zeroizing<[u8; 32]>;
pub type HmacSha256 = Hmac<Sha256>;

/// Direction of a unidirectional key: 1 = initiator->responder, 2 = responder->initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    InitiatorToResponder = 1,
    ResponderToInitiator = 2,
}

impl Dir {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

const ROOT_INFO: &[u8] = b"filejaunt/v1/root";
const CONFIRM_INFO: &[u8] = b"filejaunt/v1/confirm";
const RECEIPT_INFO: &[u8] = b"filejaunt/v1/receipt";
const ENV_INFO: &[u8] = b"filejaunt/v1/envelope";
const ENV_OFFER_INFO: &[u8] = b"filejaunt/v1/envelope/offer";
const ENV_ANSWER_INFO: &[u8] = b"filejaunt/v1/envelope/answer";

fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut()).expect("32-byte OKM is valid");
    okm
}

fn dir_info(dir: Dir, epoch: u32) -> Vec<u8> {
    format!("filejaunt/v1/dir/{}/epoch/{}", dir.as_u32(), epoch).into_bytes()
}

pub fn derive_root(shared_secret: &[u8], sid: &[u8; 16]) -> Key32 {
    hkdf_derive(shared_secret, sid, ROOT_INFO)
}

pub fn derive_dir_key(root: &Key32, sid: &[u8; 16], dir: Dir, epoch: u32) -> Key32 {
    hkdf_derive(root.as_slice(), sid, &dir_info(dir, epoch))
}

pub fn derive_confirm(root: &Key32, sid: &[u8; 16]) -> Key32 {
    hkdf_derive(root.as_slice(), sid, CONFIRM_INFO)
}

pub fn derive_receipt(root: &Key32, sid: &[u8; 16]) -> Key32 {
    hkdf_derive(root.as_slice(), sid, RECEIPT_INFO)
}

fn derive_env_sub(root: &Key32, sid: &[u8; 16], info: &[u8]) -> Key32 {
    let env = hkdf_derive(root.as_slice(), sid, ENV_INFO);
    hkdf_derive(env.as_slice(), sid, info)
}

pub fn derive_env_offer(root: &Key32, sid: &[u8; 16]) -> Key32 {
    derive_env_sub(root, sid, ENV_OFFER_INFO)
}

pub fn derive_env_answer(root: &Key32, sid: &[u8; 16]) -> Key32 {
    derive_env_sub(root, sid, ENV_ANSWER_INFO)
}

/// Passphrase-bound receipt key (DEVIATION D2, documented): SPAKE2 shared
/// secrets cannot be re-derived offline from the public PAKE messages (CDH),
/// so the exported receipt carries an additional MAC under
/// `K_pf = HKDF(ikm = canonical passphrase, salt = sid,
/// info = "filejaunt/v1/receipt-pf", 32)` for offline `verify` with the
/// passphrase. Anyone holding the passphrase can forge this MAC; it is
/// binding between the two session participants only.
const RECEIPT_PF_INFO: &[u8] = b"filejaunt/v1/receipt-pf";

pub fn derive_receipt_pf(passphrase_canonical: &[u8], sid: &[u8; 16]) -> Key32 {
    hkdf_derive(passphrase_canonical, sid, RECEIPT_PF_INFO)
}

/// HMAC-SHA256(key, data).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// `u64 LE || bytes` length prefix used in confirm-fingerprint and MAC inputs.
fn lenprefix(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
}

/// HELO fingerprint: HMAC-SHA256(K_confirm,
/// lenprefix(offer_sdp) || lenprefix(answer_sdp) || sid).
pub fn confirm_fp(
    k_confirm: &Key32,
    offer_sdp: &str,
    answer_sdp: &str,
    sid: &[u8; 16],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(offer_sdp.len() + answer_sdp.len() + 48);
    lenprefix(&mut buf, offer_sdp.as_bytes());
    lenprefix(&mut buf, answer_sdp.as_bytes());
    buf.extend_from_slice(sid);
    let tag = hmac_sha256(k_confirm.as_slice(), &buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

fn frame_nonce(epoch: u32, dir: Dir, counter: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&epoch.to_le_bytes());
    n[4..8].copy_from_slice(&dir.as_u32().to_le_bytes());
    n[8..12].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Encrypt a frame payload. Returns `ciphertext || tag`; the 12-byte header
/// travels in the clear (it is the AAD).
pub fn encrypt_frame(
    key: &Key32,
    epoch: u32,
    dir: Dir,
    counter: u32,
    header: &[u8; 12],
    payload: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new((&**key).into());
    cipher
        .encrypt(
            &Nonce::from(frame_nonce(epoch, dir, counter)),
            Payload {
                msg: payload,
                aad: header,
            },
        )
        .expect("AES-GCM encryption cannot fail")
}

/// Decrypt a frame payload (`ciphertext || tag`). Fails with
/// PROTO_MALFORMED ("frame authentication failed") on any tamper or desync.
pub fn decrypt_frame(
    key: &Key32,
    epoch: u32,
    dir: Dir,
    counter: u32,
    header: &[u8; 12],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new((&**key).into());
    cipher
        .decrypt(
            &Nonce::from(frame_nonce(epoch, dir, counter)),
            Payload {
                msg: ct,
                aad: header,
            },
        )
        .map_err(|_| {
            crate::error::Error::new(
                ErrorCode::ProtoMalformed,
                "frame authentication failed (tamper or desync)",
            )
        })
}

/// Envelope SDP encryption: AES-256-GCM, zero nonce (single use per key),
/// AAD = label ("sdp-offer" / "sdp-answer").
pub fn encrypt_sdp(key: &Key32, label: &str, sdp: &str) -> Vec<u8> {
    let cipher = Aes256Gcm::new((&**key).into());
    cipher
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: sdp.as_bytes(),
                aad: label.as_bytes(),
            },
        )
        .expect("AES-GCM encryption cannot fail")
}

pub fn decrypt_sdp(key: &Key32, label: &str, ct: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new((&**key).into());
    let pt = cipher
        .decrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: ct,
                aad: label.as_bytes(),
            },
        )
        .map_err(|_| {
            crate::error::Error::new(
                ErrorCode::SecPakeFailed,
                "SDP envelope authentication failed",
            )
        })?;
    String::from_utf8(pt)
        .map_err(|_| crate::error::Error::new(ErrorCode::ProtoMalformed, "SDP is not UTF-8"))
}

/// Constant-time equality for MACs / fingerprints.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// SHA-256 of concatenated parts (convenience).
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
