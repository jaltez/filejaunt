//! common lib for fuzz targets.
//!
//! TEST-ONLY key material pinned from `tests/vectors/protocol.json`
//! (recorded SPAKE2 shared secret + sid). Per the vector file's own note
//! these unlock nothing outside that file: real sessions derive fresh keys
//! from fresh SPAKE2 runs. They let fuzz targets reach the AEAD/MAC code
//! with a fixed key so mutations land in the crypto, not the PAKE.

/// Offer SDP used by the native test loopback (tests/common/mod.rs).
pub const OFFER_SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=filejaunt-test-offer\r\n";
/// Answer SDP used by the native test loopback.
pub const ANSWER_SDP: &str = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=filejaunt-test-answer\r\n";

/// Vector sid ("4242...42").
pub const TEST_SID: [u8; 16] = [0x42; 16];
/// Vector SPAKE2 shared secret (hex).
pub const TEST_SPAKE_SECRET_HEX: &str =
    "fe3d084d91006f32557506e17ea4e647cd27c287319ce1f81270a41a5de4ebfb";
/// Vector passphrase (receipt verify seeds).
pub const VECTOR_PASSPHRASE: &str = "alpha bravo charlie delta vector";

/// K_root derived from the fixed vector values.
pub fn test_root() -> fj_protocol::crypto::Key32 {
    fj_protocol::crypto::derive_root(&hex_decode(TEST_SPAKE_SECRET_HEX), &TEST_SID)
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Deterministic hex64 string shaped like a SHA-256 digest (not a real hash).
pub fn fake_sha256(seed: u64) -> String {
    let mut x = seed | 1;
    let mut out = String::with_capacity(64);
    for _ in 0..8 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push_str(&format!("{:08x}", x as u32));
    }
    out
}

/// Sequential reader over fuzz bytes: missing bytes read as 0, never panics.
pub struct Rd<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Rd { d, p: 0 }
    }

    pub fn u8(&mut self) -> u8 {
        let b = self.d.get(self.p).copied().unwrap_or(0);
        self.p += 1;
        b
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.u8(),
            self.u8(),
            self.u8(),
            self.u8(),
            self.u8(),
            self.u8(),
            self.u8(),
            self.u8(),
        ])
    }

    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let s = self.d.get(self.p..).unwrap_or(&[]);
        let n = n.min(s.len());
        self.p += n;
        &s[..n]
    }

    pub fn str(&mut self, n: usize) -> String {
        String::from_utf8_lossy(self.bytes(n)).into_owned()
    }

    pub fn done(&self) -> bool {
        self.p >= self.d.len()
    }
}
