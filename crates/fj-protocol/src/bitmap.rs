//! Chunk bitmap with run-length encoding. Own fixed-bitset (Vec<u64>).
//!
//! Invalid runs (unordered, overlapping, zero-length, out of range) are
//! BITMAP_CORRUPT — never a panic.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, Result, err};

#[derive(Debug, Clone, PartialEq)]
pub struct Bitmap {
    words: Vec<u64>,
    len: u64,
}

impl Bitmap {
    pub fn new(len: u64) -> Bitmap {
        let words = (len as usize).div_ceil(64);
        Bitmap {
            words: vec![0u64; words],
            len,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, i: u64) -> bool {
        if i >= self.len {
            return false;
        }
        self.words[(i / 64) as usize] >> (i % 64) & 1 == 1
    }

    pub fn set(&mut self, i: u64, v: bool) {
        if i >= self.len {
            return;
        }
        let w = &mut self.words[(i / 64) as usize];
        let bit = 1u64 << (i % 64);
        if v {
            *w |= bit;
        } else {
            *w &= !bit;
        }
    }

    pub fn count_ones(&self) -> u64 {
        self.words.iter().map(|w| w.count_ones() as u64).sum()
    }

    /// Number of bits set in the union with `other` (same length required).
    pub fn union_count(&self, other: &Bitmap) -> u64 {
        if other.words.len() != self.words.len() {
            return self.count_ones();
        }
        self.words
            .iter()
            .zip(other.words.iter())
            .map(|(a, b)| (a | b).count_ones() as u64)
            .sum()
    }

    pub fn is_full(&self) -> bool {
        if self.len == 0 {
            return true;
        }
        self.count_ones() == self.len
    }

    /// Runs of SET bits: ordered, non-overlapping, len >= 1.
    pub fn to_runs(&self) -> Vec<(u64, u64)> {
        let mut runs = Vec::new();
        let mut i = 0u64;
        while i < self.len {
            if self.get(i) {
                let start = i;
                while i < self.len && self.get(i) {
                    i += 1;
                }
                runs.push((start, i - start));
            } else {
                i += 1;
            }
        }
        runs
    }

    /// Missing ranges (start, len), at most `limit` runs.
    pub fn missing_ranges(&self, limit: usize) -> Vec<(u64, u64)> {
        let mut runs = Vec::new();
        let mut i = 0u64;
        while i < self.len && runs.len() < limit {
            if !self.get(i) {
                let start = i;
                while i < self.len && !self.get(i) {
                    i += 1;
                }
                runs.push((start, i - start));
            } else {
                i += 1;
            }
        }
        runs
    }

    /// Build from runs of SET bits. BITMAP_CORRUPT on disorder/overlap/
    /// zero-len/out-of-range.
    pub fn from_runs(len: u64, runs: &[(u64, u64)]) -> Result<Bitmap> {
        let mut b = Bitmap::new(len);
        let mut prev_end = 0u64;
        for &(start, l) in runs {
            if l == 0 {
                return err(ErrorCode::BitmapCorrupt, "zero-length run");
            }
            if start < prev_end {
                return err(ErrorCode::BitmapCorrupt, "runs unordered or overlapping");
            }
            if start.saturating_add(l) > len {
                return err(ErrorCode::BitmapCorrupt, "run out of range");
            }
            for i in start..start + l {
                b.set(i, true);
            }
            prev_end = start + l;
        }
        Ok(b)
    }

    /// Merge runs into self (mark those chunks present).
    pub fn merge_runs(&mut self, runs: &[(u64, u64)]) -> Result<()> {
        let mut prev_end = 0u64;
        for &(start, l) in runs {
            if l == 0 {
                return err(ErrorCode::BitmapCorrupt, "zero-length run");
            }
            if start < prev_end {
                return err(ErrorCode::BitmapCorrupt, "runs unordered or overlapping");
            }
            if start.saturating_add(l) > self.len {
                return err(ErrorCode::BitmapCorrupt, "run out of range");
            }
            for i in start..start + l {
                self.set(i, true);
            }
            prev_end = start + l;
        }
        Ok(())
    }

    /// First `count` unset indices at or after `from`.
    pub fn next_missing(&self, from: u64, count: usize) -> Vec<u64> {
        let mut out = Vec::new();
        let mut i = from;
        while i < self.len && out.len() < count {
            if !self.get(i) {
                out.push(i);
            }
            i += 1;
        }
        out
    }
}

/// Serializable snapshot of a bitmap (runs of set bits).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BitmapJson {
    pub len: u64,
    pub runs: Vec<(u64, u64)>,
}

impl From<&Bitmap> for BitmapJson {
    fn from(b: &Bitmap) -> Self {
        BitmapJson {
            len: b.len,
            runs: b.to_runs(),
        }
    }
}

impl BitmapJson {
    pub fn to_bitmap(&self) -> Result<Bitmap> {
        Bitmap::from_runs(self.len, &self.runs)
    }
}
