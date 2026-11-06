//! Passphrase words (EFF large wordlist, 7776 words, public domain) and
//! generation from OsRng.

use crate::error::{ErrorCode, Result, err};
use crate::{WORDS_MAX, WORDS_MIN};

const WORDLIST: &str = include_str!("../../../assets/wordlist-eff.txt");

pub fn wordlist() -> Vec<&'static str> {
    WORDLIST
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect()
}

/// N random words joined with '-' (OsRng). 4..=12 words.
pub fn generate(n: usize) -> Result<String> {
    if !(WORDS_MIN..=WORDS_MAX).contains(&n) {
        return err(
            ErrorCode::ProtoMalformed,
            format!("words must be {WORDS_MIN}..={WORDS_MAX}"),
        );
    }
    let wl = wordlist();
    if wl.len() != 7776 {
        return err(
            ErrorCode::StorageFailed,
            format!("wordlist must have 7776 entries, has {}", wl.len()),
        );
    }
    let mut words = Vec::with_capacity(n);
    for _ in 0..n {
        // rejection sampling: no modulo bias (65536 % 7776 != 0)
        let v = loop {
            let cand = rand::random::<u16>() as usize;
            if cand < 7776 * 4 {
                break cand % 7776;
            }
        };
        words.push(wl[v]);
    }
    Ok(words.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_size() {
        assert_eq!(wordlist().len(), 7776);
    }

    #[test]
    fn generate_bounds() {
        let p = generate(6).unwrap();
        assert_eq!(p.split('-').count(), 6);
        assert!(generate(3).is_err());
        assert!(generate(13).is_err());
    }
}
