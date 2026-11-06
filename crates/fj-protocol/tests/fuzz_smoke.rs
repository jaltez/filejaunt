//! Deterministic fuzz-lite: 20k random/mutated inputs through the two
//! attack surfaces (frame decode + envelope parse). Mirrors fuzz/ targets
//! so CI gets continuous robustness coverage without libFuzzer infra.
//! For guided coverage-guided fuzzing run `cargo fuzz` locally (see fuzz/).

use fj_protocol::envelope::Envelope;
use fj_protocol::frame::Frame;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn fuzz_smoke_frame_and_envelope() {
    let mut state: u64 = 0x66696c656a61756e; // "filejaun"

    // 1) pure random garbage must never panic
    for _ in 0..12_000 {
        let len = (xorshift(&mut state) % 512) as usize;
        let data: Vec<u8> = (0..len).map(|_| xorshift(&mut state) as u8).collect();
        let _ = Frame::decode(&data);
        if len > 4 {
            let s: String = data.iter().map(|&b| (b % 96 + 32) as char).collect();
            let _ = Envelope::parse(&s);
        }
    }

    // 2) structured inputs: valid frame prefix + random tail
    let head = Frame::Text("seed".into()).encode_to_vec(1);
    for _ in 0..4_000 {
        let tail_len = (xorshift(&mut state) % 64) as usize;
        let mut data = head.clone();
        data.truncate((xorshift(&mut state) as usize) % head.len().max(1));
        for _ in 0..tail_len {
            data.push(xorshift(&mut state) as u8);
        }
        let _ = Frame::decode(&data);
    }

    // 3) mutated valid envelope: flip bytes inside the base64 body
    let body: Vec<u8> = (0..64).map(|_| xorshift(&mut state) as u8).collect();
    for i in 0..64 {
        let b64: String = body
            .iter()
            .enumerate()
            .map(|(j, b)| if j == i { *b % 64 } else { *b })
            .map(|b| {
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                alphabet[b as usize % 64] as char
            })
            .collect();
        let _ = Envelope::parse(&format!("FJ1.{b64}"));
    }
}
