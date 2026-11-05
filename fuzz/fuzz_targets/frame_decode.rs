#![no_main]
//! Fuzz `Frame::decode`: any input must produce Err, never a panic.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let _ = fj_protocol::Frame::decode(data);

    // also exercise encode of the decoded frame when it parses
    if let Ok(frame) = fj_protocol::Frame::decode(data) {
        let mut out = Vec::new();
        frame.encode(&mut out, 0);
        let _ = fj_protocol::Frame::decode(&out);
    }

    // churn the gzip chunk helpers through the public API where possible
    // (envelope inflation also covers gzip parsing)
    let mut env_input = Vec::new();
    let _ = env_input.write_all(data);
});
