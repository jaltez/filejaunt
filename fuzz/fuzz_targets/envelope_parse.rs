#![no_main]
//! Fuzz `Envelope::parse`: any input must produce Err, never a panic.
//! Inputs that happen to be valid UTF-8 are tried as raw envelopes;
//! additionally a mutated FJ1.-prefixed variant is exercised.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = fj_protocol::envelope::Envelope::parse(s);
        let _ = fj_protocol::envelope::inflate(s);
    }
    // prefix-mutation: treat the data as the base64url body
    if let Ok(s) = std::str::from_utf8(data) {
        let prefixed = format!("FJ1.{}", s.trim_matches(char::from(0)));
        let _ = fj_protocol::envelope::Envelope::parse(&prefixed);
    }
});
