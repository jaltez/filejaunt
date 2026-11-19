#![no_main]
//! Fuzz `Manifest` / `FileEntry` deserialization + validation: limits,
//! name/path traversal rules, sha256 shape. Any input must produce Err or a
//! rejected manifest, never a panic and never an accepted traversal.
use fj_protocol::manifest::{validate_entry, validate_name, validate_path, validate_sha256};
use fj_protocol::{FileEntry, Manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = serde_json::from_slice::<Manifest>(data) {
        let _ = m.validate();
        for id in 0..4u16 {
            let _ = m.file(id);
            let _ = m.rel_path(id);
        }
    }

    if let Ok(e) = serde_json::from_slice::<FileEntry>(data) {
        let _ = validate_entry(&e);
    }

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validate_name(s);
        let _ = validate_path(s);
        let _ = validate_sha256(s);

        // negative invariants: traversal-shaped inputs must never validate
        for bad in ["..", "../x", "a/../b", "/abs", "a\\b"] {
            assert!(validate_path(bad).is_err(), "path traversal accepted: {bad:?}");
        }
        assert!(validate_name("..").is_err(), "'..' must be rejected as a name");
        assert!(validate_name("a/b").is_err(), "'/' must be rejected in a name");
    }
});
