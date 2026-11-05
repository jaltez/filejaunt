//! Manifest validation: 12 malicious names/paths + unicode happy paths.

mod common;

use fj_protocol::ErrorCode;
use fj_protocol::manifest::{FileSpec, build_manifest, validate_name, validate_path};

#[test]
fn malicious_names() {
    let bad_names: Vec<String> = vec![
        String::new(),
        "..".into(),
        ".".into(),
        "../escape".into(),
        "..\\escape".into(),
        "/absolute".into(),
        "C:\\drive".into(),
        "a\0b".into(),
        "a\u{01}control".into(),
        "a/b".into(),
        "a\\b".into(),
        "x".repeat(256),
    ];
    for n in &bad_names {
        let e = validate_name(n).unwrap_err();
        assert_eq!(
            e.code(),
            ErrorCode::PathRejected,
            "name {n:?} must be rejected"
        );
    }
}

#[test]
fn malicious_paths() {
    let bad_paths: Vec<String> = vec![
        "/leading".into(),
        "trailing/".into(),
        "a/../b".into(),
        "..".into(),
        "../x".into(),
        "a\\b".into(),
        "a//b".into(), // empty component
        "a/.".into(),
        "a/..".into(),
        "p/".repeat(200), // >1024 bytes
    ];
    for p in &bad_paths {
        let e = validate_path(p).unwrap_err();
        assert_eq!(
            e.code(),
            ErrorCode::PathRejected,
            "path {p:?} must be rejected"
        );
    }
    assert!(validate_path("").is_ok());
}

#[test]
fn unicode_happy_paths() {
    for name in ["ñandú-🦤.bin", "日本語のファイル.txt", "über file.dat"] {
        assert!(validate_name(name).is_ok(), "{name}");
    }
    assert!(validate_path("año 2026/carpeta ñ/utiles").is_ok());
    let m = build_manifest(
        &[7u8; 16],
        0,
        &[FileSpec {
            name: "ñandú 🦤.bin".into(),
            path: "año 2026".into(),
            size: 100,
            sha256: "c".repeat(64),
            gzip: false,
        }],
        16384,
    )
    .unwrap();
    m.validate().unwrap();
    assert_eq!(m.files[0].chunks, 1);
    assert_eq!(m.total, 100);
}

#[test]
fn chunk_math_and_dup_ids() {
    let spec = |id: u16, size: u64| FileSpec {
        name: format!("f{id}"),
        path: String::new(),
        size,
        sha256: "a".repeat(64),
        gzip: false,
    };
    // chunk counts: size 0 -> 0 chunks (valid empty file)
    let m = build_manifest(
        &[0u8; 16],
        0,
        &[spec(0, 0), spec(1, 1), spec(2, 16384), spec(3, 16385)],
        16384,
    )
    .unwrap();
    assert_eq!(
        m.files.iter().map(|f| f.chunks).collect::<Vec<_>>(),
        [0, 1, 1, 2]
    );
    m.validate().unwrap();

    // bad chunk_size
    let e = build_manifest(&[0u8; 16], 0, &[spec(0, 10)], 12345).unwrap_err();
    assert_eq!(e.code(), ErrorCode::PathRejected);
    // large size chunks ok
    build_manifest(&[0u8; 16], 0, &[spec(0, 100_000)], 65519)
        .unwrap()
        .validate()
        .unwrap();

    // manifest validation catches corruption
    let mut m = build_manifest(&[0u8; 16], 0, &[spec(0, 16384)], 16384).unwrap();
    m.files[0].chunks = 5;
    let e = m.validate().unwrap_err();
    assert_eq!(e.code(), ErrorCode::PathRejected);
    let mut m = build_manifest(&[0u8; 16], 0, &[spec(0, 100)], 16384).unwrap();
    m.total = 999;
    assert!(m.validate().is_err());
    let mut m = build_manifest(&[0u8; 16], 0, &[spec(0, 100), spec(1, 100)], 16384).unwrap();
    m.files[1].id = 0; // force duplicate ids on the wire
    assert!(m.validate().is_err(), "duplicate ids");
}

#[test]
fn max_files() {
    let specs: Vec<FileSpec> = (0..4097)
        .map(|i| FileSpec {
            name: format!("f{i}"),
            path: String::new(),
            size: 1,
            sha256: "a".repeat(64),
            gzip: false,
        })
        .collect();
    let e = build_manifest(&[0u8; 16], 0, &specs, 16384).unwrap_err();
    assert_eq!(e.code(), ErrorCode::PathRejected);
}

#[test]
fn sha256_field() {
    let spec = FileSpec {
        name: "x".into(),
        path: String::new(),
        size: 1,
        sha256: "XYZ".repeat(20), // uppercase rejected
        gzip: false,
    };
    assert!(build_manifest(&[0u8; 16], 0, &[spec], 16384).is_err());
}
