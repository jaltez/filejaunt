//! Frame wire-format tests: roundtrip of all 12 types, malformed table,
//! proptest fuzz-lite. `Frame::decode` must never panic.

mod common;
use fj_protocol::ErrorCode;
use fj_protocol::frame::{Frame, b64};
use fj_protocol::manifest::{FileSpec, build_manifest};
use proptest::prelude::*;

fn sample_manifest() -> fj_protocol::Manifest {
    build_manifest(
        &[1u8; 16],
        0,
        &[FileSpec {
            name: "hello.bin".into(),
            path: "dir/sub".into(),
            size: 40000,
            sha256: "a".repeat(64),
            gzip: false,
        }],
        16384,
    )
    .unwrap()
}

fn all_frames() -> Vec<Frame> {
    vec![
        Frame::Hello {
            role: 0,
            version: 1,
            fp: [7u8; 32],
        },
        Frame::Manifest(sample_manifest()),
        Frame::ChunkReq {
            file: 3,
            from: 0,
            to: 64,
        },
        Frame::Chunk {
            file: 3,
            index: 5,
            gzip: true,
            data: vec![1, 2, 3, 255],
        },
        Frame::Bitmap {
            file: 3,
            runs: vec![(0, 10), (20, 5)],
        },
        Frame::Pause { file: 3 },
        Frame::Resume { file: 65535 },
        Frame::Cancel { file: 65535 },
        Frame::Receipt(fj_protocol::ReceiptMsg {
            file: 0,
            sha256: "b".repeat(64),
            bytes: 42,
            ts: 1700000000,
            mac: b64(&[9u8; 32]),
        }),
        Frame::Text("hi there".into()),
        Frame::Error {
            code: ErrorCode::ProtoMalformed,
            msg: "x".into(),
        },
        Frame::Done { file: 0 },
    ]
}

#[test]
fn roundtrip_all_types() {
    for (i, f) in all_frames().into_iter().enumerate() {
        let wire = f.encode_to_vec(7);
        assert_eq!(wire[0], 1, "version");
        let back = Frame::decode(&wire).unwrap_or_else(|e| panic!("frame {i}: {e}"));
        assert_eq!(&back, &f, "roundtrip {i}");
    }
}

#[test]
fn chunk_header_fields() {
    let f = Frame::Chunk {
        file: 9,
        index: 77,
        gzip: false,
        data: vec![0; 100],
    };
    let wire = f.encode_to_vec(0);
    assert_eq!(
        u16::from_le_bytes([wire[2], wire[3]]),
        9,
        "stream_id = file"
    );
    assert_eq!(
        u32::from_le_bytes([wire[4], wire[5], wire[6], wire[7]]),
        77,
        "seq = index"
    );
    let back = Frame::decode(&wire).unwrap();
    match back {
        Frame::Chunk {
            file,
            index,
            gzip,
            data,
        } => {
            assert_eq!((file, index, gzip), (9, 77, false));
            assert_eq!(data.len(), 100);
        }
        _ => panic!("wrong type"),
    }
}

#[test]
fn malformed_table() {
    let good = Frame::Chunk {
        file: 1,
        index: 2,
        gzip: false,
        data: vec![5; 64],
    }
    .encode_to_vec(0);
    // truncation at every offset
    for cut in 0..good.len() {
        let r = Frame::decode(&good[..cut]);
        assert!(r.is_err(), "truncated at {cut} must fail");
    }
    // version 2
    let mut w = good.clone();
    w[0] = 2;
    let e = Frame::decode(&w).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProtoVersion);
    // unknown type
    let mut w = good.clone();
    w[1] = 0x7F;
    let e = Frame::decode(&w).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProtoMalformed);
    // length 1<<20
    let mut w = good.clone();
    w[8..12].copy_from_slice(&(1u32 << 20).to_le_bytes());
    assert!(Frame::decode(&w).is_err());
    // length mismatch
    let mut w = good.clone();
    w[11] ^= 1;
    assert!(Frame::decode(&w).is_err());
}

#[test]
fn malformed_json_payloads() {
    // JSON-typed frames with corrupt payload
    let json_frames: Vec<Frame> = vec![
        Frame::Hello {
            role: 0,
            version: 1,
            fp: [0; 32],
        },
        Frame::ChunkReq {
            file: 0,
            from: 0,
            to: 1,
        },
        Frame::Bitmap {
            file: 0,
            runs: vec![],
        },
        Frame::Pause { file: 0 },
        Frame::Error {
            code: ErrorCode::PeerCancel,
            msg: "m".into(),
        },
        Frame::Done { file: 0 },
    ];
    for f in json_frames {
        let wire = f.encode_to_vec(0);
        let mut bad = wire.clone();
        // replace payload with broken JSON
        for b in bad.iter_mut().skip(12) {
            *b = b'{';
        }
        let n = (bad.len() - 12) as u32;
        bad[8..12].copy_from_slice(&n.to_le_bytes());
        assert!(Frame::decode(&bad).is_err());
        // and with empty payload
        let empty = bad[..12].to_vec();
        assert!(Frame::decode(&empty).is_err());
    }
}

#[test]
fn text_limits() {
    let big = "x".repeat(32 * 1024 + 1);
    let wire = Frame::Text(big).encode_to_vec(0);
    assert!(Frame::decode(&wire).is_err());
    let ok = "x".repeat(32 * 1024);
    let wire = Frame::Text(ok).encode_to_vec(0);
    assert!(Frame::decode(&wire).is_ok());
    // invalid UTF-8
    let mut w = Frame::Text("ok".into()).encode_to_vec(0);
    w[12] = 0xFF;
    assert!(Frame::decode(&w).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn random_input_never_panics(data in any::<Vec<u8>>()) {
        let _ = Frame::decode(&data);
    }

    #[test]
    fn random_chunk_roundtrip(
        file in 0u16..,
        index in 0u64..1000,
        gzip in any::<bool>(),
        data in proptest::collection::vec(any::<u8>(), 0..2000),
        seq in any::<u32>(),
    ) {
        let f = Frame::Chunk { file, index, gzip, data };
        prop_assert_eq!(Frame::decode(&f.encode_to_vec(seq)).unwrap(), f);
    }

    #[test]
    fn random_text_roundtrip(
        t in ".{0,100}",
        seq in any::<u32>(),
    ) {
        let f = Frame::Text(t.clone());
        prop_assert_eq!(Frame::decode(&f.encode_to_vec(seq)).unwrap(), Frame::Text(t));
    }

    #[test]
    fn random_bitmap_roundtrip(
        runs in proptest::collection::vec((0u64..200, 1u64..20), 0..30),
        file in any::<u16>(),
    ) {
        let f = Frame::Bitmap { file, runs };
        if let Ok(back) = Frame::decode(&f.encode_to_vec(0)) {
            prop_assert_eq!(back, f);
        }
    }
}
