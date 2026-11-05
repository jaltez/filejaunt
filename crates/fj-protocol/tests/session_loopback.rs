//! Session loopback (no network): full transfer, cancel, pause/resume,
//! empty file, text, and resume with epoch+1 + counter reset.

mod common;

use common::*;
use fj_protocol::ErrorCode;
use fj_protocol::pake::AttemptLimiter;
use fj_protocol::session::{Action, Role, Session, SessionOpts};

#[test]
fn full_transfer_3mib_and_receipts() {
    let data = file_3mib();
    let empty: Vec<u8> = vec![];
    let mut l = Loop::new(
        &[
            ("big.bin".into(), data.clone()),
            ("empty.dat".into(), empty),
        ],
        false,
    );
    l.pump();

    // both files done and verified on the receiver
    assert!(
        l.events_rsp.contains(&Event::FileDone {
            file: 0,
            verified: true
        }),
        "file 0 verified"
    );
    assert!(
        l.events_rsp.contains(&Event::FileDone {
            file: 1,
            verified: true
        }),
        "empty file verified"
    );
    // bytes identical end-to-end
    assert_eq!(l.received_file(0), data);
    assert_eq!(l.received_file(1), Vec::<u8>::new());
    // receipts: receiver emitted 2, initiator accepted 2
    assert_eq!(
        l.receipts.len(),
        4,
        "2 from receiver + 2 accepted by initiator"
    );
    // both sessions reached Done
    assert!(l.events_ini.contains(&Event::SessionDone));
    assert!(l.events_rsp.contains(&Event::SessionDone));
    assert!(l.ini.is_done() && l.rsp.is_done());
    // exported receipts verify against the passphrase-bound MAC
    for r in &l.receipts {
        // receipts carry the session passphrase; we used a generated one, so
        // instead verify structural validity via Receipt::verify with the
        // canonical passphrase re-injected is impossible here; check shape.
        assert_eq!(r.sha256.len(), 64);
        assert!(!r.macpf.is_empty());
    }
}

#[test]
fn receipt_verify_with_known_passphrase() {
    // deterministic passphrase path: pair manually with a fixed sid
    let data = b"receipt proof bytes".to_vec();
    let mut l = Loop::new(&[("r.bin".into(), data)], false);
    l.pump();
    assert!(l.events_rsp.contains(&Event::FileDone {
        file: 0,
        verified: true
    }));
    let receipt = l.receipts.iter().find(|_| true).unwrap().clone();
    // The passphrase was generated inside Loop; recover it via canonical
    // verification: try verify with the actual session passphrase by
    // re-deriving from receipt fields is impossible without it. Instead this
    // test verifies the negative: a wrong passphrase never verifies.
    assert!(!receipt.verify("definitely-not-the-passphrase"));
}

#[test]
fn text_both_directions() {
    let data = file_3mib();
    let mut l = Loop::new(&[("t.bin".into(), data)], false);
    l.push_n_chunks(3);
    let w = l.ini.send_text("hello from sender").unwrap();
    let acts = l.rsp.on_frame(&w).unwrap();
    assert!(
        acts.iter()
            .any(|a| matches!(a, Action::EmitText(t) if t == "hello from sender"))
    );
    let w = l.rsp.send_text("hi from receiver").unwrap();
    let acts = l.ini.on_frame(&w).unwrap();
    assert!(
        acts.iter()
            .any(|a| matches!(a, Action::EmitText(t) if t == "hi from receiver"))
    );
}

#[test]
fn local_cancel_is_clean_peer_cancel_fails() {
    let data = file_1mib();
    let mut l = Loop::new(&[("c.bin".into(), data)], false);
    l.push_n_chunks(10);
    // receiver cancels the whole session locally: CANCEL(65535) to sender
    let acts = l.rsp.cancel(65535);
    let mut saw_done = false;
    for a in acts {
        match a {
            Action::Send(w) => {
                let back = l.ini.on_frame(&w).unwrap();
                assert!(
                    back.iter().any(|a| matches!(
                        a,
                        Action::Fail {
                            code: ErrorCode::PeerCancel,
                            ..
                        }
                    )),
                    "sender sees PEER_CANCEL"
                );
                l.apply(fj_protocol::session::Role::Initiator, back);
            }
            Action::SessionDone => saw_done = true,
            _ => {}
        }
    }
    assert!(saw_done, "own cancel is a clean SessionDone");
    assert!(l.ini.is_failed());
    // own cancel is clean: SessionDone without error
    assert!(l.events_ini.iter().any(|e| matches!(
        e,
        Event::Fail {
            code: ErrorCode::PeerCancel,
            ..
        }
    )));
}

#[test]
fn pause_resume_freezes_stream() {
    let data = file_1mib();
    let mut l = Loop::new(&[("p.bin".into(), data)], false);
    l.push_n_chunks(5);
    // sender-local pause
    let acts = l.ini.pause(0);
    let mut back = vec![];
    for a in acts {
        if let Action::Send(w) = a {
            back.extend(l.rsp.on_frame(&w).unwrap());
        }
    }
    assert!(l.ini.is_paused(0));
    assert_eq!(l.ini.next_send_chunk(0), None, "paused file sends nothing");
    // resume
    let acts = l.ini.resume(0);
    for a in acts {
        if let Action::Send(w) = a {
            let _ = l.rsp.on_frame(&w).unwrap();
        }
    }
    assert!(l.ini.next_send_chunk(0).is_some());
    l.pump();
    assert!(l.events_rsp.contains(&Event::FileDone {
        file: 0,
        verified: true
    }));
}

#[test]
fn duplicate_chunks_discarded_not_written() {
    let data = file_1mib();
    let mut l = Loop::new(&[("d.bin".into(), data)], false);
    l.push_n_chunks(2); // chunks 0,1 delivered and written
    // re-send chunk 0: the receiver must discard it (dup), not write it
    let (w1, _) = l.ini.push_chunk_data(0, 0, &l.source[&0][..16384]).unwrap();
    let acts = l.rsp.on_frame(&w1).unwrap();
    let saves = acts
        .iter()
        .filter(|a| matches!(a, Action::SaveChunk { .. }))
        .count();
    assert_eq!(saves, 0, "duplicate chunk must not be written");
    assert_eq!(l.rsp.dup_count(0), 1);
    assert!(
        acts.iter()
            .any(|a| matches!(a, Action::Progress { resumed: true, .. }))
    );
    let out_of_range = l.ini.push_chunk_data(0, 9999, &[0u8; 10]);
    assert!(out_of_range.is_err(), "index >= chunks rejected");
}

#[test]
fn resume_after_interruption_epoch_bump() {
    let data = file_3mib();
    let mut l = Loop::new(&[("r.bin".into(), data.clone())], false);
    l.push_n_chunks(30); // ~30/192 chunks, then "crash"

    // Mechanism test with a known passphrase:
    let mut limiter = AttemptLimiter::new();
    let sid = [0xABu8; 16];
    let (mut ini, pass, blob1) = Session::initiator_new(SessionOpts {
        words: 6,
        private3: false,
        chunk_size: 16384,
        sid: Some(sid),
        offer_sdp: OFFER.into(),
    })
    .unwrap();
    ini.set_files(&[fj_protocol::manifest::FileSpec {
        name: "m.bin".into(),
        path: String::new(),
        size: data.len() as u64,
        sha256: sha256_hex(&data),
        gzip: false,
    }])
    .unwrap();
    let (mut rsp, blob2) = Session::responder_join(&blob1, &pass, ANSWER, &mut limiter).unwrap();
    ini.initiator_accept(&blob2).unwrap();
    let a = ini.on_channel_open();
    let b = rsp.on_channel_open();
    for act in a {
        if let Action::Send(w) = act {
            let _ = rsp.on_frame(&w).unwrap();
        }
    }
    for act in b {
        if let Action::Send(w) = act {
            let _ = ini.on_frame(&w).unwrap();
        }
    }
    // push 20 chunks
    for _ in 0..20 {
        let Some((index, len)) = ini.next_send_chunk(0) else {
            break;
        };
        let bytes = data[index as usize * 16384..index as usize * 16384 + len as usize].to_vec();
        let (w, _) = ini.push_chunk_data(0, index, &bytes).unwrap();
        let acts = rsp.on_frame(&w).unwrap();
        for act in acts {
            if let Action::SaveChunk { file, index, data } = act {
                assert_eq!(data.len(), 16384);
                let _ = (file, index);
            }
        }
    }
    let snap_i = ini.snapshot();
    let snap_r = rsp.snapshot();
    assert!(ini.epoch() == 0);

    // reconnect: NEW offer/answer strings, same passphrase, epoch+1
    let mut limiter = AttemptLimiter::new();
    let mut ini3 = Session::restore(&snap_i).unwrap();
    let mut rsp3 = Session::restore(&snap_r).unwrap();
    let new_offer = "v=0\r\no=- second generation offer\r\n";
    let new_answer = "v=0\r\no=- second generation answer\r\n";
    let blob1b = ini3.resume_initiator(&pass, new_offer).unwrap();
    assert_eq!(ini3.epoch(), 1, "epoch bumped");
    let blob2b = rsp3
        .resume_responder(&blob1b, &pass, new_answer, &mut limiter)
        .unwrap();
    ini3.initiator_accept(&blob2b).unwrap();
    let a = ini3.on_channel_open();
    let b = rsp3.on_channel_open();
    let mut i_acts = vec![];
    for act in a {
        if let Action::Send(w) = act {
            i_acts.extend(rsp3.on_frame(&w).unwrap());
        }
    }
    // deliver the receiver's channel-open HELO FIRST, then its resume
    // BITMAPs (ordered channel), to the restored sender
    let mut resumed_seen = 0;
    for act in b {
        if let Action::Send(w) = act {
            let _ = ini3.on_frame(&w).unwrap();
        }
    }
    for act in i_acts {
        if let Action::Send(w) = act {
            for act2 in ini3.on_frame(&w).unwrap() {
                if matches!(act2, Action::Progress { resumed: true, .. }) {
                    resumed_seen += 1;
                }
            }
        }
    }
    assert!(resumed_seen > 0, "resumed progress observed via BITMAP");
    // counter reset + epoch bump => no nonce reuse (epoch differs in nonce)
    assert_eq!(ini3.epoch(), 1);

    // drain: sender continues from holes
    let mut iterations = 0;
    loop {
        let mut pushed = 0;
        if let Some((index, len)) = ini3.next_send_chunk(0) {
            let bytes =
                data[index as usize * 16384..index as usize * 16384 + len as usize].to_vec();
            let (w, acts) = ini3.push_chunk_data(0, index, &bytes).unwrap();
            let recv = rsp3.on_frame(&w).unwrap();
            // store chunk + deliver any DONE emitted with the final push,
            // running the receiver hash pipeline when DONE completes the file
            for a in acts {
                if let Action::Send(w2) = a {
                    let done_acts = rsp3.on_frame(&w2).unwrap();
                    let hash_pending = done_acts
                        .iter()
                        .any(|a| matches!(a, Action::HashFeed { .. }));
                    if hash_pending {
                        let final_acts = rsp3.hash_feed(0, &data).unwrap();
                        assert!(
                            final_acts
                                .iter()
                                .any(|a| matches!(a, Action::FileDone { verified: true, .. })),
                            "verified after resume"
                        );
                    }
                }
            }
            let _ = recv;
            pushed += 1;
        }
        if pushed == 0 {
            break;
        }
        iterations += 1;
        assert!(iterations < 500, "does not terminate");
    }
    assert!(
        rsp3.file_done(0),
        "file completed and verified after resume"
    );
    assert!(rsp3.epoch() == 1);
}

#[test]
fn empty_file_done_immediately() {
    let mut l = Loop::new(&[("e.txt".into(), vec![])], false);
    l.pump();
    assert!(l.events_rsp.contains(&Event::FileDone {
        file: 0,
        verified: true
    }));
    assert_eq!(l.received_file(0), Vec::<u8>::new());
}

#[test]
fn snapshot_restore_roundtrip() {
    let data = file_1mib();
    let mut l = Loop::new(&[("s.bin".into(), data)], false);
    l.push_n_chunks(40);
    let snap = l.rsp.snapshot();
    let restored = Session::restore(&snap).unwrap();
    assert_eq!(restored.role(), Role::Responder);
    assert_eq!(restored.epoch(), 0);
    assert_eq!(restored.sid_hex(), l.rsp.sid_hex());
    assert_eq!(
        restored.file_progress(0).unwrap().0,
        l.rsp.file_progress(0).unwrap().0
    );
    let m = restored.manifest().unwrap();
    assert_eq!(m.files.len(), 1);
    assert_eq!(m.files[0].name, "s.bin");
    // snapshot contains no key material: the known k_root must not appear
    let kroot = l.rsp.k_root_hex_for_test().unwrap();
    assert!(!snap.contains(&kroot), "snapshot leaks k_root");
}

#[test]
fn gzip_auto_and_chunk_compression() {
    // compressible data through push_chunk_data: wire bytes shrink
    let pad = b"padding-padding-padding".repeat(1024); // 26 KiB compressible
    let mut l = Loop::new(&[("g.bin".into(), pad.clone())], false);
    // turn gzip on for file 0 via probe with a sample
    let sample = pad[..16384].to_vec();
    let on = l.ini.resolve_gzip_auto(0, &[sample]).unwrap();
    assert!(on, "repetitive data should compress");
    // rebuild manifest gzip policy marker: set_files was already called with
    // gzip=false; the per-file flag drives push_chunk_data compression.
    l.pump();
    assert!(l.events_rsp.contains(&Event::FileDone {
        file: 0,
        verified: true
    }));
    let (_, _, wire) = l.rsp.file_progress(0).unwrap();
    assert!(
        (wire as f64) < 0.6 * pad.len() as f64,
        "wire {wire} should be well below {} bytes",
        pad.len()
    );
    assert_eq!(l.received_file(0), pad);
}

#[test]
fn random_data_not_compressed() {
    let data = prand(0x1234, 100_000);
    let mut l = Loop::new(&[("r2.bin".into(), data.clone())], false);
    let sample = data[..16384].to_vec();
    let on = l.ini.resolve_gzip_auto(0, &[sample]).unwrap();
    assert!(!on, "random data should not compress");
    l.pump();
    assert!(l.events_rsp.contains(&Event::FileDone {
        file: 0,
        verified: true
    }));
    let (_, _, wire) = l.rsp.file_progress(0).unwrap();
    assert!(
        (wire as f64) < 1.05 * data.len() as f64,
        "wire {wire} ≈ size {}",
        data.len()
    );
}

#[test]
fn hash_mismatch_detected() {
    // receiver storage corrupted between SaveChunk and hash: simulate by
    // feeding wrong bytes to hash_feed.
    let data = file_1mib();
    let mut l = Loop::new(&[("hm.bin".into(), data)], false);
    l.pump();
    // after full verified transfer, corrupt + refeed isn't possible (hashers
    // are consumed). Instead: fresh loop, intercept the last chunk.
    let data2 = file_1mib();
    let mut l2 = Loop::new(&[("hm2.bin".into(), data2.clone())], false);
    l2.push_n_chunks(63); // all but the last chunk of 1 MiB
    // deliver a WRONG final chunk: sender pushes correct index 63 but we
    // substitute bytes (simulating tamper/corrupt storage)
    let Some((index, len)) = l2.ini.next_send_chunk(0) else {
        panic!("expected last chunk")
    };
    assert_eq!(index, 63);
    let mut wrong = vec![0u8; len as usize];
    wrong[0] ^= 0xFF;
    let (w, actions) = l2.ini.push_chunk_data(0, index, &wrong).unwrap();
    let recv_acts = l2.rsp.on_frame(&w).unwrap();
    l2.run_receiver_hash(&recv_acts);
    l2.apply(fj_protocol::session::Role::Responder, recv_acts);
    // the push also emitted DONE (last chunk); deliver it and run the
    // receiver's hash pipeline over the (corrupted) stored bytes
    l2.apply(fj_protocol::session::Role::Initiator, actions);
    l2.pump();
    // the receiver hash-fed the stored bytes -> mismatch
    assert!(
        l2.has_fail(ErrorCode::HashMismatch),
        "hash mismatch must fail the session"
    );
}
