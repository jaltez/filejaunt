# filejaunt — security model

Based on §4 of `SEED.md`. Guarantees and non-guarantees, no marketing.

## Guarantees

| Threat | Protection |
|:--|:--|
| Network observer (ISP, Wi-Fi) | Mandatory DTLS on the DataChannel + a per-frame AES-256-GCM layer of our own (PAKE-derived keys) |
| The channel carrying the blob (chat, proxy) | SPAKE2: rewriting the blob without the passphrase yields no usable keys; SDP substitution is detected by the HELO fingerprint (HMAC-SHA256 over offer+answer+sid with K_confirm) |
| Attacker retransmitting blobs | Sees ciphertext only; does not know K_root (CDH) |
| Web server hosting the app | Single self-contained artifact with a published sha256 (`dist/filejaunt.html.sha256`); no CDN, no update channel |
| TURN relay (opt-in) | Second AES-GCM layer per chunk; the relay sees DTLS but the app does not depend on that negotiation |
| The other endpoint | Per-file receipt: SHA-256 + HMAC (K_receipt live, K_pf offline) verifiable with the passphrase |

Crypto in use (nothing home-made): SPAKE2 (Ed25519 group, `spake2` crate),
HKDF-SHA256, HMAC-SHA256, AES-256-GCM, constant-time comparisons
(`subtle`), zeroization of keys/passphrases.

## Not guaranteed

- **Anonymity**: the direct peer sees your IP and traffic/size patterns.
- **Endpoint integrity**: malware on either machine.
- **Availability**: symmetric NAT / blocked UDP → no connection without
  TURN; `filejaunt doctor` diagnoses it.
- **Offline receipt forgery**: whoever knows the passphrase can forge the
  exported receipt's `macpf` (see D2); the session MAC (`K_receipt`) is only
  generated/verified by live participants.
- **Passive tunnelling attacker**: whoever retransmits both blobs verbatim
  can act as a blind tunnel (sees ciphertext only); accepted and documented.

## Operational limits

- PAKE online: 3 failed attempts per sid in receiver memory
  (`SEC_ATTEMPT_LIMIT`). In the CLI the limit is per process (each run is
  one attempt); in the web the limiter lives in the tab's `FjCore`
  instance. A HELO/SDP failure counts the same as a PAKE failure.
- Manifests strictly validated (traversal-proof names/paths,
  `PATH_REJECTED` + abort). The glue never writes outside the outdir.
- Session snapshots contain NO key material; keys are re-derived from the
  passphrase on every reconnect (epoch+1 ⇒ fresh nonces).
- Restrictive CSP in the web app; zero fetch/XHR; hashed single file.

## Reporting policy

Report vulnerabilities via a private issue / security advisory on this
repository. No bounty; courtesy response within 7 days.

## Platform notes

- Streaming: MSE SourceBuffers require fragmented mp4 (`moov` + `moof`);
  the committed fixture is fMP4 and the e2e uses it as-is.
- On WSL2, Chromium ↔ webrtc-rs needs
  `--disable-features=WebRTCHideLocalIpsWithMdns` (Playwright only; mDNS
  candidates do not resolve against webrtc-rs).
- The player may reject a file; the transfer itself never fails because of
  the player.
- The vectors in `tests/vectors/protocol.json` use a FIXED passphrase, sid
  and SPAKE2 secret, test-only (documented in the JSON itself): useless for
  attacking real sessions (a real sid is OsRng, keys are ephemeral).
- Web v1: one receiver per tab (multi-receiver fan-out is CLI-only); resume
  requires the same storage backend (OPFS) and same tab/profile — a
  snapshot does not resume against a manually picked FSA directory.

## Reproducible build checklist

```sh
git checkout <tag> && cargo build --release --locked -p fj-cli
scripts/publish-app.sh          # prints the HTML sha256
(cd web/dist && sha256sum -c filejaunt.html.sha256)
```

CI runs fmt + clippy(-D warnings) + tests + fuzz-smoke + wasm parity +
supply-chain (cargo-deny advisories+licenses). Guided cargo-fuzz runs are
documented in the README Testing section.

## Documented deviations from SEED/plan

- **D1** — K_env with a zero nonce for both offer and answer reused
  key+nonce in private mode (GCM break). Subkeys `K_env_offer`/`K_env_answer`
  are derived from K_env; wire format and UX unchanged.
- **D2** — Offline re-derivation of K_root from the public PAKE messages is
  impossible (CDH); the exported receipt adds `macpf` (HMAC under
  HKDF(passphrase, sid)) verifiable with the passphrase. `mac` (K_receipt)
  is verified live during the session.
- **D3** — `Action::Send` carries already-encrypted bytes (the encryption
  counter advances in emission order) instead of plaintext frames.
- **D4** — The header `seq` field ALWAYS carries the encryption counter
  (chunk_index travels in the CHUNK payload). Required so decryption does
  not depend on arrival order across 4 channels.
- **D5** — Envelope-1 adds the `ch` field (channel count): the SDP cannot
  reveal it (a single `m=application`).
