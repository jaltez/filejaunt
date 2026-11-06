# filejaunt — core

Encrypted P2P file transfer: browser↔browser and browser↔CLI, no signaling
server, no data relay, resumable, ephemeral by construction.

Este README describe el repositorio del core. La especificación de producto
completa está en [`docs/SEED.md`](docs/SEED.md); el modelo de seguridad en
[`docs/SECURITY.md`](docs/SECURITY.md).

## Quickstart

```sh
# web app (single self-contained HTML)
cargo install wasm-pack
wasm-pack build crates/fj-wasm --target web --out-dir pkg --out-name filejaunt_wasm
cd web && npm install && node build.mjs
# open web/dist/filejaunt.html on two machines (copy/paste code + blob)

# CLI
cargo install --path crates/fj-cli
filejaunt send FILE...          # prints passphrase + blob-1, waits for blob-2
filejaunt receive --out DIR     # paste blob-1, type the passphrase, paste blob-2 back
filejaunt doctor --stun public  # NAT diagnosis
filejaunt verify --receipt FILE # receipt check (exit 0 VALID / 3 INVALID)
```

Pairing = passphrase (voice/second channel) + two paste blobs. No server
involved; LAN sessions use host candidates only (`--stun none`, the default).

## Feature status

| Feature | Status |
|:--|:--|
| E2E encryption (DTLS + SPAKE2-derived AES-GCM layer) | done |
| Resume after disconnect/crash (bitmap, epoch+1) | done (CLI + web) |
| Streaming playback (fragmented mp4 for MSE) | done (web) |
| Path transparency badge (DIRECT/RELAY) | done |
| NAT diagnosis (`doctor`) | done |
| CLI ↔ web interop (one protocol core, Rust + WASM) | done |
| gzip chunk compression (auto/on/off) | done |
| Multi-channel (4) + fan-out (up to 4 receivers, CLI; web UI is one receiver per tab) | done |
| Per-file receipts + offline verify | done |

## Layout

```
crates/fj-protocol   pure sans-IO core: framing, crypto, PAKE, state machine
crates/fj-webrtc     webrtc-rs glue, STUN client, NAT classifier
crates/fj-cli        `filejaunt` binary
crates/fj-wasm       wasm-bindgen facade for the web client
crates/xtask         dev tasks (`cargo xtask gen-vectors`)
fuzz/                cargo-fuzz targets (frame_decode, envelope_parse)
tests/               multi-process CLI e2e + protocol vectors
web/                 TypeScript client, single-file build
e2e/                 Playwright browser suite
```

## Testing

```sh
scripts/gen-fixtures.sh
cargo fmt --check && cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo test --workspace --release -- --ignored   # CLI e2e (loopback)
cargo fuzz run frame_decode  -s none -- -max_total_time=60   # in fuzz/
wasm-pack test --node crates/fj-wasm
cd web && node build.mjs && cd ../e2e && npx playwright test
```

Documented deviations from the seed design are listed in
[`docs/SECURITY.md`](docs/SECURITY.md#deviations).

## Licencia

AGPL-3.0-only — uso, estudio, modificación y redistribución libres. Cualquier
servicio de red derivado debe publicar su código fuente modificado (sección
13 de la licencia). Ver [`LICENSE`](LICENSE).

## Roadmap (próximos pasos)

- [ ] Emparejamiento QR (passphrase por QR + blob por enlace/canal aparte)
- [ ] Fan-out multi-receptor en la UI web (slots compartiendo lectura)
- [ ] TURN opt-in con UI de estado permanente (relay ámbar)
- [ ] Ventana de negociación de chunk 65519 cuando el par anuncia SCTP grande
- [ ] Worker para OPFS + hash en la web (sin jank en transfers grandes)
- [ ] Internacionalización (ES/EN) de los strings de producto
- [ ] Publicación en crates.io (`filejaunt` bin) y firmas de release (minisign)
