# Contributing to filejaunt

1. `git clone` + `scripts/gen-fixtures.sh` (generates test fixtures; the
   committed ones are already in the repo except `fixtures/big.bin`).
2. `cargo test --workspace` must be green before any PR;
   `cargo clippy --workspace --all-targets -- -D warnings` and
   `cargo fmt --check` too.
3. Changes to `crates/fj-protocol` require regenerating vectors
   (`cargo xtask gen-vectors`) and keeping WASM parity
   (`wasm-pack test --node crates/fj-wasm`).
4. Security: no home-made crypto; any change to key derivation or framing
   requires updating `docs/SECURITY.md` and the vectors.
5. License: by contributing you agree your code is distributed under
   AGPL-3.0-only.
