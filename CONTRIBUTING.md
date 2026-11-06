# Contribuir a filejaunt

1. `git clone` + `scripts/gen-fixtures.sh` (genera fixtures de test; los
   commitados ya están en el repo salvo `fixtures/big.bin`).
2. `cargo test --workspace` debe pasar en verde antes de cualquier PR;
   `cargo clippy --workspace --all-targets -- -D warnings` y
   `cargo fmt --check` también.
3. Los cambios en `crates/fj-protocol` requieren regenerar vectores
   (`cargo xtask gen-vectors`) y mantener paridad WASM
   (`wasm-pack test --node crates/fj-wasm`).
4. Seguridad: nada de cripto casera; cualquier cambio en derivación de claves
   o framing requiere actualizar `docs/SECURITY.md` y los vectores.
5. Licencia: al contribuir aceptas que tu código se distribuya bajo
   AGPL-3.0-only.
