# filejaunt — modelo de seguridad

Basado en §4 de `SEED.md`. Garantías y no-garantías, sin marketing.

## Garantías

| Amenaza | Protección |
|:--|:--|
| Observador de red (ISP, wifi) | DTLS obligatorio en el DataChannel + capa propia AES-256-GCM por frame (claves PAKE) |
| Canal que transporta el blob (chat, proxy) | SPAKE2: reescribir el blob sin la passphrase no permite derivar claves; la sustitución de SDP se detecta por el fingerprint de HELO (HMAC-SHA256 sobre offer+answer+sid con K_confirm) |
| Atacante que retransmite blobs | Solo ve ciphertext; no conoce K_root (CDH) |
| Servidor web que sirve la app | Artefacto único autocontenido con sha256 publicado (`dist/filejaunt.html.sha256`); sin CDN, sin canal de actualizaciones |
| Relay TURN (opt-in) | Segunda capa AES-GCM por chunk; el relay ve DTLS pero la app no depende de esa negociación |
| El otro extremo | Recibo por fichero: SHA-256 + HMAC (K_receipt en vivo, K_pf offline) verificable con la passphrase |

Cripto usada (nada casero): SPAKE2 (grupo Ed25519, crate `spake2`),
HKDF-SHA256, HMAC-SHA256, AES-256-GCM, comparaciones constant-time
(`subtle`), zeroize de claves/passphrases.

## No garantizado

- **Anonimato**: el par directo ve tu IP y el patrón de tráfico/tamaños.
- **Integridad del extremo**: malware en cualquiera de las máquinas.
- **Disponibilidad**: NAT simétrico / UDP bloqueado → sin TURN no hay
  conexión; `filejaunt doctor` lo diagnostica.
- **Offline receipt forgery**: quien conozca la passphrase puede forjar el
  `macpf` del recibo exportado (ver D2); el MAC de sesión (`K_receipt`)
  solo lo generan/verifican los participantes en vivo.
- **Atacante pasivo túnel**: quien retransmite bytes íntegros de ambos blobs
  puede actuar de túnel ciego (solo ve ciphertext); aceptado y documentado.

## Límites operativos

- PAKE online: 3 intentos fallidos por sid en memoria del receptor
  (`SEC_ATTEMPT_LIMIT`).
- Manifests estrictamente validados (nombres/rutas sin traversal,
  `PATH_REJECTED` + abort). El glue nunca escribe fuera del outdir.
- Los snapshots de sesión NO contienen material clave; las claves se
  re-derivan de la passphrase en cada reconexión (epoch+1 ⇒ nonces nuevos).
- CSP restrictiva en la app web; cero fetch/XHR; single file con hash.

## Política de reporte

Reporta vulnerabilidades abriendo un issue privado / security advisory en
este repositorio. No hay bounty; respuesta de cortesía en <7 días.

## Checklist de build reproducible

```sh
git checkout <tag> && cargo build --release --locked -p fj-cli
scripts/publish-app.sh          # imprime sha256 del HTML
sha256sum -c dist/filejaunt.html.sha256
```

El CI corre fmt + clippy(-D warnings) + tests + fuzz(60s) + wasm parity +
supply-chain (cargo-deny advisories+licenses).

## Desviaciones documentadas respecto a SEED/plan

- **D1** — K_env con nonce cero para offer y answer reutilizaba
  key+nonce en modo privado (rotura GCM). Se derivan subclaves
  `K_env_offer`/`K_env_answer` de K_env; formato de wire y UX intactos.
- **D2** — La re-derivación offline de K_root desde los mensajes PAKE
  públicos es imposible (CDH); el recibo exportado añade `macpf`
  (HMAC bajo HKDF(passphrase, sid)) verificable con la passphrase. `mac`
  (K_receipt) se verifica en vivo durante la sesión.
- **D3** — `Action::Send` transporta bytes ya cifrados (el contador de
  cifrado avanza en el orden de emisión) en vez de frames en claro.
- **D4** — El campo `seq` de cabecera lleva SIEMPRE el contador de cifrado
  (chunk_index viaja en el payload de CHUNK). Necesario para que el
  descifrado no dependa del orden de llegada entre 4 canales.
- **D5** — El envelope-1 añade el campo `ch` (número de canales): el SDP no
  permite deducirlo (un solo `m=application`).
