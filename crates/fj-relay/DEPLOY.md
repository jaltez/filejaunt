# Deploying fj-relay (Dokploy / dagon)

Runs on the existing Dokploy host (`dagon`, the same box as indieboot /
javieraltez / brotando / ibersuelo). One Dokploy **application** inside a
`filejaunt` project:

| Setting | Value |
|---|---|
| Source | GitHub `jaltez/filejaunt`, watch `main` |
| Build type | Dockerfile — path `crates/fj-relay/Dockerfile` (context = repo root) |
| Port | `8088` (binary default; also accepts a port as argv[1]) |
| Domain | `relay.filejaunt.com` — Cloudflare **proxy ON (orange)** |
| Env / volumes / DB | none — the relay is stateless and secretless |

`/healthz` answers `ok`; the WebSocket endpoint is `/ws`. Push to `main`
rebuilds via the Dokploy webhook (cold build ~3–5 min on the CX33; cached
dependency layers make later builds faster).

## Why orange-cloud works here

- TLS terminates at Cloudflare's edge (zone SSL mode Flexible, like the rest
  of the fleet): clients speak `wss://` to CF, the origin hop is plain `ws`
  over :80 → Dokploy's Traefik → container. Traefik proxies WebSockets
  natively.
- Cloudflare kills **idle** proxied WebSockets after ~100 s. The relay sends
  a protocol-level ping every 30 s (see the `pump` task in `src/main.rs`);
  browsers answer with pong automatically, so peers waiting minutes to pair
  survive. If the ping is ever removed, relay must go DNS-only (grey cloud).
