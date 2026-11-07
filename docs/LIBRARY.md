# Web library

`web/dist/fj.js` is the browser build: an ES module with the WASM core,
transport, storage and pairing state machine inlined. It never fetches
anything at runtime, so it works under `default-src 'none'` with
`script-src 'self' 'wasm-unsafe-eval'`.

The library owns no DOM. A host page renders files, blobs, logs and badges;
the library reports through callbacks and accepts commands. The reference
implementation is [`web/src/main.ts`](../web/src/main.ts) on top of
[`web/index.html`](../web/index.html); a full custom UI lives at
`filejaunt.com` (`app/app.js`).

## Use

```js
import { Jaunt } from './fj.js';

const jaunt = await Jaunt.create({
  getIce: () => ({ stunUrls: ['stun:stun.example:19302'] }),
  events: {
    log: (line) => console.log(line),
    step: (text) => setStatus(text),
    passphrase: (text) => showPassphrase(text),
    blobOut: (blob) => showBlob(blob),
    files: (files) => renderFiles(files),
    text: (line) => appendText(line),
    path: (info) => setBadge(info),
    download: (name, blob) => offerDownload(name, blob),
    doctor: (result) => showDoctor(result.detail),
    reset: () => clearSessionViews(),
  },
});

jaunt.setRole('sender');
await jaunt.send(fileList, { words: 6, channels: 1, gzip: 'auto' });
// jaunt.hook.blob1 is the blob to paste into the receiver.

// receiver side
jaunt.setRole('receiver');
await jaunt.process(pastedBlob, spokenPassphrase);
// the answer is delivered through events.blobOut
```

### Relay pairing (one-line code, optional)

Give `Jaunt.create` a `getRelay()` returning a self-hosted
[`fj-relay`](../crates/fj-relay) WebSocket URL and pairing collapses to a
single `fj-<room8>-<words>` code: the sender gets it through the
`pairingCode` event (and `jaunt.pair(code)` accepts it on the receiver);
the blobs cross through the relay room automatically. The room id is
SHA-256(canonical passphrase) truncated to 8 hex — the relay cannot invert
it and sees ciphertext only. After pairing both sides receive a `checksum`
event (`"XXXX XXXX"` from K_confirm): matching values rule out a MITM in
the signaling path, so surface them next to each other. An empty/absent
`getRelay` keeps the paste-blob flow exactly as above.

```js
const jaunt = await Jaunt.create({
  getIce,
  getRelay: () => userRelayUrlOrNull, // wss://your-host/ws
  events: { pairingCode: (code) => showCode(code), checksum: (s) => showChecksum(s), ... },
});
// sender: after send() → events.pairingCode('fj-9f3a2b41-word-one-…')
// receiver: await jaunt.pair('fj-9f3a2b41-word-one-…'); // bare passphrase works too
```

Host pages need `connect-src wss:` in their CSP for the relay socket.

A secure context is required (HTTPS, or `localhost`). WebRTC and
`crypto.subtle` are unavailable on plain HTTP origins.

## Commands

| Method | Purpose |
| --- | --- |
| `Jaunt.create(opts)` | Load WASM once; returns the engine. |
| `setRole('sender' \| 'receiver')` | Sets the pairing state machine's expected blob. |
| `send(files, opts?)` | Start a session from `File[]`; returns after blob-1 exists. |
| `process(blob, passphrase)` | Advance the state machine with the peer's blob. |
| `pair(code)` | Relay pairing: consume the one-line code (or a bare passphrase). |
| `restart()` | Re-pair the same session with a new receiver (same passphrase). |
| `sendText(text)` | Send one text message; resolves `false` if not connected. |
| `togglePause(id)`, `cancel(id)` | Per-file queue control (sender). |
| `setDir(handle)` | Save through a `FileSystemDirectoryHandle`. |
| `diagnose(stunUrls)` | STUN probe; also reported via the `doctor` event. |
| `pathInfo()` | `{ kind, text, detail }` for the current link. |
| `destroy()` | Close the transport and timers. |
| `hook` | Live debug state (`state`, `files`, `sid`, `receipts`, ...). |

`SendOptions`: `words` (4–12), `privatePairing` (4-paste mode, no clear SDP),
`channels` (1 or 4), `gzip` (`'auto' | 'on' | 'off'`), `ice` (override
`getIce` for one session).

## Events

| Event | Payload |
| --- | --- |
| `log` | One human-readable line. |
| `step` | The next action for the user. |
| `state` | `idle`, `pairing`, `paired`, `transferring`, `done`, `failed`. |
| `passphrase` | The generated passphrase (sender only). |
| `blobOut` | Blob to hand to the other machine, or `''` on reset. |
| `pairingCode` | The one-line `fj-<room8>-<words>` code (relay sender). |
| `checksum` | `"XXXX XXXX"` verification checksum (relay pairing, both sides). |
| `files` | `FileView[]`: name, size, progress, wire bytes, verified, paused. |
| `text` | A text message received from the peer. |
| `path` | Connection path info, updated about once a second. |
| `download` | A verified file is ready as a `Blob`. |
| `doctor` | NAT probe result. |
| `reset` | A new session started; clear per-session views. |

## Build

```sh
wasm-pack build crates/fj-wasm --target web --out-dir pkg --out-name filejaunt_wasm
cd web && node build.mjs
```

`build.mjs` emits both `dist/fj.js` (library) and `dist/filejaunt.html`
(reference app, one self-contained file). `scripts/publish-app.sh` copies
`fj.js` into the website checkout and refreshes its `sha256` sidecar.
