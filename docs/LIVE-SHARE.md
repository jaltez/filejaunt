# Live share — design and orchestration

> Status: building. Milestones M1 (folders) and M2 (live sessions, chat)
> and M3 (append) land together; the seams below are the implementation
> map. Companion investigation: session scout report, 2026-11-07.

Three frontiers, one direction: a FileJaunt session stops being a one-shot
send and becomes a **live share** — folders shared as folders, files
appendable while the share is open, and a chat that lives as long as the
share does. All of it rides the existing encrypted DataChannel. The relay
stays what it is: a pairing courier that sees ciphertext.

## What exists today (constraints)

- The manifest is fixed per session; the receiver fails a changed MANIFEST
  (`session.rs` `on_manifest`, "MANIFEST changed mid-session").
- The session auto-closes the moment the last receipt lands: core flips
  `Phase::Done`, the wrapper closes the transport (`engine.ts` on
  `{t:"done"}`), and `send_text` refuses ("session not active").
- TEXT frames already exist both directions, tested, but are fire-and-forget
  and die with the session.
- Paths in `FileEntry` and the receiver sink already support folder trees;
  the web sender just never offers more than one picked folder, because
  `engine.ts` derives paths from a single `webkitRelativePath`.
- There is no capability negotiation: `PROTOCOL_VERSION=1` gates HELO, and
  an old peer fails hard on an unknown frame type. Any new frame must be
  gated so old peers never receive it.

## M1 — folders and multiple folders (no protocol change)

The wire already carries per-file paths and the receiver already recreates
subfolders. The gap is the sender glue and the pad UI.

- `engine.ts` `send()` accepts entries with explicit paths
  (`{ file, path }` or `File` with `webkitRelativePath`), so several
  directory picks can be folded into one session, each under its own root
  folder name.
- The files event gains `path`, so both sides can render a tree instead of
  a flat list.
- Pad: a staging area (add files, add folder, add another folder, remove,
  then start the share) and a folder-grouped manifest on both sides.
- Limits unchanged: `MAX_FILES=4096`, `MAX_TOTAL_CHUNKS`, path ≤ 1024 bytes.

## M2 — live sessions and chat (lifecycle, one tiny wire addition)

Policy: the session ends when a human ends it, not when the last byte is
verified.

Negotiation (zero breakage):

- HELO gains an optional `"c": u8` caps field. Old peers ignore the extra
  JSON field (serde ignores unknown fields); new peers read it as 0 when
  absent. No version bump, no snapshot invalidation.
- `CAPS_LIVE = 0x01`: both sides keep the session open after all files
  settle, accept BYE, and exchange TEXT after settlement.
- The initiator writes its intent into the manifest as `"live": bool`
  (serde default `false`, old receivers ignore it). Effective policy on
  both sides: `manifest.live && peer_caps & CAPS_LIVE`. A new-new pair
  goes live; any old peer collapses to today's auto-close, symmetrically.

Wire:

- `BYE` (type `0x0D`, empty payload). Sent by `end_session()`; receiver
  goes to `Phase::Done` + `SessionDone`. This is the "leave the share"
  button on both ends.

Core changes:

- The three natural-completion sites (receiver verified, initiator receipt
  accepted, per-file cancels settling the set) stop auto-closing when the
  effective policy is live; the session stays `Active`, TEXT keeps working
  (the existing phase guard already permits exactly this).
- Local `cancel(FILE_ALL)` and peer `CANCEL(FILE_ALL)` still end the
  session: cancelling everything is intent to leave.
- Resume: `live` is derived from the snapshot's manifest, so a re-paired
  live session stays live. No snapshot schema change.

Wrapper changes:

- On `{t:"done"}` do not close the transport while the session is live;
  keep feeding `handleWire`. The send pump finds no pending chunks and
  idles at near-zero cost until APPEND (M3) or BYE.
- Chat is UI state only: in-memory history per session, both directions,
  no delivery receipts (documented as best-effort, like any chat over a
  dying link).

## M3 — append files to a live share (protocol extension)

- `CAPS_APPEND = 0x02`, negotiated in the same HELO caps byte.
- `APPEND` frame (type `0x0E`): JSON payload `{"files": [FileEntry…],
  "total": u64}` — the new entries only, ids continuing the manifest's
  sequence, same uniform `chunk_size`.
- Initiator API `append_files(specs)`: initiator-only, `Phase::Active`,
  requires the negotiated append capability. Validates exactly like the
  initial manifest (names, paths, hashes, `MAX_FILES`, `MAX_TOTAL_CHUNKS`),
  recomputes chunk counts, extends the manifest and allocates fresh
  per-file state. Empty files are immediately DONE, as at session start.
- Responder `on_append`: same validation, extends manifest and state,
  emits a new `FilesAdded` action so the wrapper can create receiver
  records and sinks; the UI adds the rows as they are announced.
- The receiver's chunk requests for the new ids flow through the existing
  pull loop; the sender's pump picks them up in manifest order.
- Snapshots taken after an append embed the grown manifest; restore
  overlays per-id state with defaults, so new ids restore fresh. Old
  snapshots restore with append capability re-negotiated per HELO.
- Resume of an appended session re-requests missing chunks per file; no
  new bitmap semantics.

## Compatibility matrix

| pair | manifest.live | new frames | behavior |
|---|---|---|---|
| new ↔ new | true | BYE, APPEND, TEXT after settle | live share |
| new ↔ new | false | none beyond today | one-shot send |
| new ↔ old | true (ignored) | never sent (caps gate) | one-shot send, auto-close |
| old ↔ new | absent | never received | one-shot send, auto-close |

Snapshots: schema unchanged (`v=1`); `live` rides inside the embedded
manifest, appended manifests embed whole. HELO bytes change for new
senders (extra `"c"` field), so protocol vectors regenerate; frames other
than HELO are byte-identical to today.

## Test plan

- Rust loopback: live session — text both directions after the last
  receipt; BYE from each role; live + per-file cancel stays open;
  cancel-all still closes; append mid-session transfers new files and
  verifies receipts; append after BYE fails; old-peer caps=0 collapses to
  auto-close; snapshot of an appended live session restores and resumes.
- WASM parity: same loopbacks through `fj-wasm`.
- Playwright (reference app): folder structure round-trip, append appears
  on the receiver, chat survives completion, BYE ends both sides.
- Site pad: two-tab smoke on filejaunt.com before publish.

## Not doing

- No chat history persistence, receipts, or offline delivery: the share is
  ephemeral by construction; history dies with the tab.
- No background transfers with a closed tab (product non-goal, unchanged).
- No relay involvement beyond pairing, ever.
