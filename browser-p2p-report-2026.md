# Browser-only P2P file transfer between two PCs (2026)

**Scope:** can two browsers move multi-GB files over a WebRTC DataChannel with *zero relay and zero signaling server*, using a single local HTML file and manual SDP/QR exchange? What breaks, what is the security model, and what does the evidence actually support?

---

## 1. Bottom line

Feasible, with one honest caveat about the word "zero".

- **Zero signaling server: yes.** Signaling is deliberately outside the WebRTC spec, so a manual copy/paste SDP exchange between two peers is a legitimate, working pattern — a complete HTML+JS page needs no backend [2]. Encoding the offer into a short code (gzip+base64) or QR code, and returning an answer code, is a shipped design [1].
- **Zero relay: yes, in the happy path.** After the handshake, "no signaling server is involved; it's genuinely peer-to-peer" [1].
- **Zero infrastructure: no.** Neither source achieves that. [1] still depends on Google's public STUN servers, and states plainly that this "you can't avoid ... for NAT traversal". [2] sidesteps STUN only because its demo targets tabs/devices that can reach each other over host candidates. So the correct framing for 2026 is **zero *relay* and zero *signaling server*, but not zero third-party dependency** — one STUN lookup per session is the practical floor, and TURN is the escape hatch when hole punching fails.
- **Security: encrypted by default, but the pairing step — not DTLS — is the weak link.** DTLS is mandatory [3]; the MITM question is entirely about how the DTLS fingerprints (or an application-layer key) get from A to B, and [1]'s answer to that is weaker than it looks (§4).

---

## 2. What the manual-exchange architecture actually requires

Both sources converge on the same four-step shape [1][2]:

1. A creates offer, gathers ICE candidates, encodes `localDescription` into a code.
2. A → B transfers the code (copy/paste or QR).
3. B sets the remote description, produces an answer code, returns it.
4. A pastes the answer; DataChannel opens; bytes flow.

Two implementation details are where naive versions fail, and the evidence is worth reconciling here because the two sources appear to disagree on timing:

- [1] reports you must wait for `iceGatheringState === 'complete'` before encoding, otherwise the offer is incomplete ("handshake timing is fiddly").
- [2]'s minimal code does not check that flag; it dumps `pc.localDescription` inside `onicecandidate` when `e.candidate === null`.

These are **not** in conflict — a `null` candidate event is the end-of-gathering signal, so [2] gets the same effect implicitly. The real disagreement is about completeness, not correctness: [2]'s listing never calls `createAnswer()` on the receiving side, so as printed it cannot complete a real A↔B handshake. That asymmetry supports [1]'s broader claim that "WebRTC's spec reads cleanly. The reality is messier." A production single-file tool must also handle ICE failure, renegotiation, and candidate-less (mDNS/host) edge cases that both snippets elide.

Practical consequence: waiting for full gathering means the user stares at a spinner for a second or two; that latency is the price of removing the signaling server, and it is the main UX reason hosted tools exist.

---

## 3. NAT traversal without TURN

The provided evidence contains **no measured success rates** — no percentage for symmetric NAT, CGNAT, or UDP-blocked networks. I will not manufacture one; the honest statement is that the numbers this question asks for are not in the corpus (see Caveats).

What the evidence does establish is the *shape* of the constraint:

- STUN is treated as unavoidable for NAT traversal [1]. STUN is reflexive-address discovery, not a relay, so using it does not violate "zero relay" — it does violate "zero servers".
- Nothing in [1] or [2] provides a fallback when hole punching fails. [1]'s design simply assumes ICE succeeds; there is no TURN configuration shown, and no error path described.
- The failure modes named in the question (symmetric NAT, CGNAT, UDP-blocked corporate/guest Wi-Fi) are precisely the cases where a reflexive address is not predictive of the mapping a peer will actually get, so no amount of SDP exchange substitutes for a relay.

**Design implication:** a truthful 2026 single-file tool must detect ICE failure and say so, rather than leaving a spinner. The deterministic degradation path is: try direct → on `iceconnectionstate` failure, instruct the user to switch networks (phone hotspot defeats most CGNAT cases) or fall back to a TURN/relay variant of the same page. Claiming "works everywhere, no server" is the one claim this architecture cannot support.

---

## 4. Security model

**Transport layer.** "Since all WebRTC components are required to use encryption, any data transmitted on an RTCDataChannel is automatically secured using [DTLS]" [3]. So confidentiality and integrity in transit are not optional and not the app's job. That is a genuine strength versus a WebSocket-based transfer.

**Authentication layer — this is the interesting part.** DTLS gives you an encrypted pipe to *whoever completed the handshake*; it does not tell you that peer is the person you think. Whoever controls the SDP path controls which certificate fingerprint the peers validate against. If the code travels through a chat app, a corporate proxy, or a hosted relay page, that intermediary can substitute both SDPs and sit in the middle.

[1] layers defenses on top of DTLS:

- AES-GCM per 64 KiB chunk with a fresh nonce, key derived via PBKDF2 from a shared session secret.
- A SHA-256 hash verified against an expected value, checked before the file is assembled.
- A session fingerprint in the signaling payload "to detect MITM substitution", aborting the transfer if offer/answer codes were tampered with.

**The critique:** the session secret "rides along in the connection code" [1]. That means the application-layer key is transported *in-band with the very payload it is meant to protect*. Against a compromised signaling channel this adds nothing: an attacker who can rewrite the offer can read the secret, and if it can rewrite the offer it can also rewrite the fingerprint. The fingerprint check only becomes meaningful if the two humans compare it over a **separate authenticated channel** — which [1] does not describe. Read strictly, [1]'s AES-GCM layer protects against threats DTLS already covers, while its MITM defense depends on a comparison step that is left as an exercise.

**What actually closes this gap** is a PAKE: derive the key from a short human-transferred secret via SPAKE2 (the Magic Wormhole model), so a malicious server must launch an online guessing attack against a low-entropy code rather than silently substituting keys. That is the correct primitive for a QR/manual-pairing tool, and it is exactly what the question's PAKE sub-query points at. **None of the five evidence blocks describes SPAKE2, SAS comparison, or a PAKE of any kind**, so this recommendation is architectural reasoning, not a finding (§Caveats).

**Website-served-JS trust.** A single local HTML file is the strongest available answer to "the server can swap the JavaScript" — no origin, no CDN, no service worker, no update channel. The trade-off is the mirror image: no security updates, and the file's provenance becomes the trust anchor (hash the file, share the hash). Neither [1] nor [2] discusses this; it follows from the deployment model they describe.

---

## 5. Streaming multi-GB files

Established by the evidence:

- The interoperable pattern is to split the file into chunks and send them over the DataChannel, which is reliable and ordered by default and "well-suited for filetransfers" [4].
- Real applications must carry metadata (name, type, size, hash) either via signaling or in-band; the reference demo cheats by assuming the size up front and closes the connection after the expected byte count [4].
- Message size is bounded by the browser's SCTP stack — roughly 16 KB safe / 64 KB ceiling — so chunking is mandatory, and `bufferedAmount` backpressure is how you avoid unbounded memory growth [5].

The scaling arithmetic: a 10 GB file is ~163,840 chunks at 64 KiB or ~655,360 at the safe 16 KiB. That is fine for throughput but fatal for the reference implementation's reassembly strategy — it collects chunks into an in-memory `Blob` [4], which puts the practical ceiling at available RAM, not at the file size. **Streaming straight to disk via the File System Access API (`createWritable`) is the obvious fix and is not covered by any evidence block here**; it is also Chromium-only, so a single HTML file cannot rely on it universally. Plan for two receive paths: FSA stream where available, Blob assembly (with an explicit size warning) elsewhere.

Bottleneck ordering for a two-PC LAN/WAN transfer: ICE path quality ≫ DataChannel framing ≫ disk write. AES-GCM per chunk [1] adds a per-chunk cost that is negligible next to SCTP/DTLS overhead at these chunk sizes.

---

## 6. Ready-to-use tools

The evidence blocks document only the **DIY pattern** ([1] a working app, [2] a minimal demo). They contain no evaluation of PairDrop, FilePizza, WebTorrent, croc, Holepunch/portal, or WebWormhole — no architecture review, no signaling/relay description, no measurements. Rather than assert facts about those projects from memory and dress them up as findings, the honest mapping is by *architectural class*, which the evidence does support:

| Class | Signaling | Relay | Evidence |
|---|---|---|---|
| Manual code/QR page (this report's target) | none — out-of-band | none (STUN only) | [1], [2] |
| Hosted web app with a signaling server | server required | usually optional TURN | not in evidence |
| CLI/library pairers using a rendezvous service | service required | optional | not in evidence |

The concrete question to ask of any candidate tool is exactly two: *does it need a rendezvous service to introduce the peers, and does it fall back to TURN?* If yes to either, it is not in the same class as [1] and [2].

---

## 7. Direct Sockets and WebTransport

Nothing in [1]–[5] mentions either API; the entire evidence base is `RTCPeerConnection` + `RTCDataChannel` [1][2][3]. The reportable conclusion is therefore narrow: within this corpus, the DataChannel is the only transport demonstrated to work browser-to-browser with no server component at all, and it arrives with mandatory DTLS [3].

Reasoning beyond the evidence, flagged as such: Direct Sockets targets a different problem (a page opening raw TCP/UDP to a host, gated by Isolated Web App installation rather than a plain `file://` HTML page), and WebTransport is client–server by design — it terminates at an HTTP/3 endpoint, so it presupposes the server the question wants to eliminate. Neither replaces WebRTC's peer-to-peer NAT traversal with a manual handshake. This should be re-verified against current browser support before being written into a design doc.

---

## 8. Verdict

A single local HTML file that (a) generates an offer, waits for gathering, encodes it to a QR/code, (b) accepts a pasted answer, (c) streams 64 KiB chunks with `bufferedAmount`-gated backpressure, and (d) writes to disk via FSA where available, is a sound 2026 design that genuinely eliminates the relay and the signaling server. It is not serverless: it needs STUN, it fails on symmetric NAT/CGNAT/UDP-blocked paths with no fallback, and its MITM resistance is only as good as the out-of-band comparison step — which is where a PAKE belongs and where [1]'s in-band session secret does not help.

## Caveats & open questions

1. **No NAT traversal statistics exist in the provided evidence.** Zero measured success rates for symmetric NAT, CGNAT, or UDP-blocked networks; no TURN-usage percentages. Any figure quoted for these would be unsourced.
2. **No PAKE evidence.** SPAKE2, SAS/short-authentication-string comparison, Magic Wormhole, and WebWormhole are not described in [1]–[5]. The PAKE recommendation in §4 is reasoning from the threat model, not a cited finding.
3. **No tool evaluations.** PairDrop, FilePizza, WebTorrent, croc, Holepunch/portal, and WebWormhole are unassessed here; their signaling and relay requirements must be verified from their own docs. §6's table is deliberately class-level only.
4. **No Direct Sockets or WebTransport evidence.** §7's comparison is outside the corpus and depends on browser-support facts that could not be checked.
5. **File System Access API is not covered.** The only documented receive path is in-memory `Blob` assembly [4]; multi-GB-to-disk streaming is an inference, and FSA availability/origin restrictions are unverified.
6. **[5] was available only as title + abstract**, so the 16 KB/64 KB figures and the `bufferedAmount` backpressure guidance are cited at the level of the article's stated scope, not its detailed per-browser table.
7. **Throughput is unquantified.** No measured MB/s for DataChannel transfers between two PCs over LAN or WAN appears in the evidence; the 10 GB chunk counts in §5 are arithmetic, not benchmarks.
8. **[2] is an incomplete reference implementation** (no `createAnswer()`), so it demonstrates the signaling shape rather than a working handshake; treat [1] as the reliability signal.
9. **Security of [1]'s key transport is asserted, not proven.** The claim that the session fingerprint "detects MITM substitution" holds only if the fingerprint is compared over a channel independent of the one carrying the codes — a precondition the source does not state.
