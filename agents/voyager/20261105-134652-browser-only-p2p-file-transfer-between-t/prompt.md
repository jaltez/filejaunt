# Research prompt

Browser-only P2P file transfer between two PCs (2026): feasibility of direct WebRTC DataChannel transfer with zero relay and zero signaling server via manual SDP or QR-code exchange from a single local HTML file; measured success rates of NAT traversal without TURN (symmetric NAT, CGNAT, UDP blocked); security model (DTLS, SDP fingerprint MITM by malicious signaling server, PAKE pairing like Magic Wormhole SPAKE2 or WebWormhole, website-served-JS trust problem); streaming multi-GB files in the browser with File System Access API and DataChannel backpressure; ready-to-use open source tools (PairDrop, FilePizza, WebTorrent, croc, Holepunch portal, WebWormhole) and their signaling/relay needs; whether Direct Sockets API or WebTransport eliminate the need for WebRTC

- provider chain: ddgs
- depth: 3..3
- breadth: 4
- budget: unbounded
- llm: harness shell-out: pi --print
