// RTCPeerConnection transport: N ordered/reliable DataChannels (fj-0..N-1),
// non-trickle ICE (gather before pairing), backpressured sends, path badge
// data via getStats, and the STUN-based NAT doctor probe.

export interface IceConfig {
  stunUrls: string[];
  turn?: { urls: string[]; username: string; credential: string };
}

const GATHER_TIMEOUT_MS = 10_000;
export const BACKPRESSURE_HIGH = 1 << 20;
export const BACKPRESSURE_LOW = 256 << 1024;

function rtcConfig(cfg: IceConfig): RTCConfiguration {
  const iceServers: RTCIceServer[] = [];
  if (cfg.stunUrls.length) iceServers.push({ urls: cfg.stunUrls });
  if (cfg.turn) iceServers.push({ urls: cfg.turn.urls, username: cfg.turn.username, credential: cfg.turn.credential });
  return { iceServers };
}


// lib.dom keeps WebRTC stats loosely typed; these narrow the fields we read.
interface PairStat {
  id: string;
  selected?: boolean;
  nominated?: boolean;
  state?: string;
  localCandidateId?: string;
  remoteCandidateId?: string;
}
interface CandStat {
  candidateType?: string;
  address?: string;
  ip?: string;
  port?: number;
}

async function gather(pc: RTCPeerConnection): Promise<void> {
  if (pc.iceGatheringState === 'complete') return;
  const { promise, resolve } = Promise.withResolvers<void>();
  const timer = setTimeout(resolve, GATHER_TIMEOUT_MS);
  pc.addEventListener('icegatheringstatechange', () => {
    if (pc.iceGatheringState === 'complete') resolve();
  });
  await promise;
  clearTimeout(timer);
}

export interface PathInfo {
  kind: string; // 'host' | 'srflx' | 'relay' | 'unknown'
  text: string; // 'DIRECT host' | 'DIRECT srflx' | 'RELAY' | ...
  detail: string; // addresses
}

export class Transport {
  readonly pc: RTCPeerConnection;
  channels: RTCDataChannel[] = [];
  onFrame: ((bytes: Uint8Array) => void) | null = null;
  onFirstOpen: (() => void) | null = null;
  onClosed: (() => void) | null = null;
  private opened = false;
  private closed = false;

  private constructor(pc: RTCPeerConnection, private readonly channelCount: number) {
    this.pc = pc;
    pc.addEventListener('connectionstatechange', () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected' || pc.connectionState === 'closed') {
        this.onClosed?.();
      }
    });
  }

  /** Sender side: create N data channels BEFORE the offer, then gather. */
  static async offerer(cfg: IceConfig, channels: number): Promise<Transport> {
    const pc = new RTCPeerConnection(rtcConfig(cfg));
    const t = new Transport(pc, channels);
    for (let i = 0; i < channels; i++) {
      const ch = pc.createDataChannel(`fj-${i}`, { ordered: true });
      t.wire(ch);
    }
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await gather(pc);
    return t;
  }

  /** Receiver side: apply the offer, answer, gather. Channels arrive inbound. */
  static async answerer(cfg: IceConfig, offerSdp: string): Promise<Transport> {
    const pc = new RTCPeerConnection(rtcConfig(cfg));
    const t = new Transport(pc, 1);
    pc.ondatachannel = (e) => t.wire(e.channel);
    await pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await gather(pc);
    return t;
  }

  get offerSdp(): string {
    return this.pc.localDescription?.sdp ?? '';
  }

  get answerSdp(): string {
    return this.pc.localDescription?.sdp ?? '';
  }

  private wire(ch: RTCDataChannel): void {
    this.channels.push(ch);
    ch.binaryType = 'arraybuffer';
    ch.bufferedAmountLowThreshold = BACKPRESSURE_LOW;
    ch.onopen = () => {
      if (!this.opened) {
        this.opened = true;
        this.onFirstOpen?.();
      }
    };
    ch.onmessage = (e) => {
      if (e.data instanceof ArrayBuffer) this.onFrame?.(new Uint8Array(e.data));
      else if (e.data instanceof Blob) void e.data.arrayBuffer().then((b) => this.onFrame?.(new Uint8Array(b)));
    };
    ch.onerror = () => {
      if (!this.opened) this.onClosed?.();
    };
  }

  async applyAnswer(sdp: string): Promise<void> {
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
  }

  /** Wait until every requested channel is open (or a short timeout after the first). */
  async waitAllOpen(timeoutMs = 3000): Promise<void> {
    const want = Math.max(1, this.channelCount);
    const start = performance.now();
    for (;;) {
      const open = this.channels.filter((c) => c.readyState === 'open').length;
      if (open >= want || this.closed) return;
      if (this.opened && performance.now() - start > timeoutMs) return;
      await new Promise((r) => setTimeout(r, 20));
    }
  }

  isOpen(): boolean {
    return !this.closed && this.channels.some((c) => c.readyState === 'open');
  }

  private ch(i: number): RTCDataChannel | null {
    if (!this.channels.length) return null;
    return this.channels[i % this.channels.length];
  }

  /** Send honoring backpressure; throws when the channel is gone. */
  async sendBackpressured(chIdx: number, bytes: Uint8Array<ArrayBuffer>): Promise<void> {
    const ch = this.ch(chIdx);
    if (!ch) throw new Error('no data channel');
    for (;;) {
      if (ch.readyState !== 'open') throw new Error('data channel closed');
      if (ch.bufferedAmount <= BACKPRESSURE_HIGH) break;
      const { promise, resolve } = Promise.withResolvers<void>();
      const timer = setTimeout(resolve, 200);
      ch.addEventListener('bufferedamountlow', () => resolve(), { once: true });
      await promise;
      clearTimeout(timer);
    }
    ch.send(bytes);
  }

  /** Send on every currently-open channel (open-time announcements). */
  sendAll(bytes: Uint8Array<ArrayBuffer>): void {
    for (const ch of this.channels) {
      if (ch.readyState === 'open') ch.send(bytes);
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.pc.close();
    } catch {
      /* already closed */
    }
  }

  /** Selected candidate pair info for the path badge. */
  async pathInfo(): Promise<PathInfo | null> {
    let stats: RTCStatsReport;
    try {
      stats = await this.pc.getStats();
    } catch {
      return null;
    }
    const pairs = new Map<string, PairStat>();
    const cands = new Map<string, CandStat>();
    stats.forEach((r) => {
      if (r.type === 'candidate-pair') pairs.set(r.id, r as PairStat); // stats are untyped in lib.dom
      else if (r.type === 'local-candidate' || r.type === 'remote-candidate') cands.set(r.id, r as CandStat);
    });
    let chosen: PairStat | undefined;
    for (const p of pairs.values()) {
      if (p.selected || (p.nominated && p.state === 'succeeded')) {
        chosen = p;
        break;
      }
    }
    if (!chosen) for (const p of pairs.values()) if (p.state === 'succeeded') chosen = p;
    if (!chosen) return null;
    const local = cands.get(chosen.localCandidateId ?? '');
    const remote = cands.get(chosen.remoteCandidateId ?? '');
    const kind = local?.candidateType ?? 'unknown';
    const la = `${local?.address ?? local?.ip ?? '?'}:${local?.port ?? '?'}`;
    const ra = `${remote?.address ?? remote?.ip ?? '?'}:${remote?.port ?? '?'}`;
    const text = kind === 'relay' ? 'RELAY' : kind === 'unknown' ? kind : `DIRECT ${kind}`;
    return { kind, text, detail: `${kind} ${la} -> ${ra}` };
  }
}

// ---------------------------------------------------------------------------
// NAT doctor: two independent STUN probes, compare srflx ip:port.
// ---------------------------------------------------------------------------

export interface DoctorResult {
  klass: 'cone' | 'symmetric' | 'blocked' | 'none';
  detail: string;
}


async function srflxProbe(url: string, timeoutMs: number): Promise<string[]> {
  const pc = new RTCPeerConnection({ iceServers: [{ urls: [url] }] });
  pc.createDataChannel('fj-doctor');
  const found: string[] = [];
  const { promise, resolve } = Promise.withResolvers<void>();
  const timer = setTimeout(resolve, timeoutMs);
  pc.addEventListener('icecandidate', (e) => {
    if (!e.candidate) {
      resolve();
      return;
    }
    if (e.candidate.type === 'srflx' && e.candidate.component === 'rtp') {
      found.push(`${e.candidate.address}:${e.candidate.port}`);
    }
  });
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await promise;
  clearTimeout(timer);
  pc.close();
  return found;
}

export async function doctorProbe(urls: string[]): Promise<DoctorResult> {
  const clean = urls.map((u) => u.trim()).filter(Boolean);
  if (!clean.length) {
    return {
      klass: 'none',
      detail: 'doctor: no STUN servers configured; NAT classification needs STUN (Advanced). LAN transfers use host candidates.',
    };
  }
  const a = await srflxProbe(clean[0], 6000);
  const b = await srflxProbe(clean[1] ?? clean[0], 6000);
  if (!a.length && !b.length) {
    return {
      klass: 'blocked',
      detail: 'doctor: no STUN responses (UDP blocked or servers unreachable); internet P2P unlikely, LAN still works via host candidates.',
    };
  }
  const same = a.length > 0 && b.length > 0 && a.some((x) => b.includes(x));
  if (same) {
    return { klass: 'cone', detail: 'doctor: Cone NAT (same public ip:port on both probes); direct P2P likely.' };
  }
  return {
    klass: 'symmetric',
    detail: 'doctor: Symmetric NAT likely (public endpoint differs per probe); direct P2P will probably fail, use a TURN server or another network.',
  };
}
