// Signaling-relay transport for the pairing blobs (Wormhole-style):
// both peers derive the same room id from the passphrase (wasm
// roomFromPassphrase) and exchange the opaque blobs through a self-hosted
// fj-relay (crates/fj-relay). The relay sees the room id and ciphertext
// only — never the passphrase, keys or SDP in clear.
//
// Wire protocol (JSON text frames):
//   → {"t":"join","room":"<hex8>"}   ← {"t":"joined"} | {"t":"peer-joined"}
//   → {"t":"msg","data":"<blob>"}    ← {"t":"msg","data":"<blob>"}
//   ← {"t":"peer-left"} | {"t":"error"}  ⇒ Gone: fail fast, like the CLI's
//     RelayHandle.
//
// The sender must waitPeer() before sending blob-1: the relay forwards only
// to peers currently in the room.

const WAIT_MS = 120_000; // CLI parity: two minutes to meet in the room

interface PeerWait {
  resolve: () => void;
  reject: (e: Error) => void;
  timer: number;
}

interface BlobWait {
  resolve: (blob: string) => void;
  reject: (e: Error) => void;
  timer: number;
}

export class RelayChannel {
  /** Fired once on peer-left / relay error / socket close (fail fast). */
  onGone: ((reason: string) => void) | null = null;

  private readonly ws: WebSocket;
  private peerJoined = false;
  private gone = false;
  private readonly blobs: string[] = [];
  private readonly peerWaiters: PeerWait[] = [];
  private blobWait: BlobWait | null = null;

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.onmessage = (ev) => this.onFrame(String(ev.data));
    ws.onclose = () => this.bye('relay connection closed');
    ws.onerror = () => this.bye('relay connection error');
  }

  /** Connect and join `room`; rejects if the relay is unreachable. */
  static connect(url: string, room: string): Promise<RelayChannel> {
    const { promise, resolve, reject } = Promise.withResolvers<RelayChannel>();
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      reject(new Error(`bad relay url: ${e}`));
      return promise;
    }
    const rc = new RelayChannel(ws);
    const opened = () => {
      cleanup();
      rc.sendJson({ t: 'join', room });
      resolve(rc);
    };
    const failed = () => {
      cleanup();
      rc.silence();
      try {
        ws.close();
      } catch {
        /* already closed */
      }
      reject(new Error(`cannot reach relay ${url}`));
    };
    const cleanup = () => {
      ws.removeEventListener('open', opened);
      ws.removeEventListener('error', failed);
      ws.removeEventListener('close', failed);
    };
    ws.addEventListener('open', opened);
    ws.addEventListener('error', failed);
    ws.addEventListener('close', failed);
    return promise;
  }

  /** Resolve once the other peer is in the room (the sender speaks first). */
  waitPeer(): Promise<void> {
    if (this.gone) return Promise.reject(new Error('relay gone'));
    if (this.peerJoined) return Promise.resolve();
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const timer = setTimeout(() => {
      const i = this.peerWaiters.findIndex((w) => w.resolve === resolve);
      if (i >= 0) this.peerWaiters.splice(i, 1);
      reject(new Error('the other side did not join in time'));
    }, WAIT_MS);
    this.peerWaiters.push({ resolve, reject, timer });
    return promise;
  }

  /** Next blob the peer sent through the room. */
  nextBlob(): Promise<string> {
    if (this.gone) return Promise.reject(new Error('relay gone'));
    const head = this.blobs.shift();
    if (head !== undefined) return Promise.resolve(head);
    if (this.blobWait) return Promise.reject(new Error('a blob wait is already pending'));
    const { promise, resolve, reject } = Promise.withResolvers<string>();
    const timer = setTimeout(() => {
      this.blobWait = null;
      reject(new Error('nothing arrived from the peer in time'));
    }, WAIT_MS);
    this.blobWait = { resolve, reject, timer };
    return promise;
  }

  /** Send one opaque blob to the peer. */
  send(text: string): void {
    this.sendJson({ t: 'msg', data: text });
  }

  close(): void {
    this.silence();
    try {
      this.ws.close();
    } catch {
      /* already closed */
    }
  }

  /** Stop firing callbacks without touching pending state (teardown). */
  private silence(): void {
    this.gone = true;
    this.onGone = null;
  }

  private sendJson(v: unknown): void {
    if (!this.gone && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(v));
  }

  private onFrame(line: string): void {
    if (this.gone) return;
    let v: { t?: string; data?: string; msg?: string };
    try {
      v = JSON.parse(line);
    } catch {
      return;
    }
    switch (v.t) {
      case 'peer-joined': {
        this.peerJoined = true;
        const waiters = this.peerWaiters.splice(0);
        for (const w of waiters) {
          clearTimeout(w.timer);
          w.resolve();
        }
        break;
      }
      case 'msg': {
        if (typeof v.data !== 'string') return;
        const wait = this.blobWait;
        if (wait) {
          this.blobWait = null;
          clearTimeout(wait.timer);
          wait.resolve(v.data);
        } else {
          this.blobs.push(v.data);
        }
        break;
      }
      case 'peer-left':
        this.bye('peer left the room');
        break;
      case 'error':
        this.bye(`relay error: ${v.msg ?? 'unknown'}`);
        break;
      default:
        break; // "joined"/slot bookkeeping — nothing to act on
    }
  }

  private bye(reason: string): void {
    if (this.gone) return;
    this.gone = true;
    const err = new Error(reason);
    for (const w of this.peerWaiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(err);
    }
    if (this.blobWait) {
      clearTimeout(this.blobWait.timer);
      this.blobWait.reject(err);
      this.blobWait = null;
    }
    this.onGone?.(reason);
    this.onGone = null;
  }
}
