// Streaming playback: when an mp4 carries its 'moov' index before 'mdat'
import type { Bytes } from './storage';

// (faststart), feed received chunks into a MediaSource SourceBuffer in index
// order so playback can start before the transfer completes. Any player error
// just hides the video — the transfer itself never fails because of the player.

const HEAD_WINDOW = 64 * 1024;

export class StreamPlayer {
  private enabled = false;
  private decided = false;
  private failed = false;
  private ms: MediaSource | null = null;
  private sb: SourceBuffer | null = null;
  private url = '';
  private queue: (Bytes | undefined)[] = [];
  private nextAppend = 0;
  private appending = false;
  private head: Bytes[] = [];
  private headLen = 0;
  private eos = false;

  constructor(private readonly video: HTMLVideoElement) {}

  /** Feed the head bytes; decides streaming once 64 KiB (or file end) arrived. */
  considerHead(index: number, data: Bytes, size: number): void {
    if (this.decided) return;
    // only contiguous bytes from 0 count for the moov probe
    if (index !== this.head.length) return;
    this.head.push(data);
    this.headLen += data.length;
    if (this.headLen >= Math.min(HEAD_WINDOW, size)) this.decide(size);
  }

  private decide(size: number): void {
    this.decided = true;
    const head = concat(this.head, this.headLen);
    const moov = indexOfAscii(head, 'moov');
    const mdat = indexOfAscii(head, 'mdat');
    const streamable = moov >= 0 && (mdat < 0 || moov < mdat);
    if (!streamable) {
      console.info('[media] moov at end: streaming disabled');
      return;
    }
    try {
      this.ms = new MediaSource();
      this.enabled = true;
      this.url = URL.createObjectURL(this.ms);
      this.video.src = this.url;
      this.video.style.display = '';
      this.ms.addEventListener('sourceopen', () => this.onSourceOpen());
    } catch {
      this.disable();
    }
  }

  private onSourceOpen(): void {
    if (!this.ms) return;
    const withCodecs = 'video/mp4; codecs="avc1.42E01E, mp4a.40.2"';
    const mime = MediaSource.isTypeSupported(withCodecs) ? withCodecs : 'video/mp4';
    try {
      this.sb = this.ms.addSourceBuffer(mime);
      this.sb.mode = 'segments';
      this.sb.addEventListener('error', () => this.disable());
      this.sb.addEventListener('updateend', () => void this.flush());
      void this.flush();
    } catch {
      this.disable();
    }
  }

  /** Queue a received chunk (any order); appends strictly in index order. */
  push(index: number, data: Bytes): void {
    if (!this.enabled || this.failed) return;
    this.queue[index] = data;
    void this.flush();
  }

  /** All chunks delivered: drain and end the stream. */
  finish(): void {
    if (!this.enabled || this.failed) return;
    this.eos = true;
    void this.flush();
  }

  isActive(): boolean {
    return this.enabled && !this.failed;
  }

  private disable(): void {
    if (this.failed) return;
    this.failed = true;
    this.enabled = false;
    this.video.style.display = 'none';
    if (this.url) URL.revokeObjectURL(this.url);
  }

  private async flush(): Promise<void> {
    if (this.failed) return;
    if (!this.sb) return; // sourceopen drives the first flush
    for (;;) {
      if (this.sb.updating || this.appending) return;
      const chunk = this.queue[this.nextAppend];
      if (!chunk) break;
      this.queue[this.nextAppend] = undefined;
      this.nextAppend++;
      this.appending = true;
      try {
        this.sb.appendBuffer(chunk);
      } catch {
        this.appending = false;
        this.disable();
        return;
      }
      // 'updateend' re-enters flush()
      await this.waitUpdateEnd();
      this.appending = false;
      void this.video.play().catch(() => undefined);
    }
    if (this.eos && !this.sb.updating && this.ms && this.ms.readyState === 'open') {
      try {
        this.ms.endOfStream();
      } catch {
        /* quota/abort — ignore */
      }
    }
  }

  private waitUpdateEnd(): Promise<void> {
    if (!this.sb || !this.sb.updating) return Promise.resolve();
    const { promise, resolve } = Promise.withResolvers<void>();
    this.sb.addEventListener('updateend', () => resolve(), { once: true });
    return promise;
  }
}

function concat(parts: Bytes[], total: number): Bytes {
  const out = new Uint8Array(new ArrayBuffer(total));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function indexOfAscii(hay: Uint8Array, needle: string): number {
  const first = needle.charCodeAt(0);
  for (let i = 0; i + needle.length <= hay.length; i++) {
    if (hay[i] !== first) continue;
    let ok = true;
    for (let j = 1; j < needle.length; j++) {
      if (hay[i + j] !== needle.charCodeAt(j)) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}
