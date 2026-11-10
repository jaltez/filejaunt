// filejaunt engine: transport <-> WASM core <-> storage, with zero DOM access.
//
// This is the library surface other UIs build on. It owns the pairing state
// machine, the transfer pump, session persistence (IndexedDB snapshots) and
// receiver storage, and reports everything through `JauntEvents`. The bundled
// example (main.ts) is a minimal DOM adapter; filejaunt.com ships a richer one.
//
// Pairing (p2, default): sender creates the offer, then blob-1 (offer in
// clear); receiver answers, blob-2 carries the answer ENCRYPTED. The WASM
// facade does not expose the decrypted answer to JS, so the receiver appends
// its own clear answer below the blob (separator line "-----"); the HELO
// fingerprint (HMAC-SHA256 over offer+answer) still detects any SDP
// substitution, so this keeps p2's authentication guarantees.

import { E2E, Hasher, newFjCore, parsePairingCode, roomFromPassphrase, type FjCore, type FjActionJson } from './wasm';
import { Transport, doctorProbe, type DoctorResult, type IceConfig, type PathInfo } from './transport';
import { ReceiverStore, type FjDirHandle, type Sink } from './storage';
import type { Bytes } from './storage';
import { RelayChannel } from './relay';

const CHUNK = 16384;
const HASH_FEED_SLICE = 1 << 20;

type Expect = 'none' | 'sender-blob2' | 'sender-blob4' | 'recv-blob1' | 'recv-blob3';
export type JauntState = 'idle' | 'pairing' | 'paired' | 'transferring' | 'done' | 'failed';
export type JauntRole = 'sender' | 'receiver';

/** One manifest file as the UI should render it. */
export interface FileView {
  id: number;
  name: string;
  /** Folder path ("photos/2024"); empty for top-level files. */
  path: string;
  size: number;
  progress: number; // 0..100
  wireBytes: number;
  sha256?: string;
  verified?: boolean;
  paused?: boolean;
  /** Live share: the sender removed this file; the receiver keeps its copy. */
  removed?: boolean;
  sinkLabel?: string;
}

/** Everything the engine reports to its host UI. All callbacks are optional. */
export interface JauntEvents {
  log(line: string): void;
  step(text: string): void;
  state(state: JauntState): void;
  passphrase(text: string): void;
  /** Relay pairing: the one-line `fj-<room8>-<words>` code to hand to the peer. */
  pairingCode(code: string): void;
  /** Relay pairing: "XXXX XXXX" — must match on both screens, else the
   *  signaling channel is MITM'd. Paste mode never emits this. */
  checksum(sum: string): void;
  blobOut(blob: string): void;
  files(files: FileView[]): void;
  /** Live share: the peer appended files (entries carry `supersedes` when a
   *  previously synced file was replaced). */
  filesAdded?(entries: ManifestFileJson[]): void;
  text(text: string): void;
  path(info: PathInfo | null): void;
  download(name: string, blob: Blob): void;
  doctor(result: DoctorResult): void;
  /** New session state: the UI should clear its per-session views. */
  reset(): void;
}

/** Minimal streaming player contract (media.ts StreamPlayer satisfies it). */
export interface JauntPlayer {
  considerHead(index: number, data: Bytes, size: number): void;
  push(index: number, data: Bytes): void;
  finish(): void;
  isActive(): boolean;
}

export interface JauntOptions {
  events?: Partial<JauntEvents>;
  /** ICE servers for each new peer connection (defaults to none = LAN only). */
  getIce?: () => IceConfig;
  /** Signaling relay URL (wss://…) for one-line-code pairing; null/empty
   *  keeps the paste (blob) flow — the default. Self-hosted fj-relay only;
   *  the relay sees the room id and ciphertext, never keys or SDP in clear. */
  getRelay?: () => string | null;
  /** Called when the incoming manifest contains an mp4; return null to skip playback. */
  createPlayer?: () => JauntPlayer | null;
}

export interface SendOptions {
  words?: number;
  privatePairing?: boolean;
  channels?: number;
  gzip?: 'auto' | 'on' | 'off';
  ice?: IceConfig;
  /** Live share: keep the session open after the files settle, allow
   *  appends and chat until either side leaves (needs a peer that
   *  advertises the capability; old peers fall back to one-shot). */
  live?: boolean;
}

/** A file with an explicit folder path, so several directory picks can
 *  share one session ("photos/2024/img.jpg"). Plain File objects keep
 *  their webkitRelativePath. */
export interface ShareEntry {
  file: File;
  path: string;
  /** Live edit: id of the sender-side record this file replaces (same
   *  name+path). The core retires the old id and the receiver drops it. */
  supersedes?: number;
}

export interface SenderStartResult {
  sid: string;
  passphrase: string;
  blob1: string;
}

interface FileRec {
  id: number;
  name: string;
  path: string;
  size: number;
  chunks: number;
  chunkSize: number;
  sha256?: string;
  verified?: boolean;
  progress: number;
  wireBytes: number;
  source?: File;
  sink?: Sink;
  sinkLabel?: string;
  paused?: boolean;
  /** Live share: removed on the sender (bytes are kept locally). */
  removed?: boolean;
}

/** One manifest entry as JSON (mirrors the core's FileEntry). */
export interface ManifestFileJson {
  id: number;
  name: string;
  path: string;
  size: number;
  chunks: number;
  chunk_size: number;
  supersedes?: number;
}

/** A folder whose changes the sender mirrors into a live session. */
interface WatchedRoot {
  /** First path component ("photos"). */
  name: string;
  /** File System Access root (Chromium); absent for input-picked roots. */
  handle?: FileSystemDirectoryHandle;
  /** Set when the page must re-request read permission (lost on reload). */
  needsGrant?: boolean;
  /** Baseline snapshot: subpath (after the root) -> file metadata. */
  files: Map<string, { file: File; mtime: number; size: number }>;
}

/** Mirrors the debug state exposed as `window.__fj` by the example app. */
export interface JauntHook {
  state: JauntState;
  lastActions: FjActionJson[];
  files: { name: string; sha256?: string; verified?: boolean; progress: number; wireBytes: number }[];
  resumedChunks: number;
  wireBytes: number;
  path: string;
  sid: string;
  passphrase: string;
  /** Relay pairing: the one-line `fj-<room8>-<words>` code ('' in paste mode). */
  code: string;
  /** Relay pairing: "XXXX XXXX" verification checksum ('' until paired). */
  checksum: string;
  blob1: string;
  log: string[];
  receipts: unknown[];
  doctor: { klass: string; detail: string } | null;
}

// ---------------------------------------------------------------------------
// IndexedDB session snapshots (db "filejaunt", store "sessions", key sid)
// ---------------------------------------------------------------------------

function idb(): Promise<IDBDatabase> {
  const { promise, resolve, reject } = Promise.withResolvers<IDBDatabase>();
  const req = indexedDB.open('filejaunt', 1);
  req.onupgradeneeded = () => {
    if (!req.result.objectStoreNames.contains('sessions')) req.result.createObjectStore('sessions');
  };
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
  return promise;
}

async function idbPut(key: string, value: string): Promise<void> {
  const db = await idb();
  const { promise, resolve, reject } = Promise.withResolvers<void>();
  const tx = db.transaction('sessions', 'readwrite');
  tx.objectStore('sessions').put(value, key);
  tx.oncomplete = () => resolve();
  tx.onerror = () => reject(tx.error);
  await promise;
  db.close();
}

async function idbGet(key: string): Promise<string | undefined> {
  const db = await idb();
  const { promise, resolve, reject } = Promise.withResolvers<string | undefined>();
  const tx = db.transaction('sessions', 'readonly');
  const req = tx.objectStore('sessions').get(key);
  req.onsuccess = () => resolve(req.result as string | undefined);
  req.onerror = () => reject(req.error);
  const out = await promise;
  db.close();
  return out;
}

// ---------------------------------------------------------------------------
// Envelope-1 inflation (browser side, needed for the clear offer + sid).
// Envelope = "FJ1." + base64url_nopad(gzip(JSON)). No fetch: blob streams +
// DecompressionStream only (CSP default-src 'none').
// ---------------------------------------------------------------------------

interface Envelope1 {
  v: number;
  sid: string;
  pake: string;
  sdp?: string;
  ep: number;
  mode: 'p2' | 'p3';
  ch?: number;
}

async function inflateBlob1(raw: string): Promise<Envelope1> {
  const text = raw.trim();
  if (!text.startsWith('FJ1.')) throw new Error('PROTO_MALFORMED: not a filejaunt blob (missing FJ1. prefix)');
  let b64 = text.slice(4).replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    throw new Error('PROTO_MALFORMED: bad base64 in blob');
  }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const DS: typeof DecompressionStream | undefined = globalThis.DecompressionStream;
  if (!DS) throw new Error('PROTO_MALFORMED: DecompressionStream unavailable');
  const stream = new Blob([bytes]).stream().pipeThrough(new DS('gzip'));
  let json: string;
  try {
    // hard cap mirrored from the core (64 KiB decompressed)
    const reader = stream.getReader();
    const parts: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.length;
        if (total > 64 * 1024) {
          void reader.cancel();
          throw new Error('PROTO_MALFORMED: envelope decompressed exceeds 64 KiB');
        }
        parts.push(value);
      }
    }
    const merged = new Uint8Array(new ArrayBuffer(total));
    let o = 0;
    for (const p of parts) {
      merged.set(p, o);
      o += p.length;
    }
    json = new TextDecoder().decode(merged);
  } catch (e) {
    if (String(e).includes('PROTO_MALFORMED')) throw e;
    throw new Error('PROTO_MALFORMED: bad gzip in blob');
  }
  try {
    return JSON.parse(json) as Envelope1;
  } catch {
    throw new Error('PROTO_MALFORMED: bad JSON in blob');
  }
}

const NO_EVENTS: JauntEvents = {
  log: () => {},
  step: () => {},
  state: () => {},
  passphrase: () => {},
  pairingCode: () => {},
  checksum: () => {},
  blobOut: () => {},
  files: () => {},
  text: () => {},
  path: () => {},
  download: () => {},
  doctor: () => {},
  reset: () => {},
};

// ---------------------------------------------------------------------------
// Jaunt
// ---------------------------------------------------------------------------

export class Jaunt {
  /** Live state for debugging and e2e (the example assigns it to window.__fj). */
  readonly hook: JauntHook;

  private readonly events: JauntEvents;
  private readonly getIce: () => IceConfig;
  private readonly getRelay: (() => string | null) | undefined;
  private readonly createPlayer: (() => JauntPlayer | null) | undefined;

  private core: FjCore | null = null;
  private transport: Transport | null = null;
  private store: ReceiverStore | null = null;
  private player: JauntPlayer | null = null;
  private playerFileId: number | null = null;
  private pickedDir: FjDirHandle | null = null;
  private roleValue: JauntRole | null = null;
  private expect: Expect = 'none';
  private privatePairing = false;
  private passphrase = '';
  private channelCount = 1;
  private gzipMode: 'auto' | 'on' | 'off' = 'auto';
  private manifestLoaded = false;
  private chain: Promise<void> = Promise.resolve();
  private relayMode = false;
  private relay: RelayChannel | null = null;
  /** True while a relay exchange drives onProcess: resetSession() (run at
   *  the top of receiverJoin) must not tear the channel down. */
  private relayBusy = false;
  private pumpGen = 0;
  private badgeTimer = 0;
  private lastIce: IceConfig = { stunUrls: [] };
  private readonly recs: FileRec[] = [];
  /** Live folder sync (M4): watched roots and their polling loop. */
  private watched: WatchedRoot[] = [];
  private watchTimer: number | null = null;
  /** Serializes root scans (poll, manual re-scan, picks) to one flight. */
  private scanChain: Promise<void> = Promise.resolve();
  private readonly onVisibility = (): void => {
    if (typeof document !== 'undefined' && document.visibilityState === 'visible') void this.rescan();
  };
  private readonly onFocus = (): void => {
    if (this.isLive) void this.rescan();
  };

  private constructor(opts: JauntOptions) {
    this.events = { ...NO_EVENTS, ...opts.events };
    this.getIce = opts.getIce ?? (() => ({ stunUrls: [] }));
    this.getRelay = opts.getRelay;
    this.createPlayer = opts.createPlayer;
    this.hook = {
      state: 'idle',
      lastActions: [],
      files: [],
      resumedChunks: 0,
      wireBytes: 0,
      path: '',
      sid: '',
      passphrase: '',
      code: '',
      checksum: '',
      blob1: '',
      log: [],
      receipts: [],
      doctor: null,
    };
  }

  /** Create the engine and warm the WASM module. */
  static async create(opts: JauntOptions = {}): Promise<Jaunt> {
    const jaunt = new Jaunt(opts);
    void newFjCore(); // warm the WASM module
    return jaunt;
  }

  /** Current role (set by the UI before calling send/process). */
  get role(): JauntRole | null {
    return this.roleValue;
  }

  setRole(role: JauntRole): void {
    this.roleValue = role;
    this.expect = role === 'sender' ? 'none' : 'recv-blob1';
    this.log(`role: ${role}`);
  }

  /** Pick files (sender side) and start a new session. Entries may carry
   *  an explicit folder path so several directory picks share one session. */
  async send(entries: (File | ShareEntry)[], opts: SendOptions = {}): Promise<void> {
    this.roleValue = 'sender';
    await this.startSender(entries, opts);
  }

  /** Feed the engine the blob pasted from the other side (state machine). */
  async process(blob: string, passphrase: string): Promise<void> {
    await this.onProcess(blob.trim(), passphrase.trim());
  }

  /** Relay pairing: paste the peer's one-line code (`fj-<room8>-<words>`,
   *  or a bare passphrase — the room is derived from it). The blobs cross
   *  through a self-hosted fj-relay room; nothing is pasted by hand. Needs
   *  JauntOptions.getRelay to return a URL, else it fails with a step hint. */
  async pair(code: string): Promise<void> {
    const url = this.getRelay?.() || null;
    if (!url) {
      this.events.step('no relay configured — pair by pasting blobs instead');
      this.log('relay pairing requested but getRelay() is empty');
      return;
    }
    this.roleValue = 'receiver';
    this.expect = 'recv-blob1';
    if (!this.core) this.core = await newFjCore();
    const parsed = await parsePairingCode(code);
    const pass = parsed ? parsed.passphrase : code.trim();
    const room = parsed ? parsed.room : await roomFromPassphrase(pass);
    this.relayMode = true;
    this.relayBusy = true;
    this.setState('pairing');
    let rc: RelayChannel;
    try {
      rc = await RelayChannel.connect(url, room);
    } catch (e) {
      this.relayBusy = false;
      this.fail(`relay connect failed: ${e}`);
      return;
    }
    this.relay = rc;
    // no onGone fail-fast (see senderRelayExchange): pending nextBlob
    // waits reject on their own; leaving after our reply is not an error
    this.log(`relay pairing: room ${room}`);
    try {
      this.events.step('waiting for the sender…');
      const blob1 = await rc.nextBlob();
      const blob2 = await this.onProcess(blob1, pass);
      if (blob2) rc.send(blob2);
      if ((this.expect as Expect) === 'recv-blob3') {
        const blob3 = await rc.nextBlob();
        const blob4 = await this.onProcess(blob3, '');
        if (blob4) rc.send(blob4);
      }
    } catch (e) {
      rc.close();
      if (this.hook.state !== 'failed') this.fail(`relay exchange failed: ${e}`);
    } finally {
      // grace close: give the sender time to consume our reply before the
      // room broadcasts peer-left (it raced applyAnswer behind proxies)
      setTimeout(() => rc.close(), 750);
      this.relayBusy = false;
      this.relay = null;
    }
  }

  /** Re-pair the same session with a receiver after a drop (same passphrase). */
  async restart(): Promise<void> {
    await this.restartSender();
  }

  /** Send a text message over the open channel. Returns false if not paired. */
  async sendText(text: string): Promise<boolean> {
    if (!text || !this.core || !this.transport) return false;
    try {
      await this.transport.sendBackpressured(0, this.core.sendText(text));
      return true;
    } catch (e) {
      this.log(`text send failed: ${e}`);
      return false;
    }
  }

  /** True while this is a live share both sides keep open (chat and
   *  appends allowed until someone leaves). */
  get isLive(): boolean {
    return this.hook.state !== 'done' && this.hook.state !== 'failed' && (this.core?.isLive() ?? false);
  }

  /** Live share: add files to the running session. Hashes first, then
   *  hands the specs to the core, which emits the APPEND frame. An entry
   *  with `supersedes` replaces that record (same name+path). */
  async appendFiles(entries: (File | ShareEntry)[]): Promise<boolean> {
    const items = entries.map(normalizeEntry);
    if (!items.length || !this.core || !this.transport) return false;
    const specs: { name: string; path: string; size: number; sha256: string; gzip: boolean; supersedes?: number }[] = [];
    for (const { file, path, supersedes } of items) {
      const spec: { name: string; path: string; size: number; sha256: string; gzip: boolean; supersedes?: number } = {
        name: file.name,
        path,
        size: file.size,
        sha256: await this.sha256Hex(file),
        gzip: this.gzipMode === 'on',
      };
      if (supersedes !== undefined) spec.supersedes = supersedes;
      specs.push(spec);
    }
    try {
      // ids continue the manifest, not the local rec list (superseded
      // receiver records are dropped, so recs.length can lag) — read the
      // current ids BEFORE the core extends the manifest
      const ids = this.core.fileIds();
      const base = ids.length ? ids[ids.length - 1] + 1 : 0;
      this.core.appendFiles(JSON.stringify(specs));
      // flush APPEND before the pump can see the new ids: the pump only
      // plans records that exist, and those are created after this await
      await this.applyActions(this.take());
      specs.forEach((s, i) =>
        this.recs.push({
          id: base + i,
          name: s.name,
          path: s.path,
          size: s.size,
          chunks: Math.ceil(s.size / CHUNK),
          chunkSize: CHUNK,
          progress: 0,
          wireBytes: 0,
          source: items[i].file,
        }),
      );
      if (this.gzipMode === 'auto') {
        for (let i = 0; i < items.length; i++) {
          const f = items[i].file;
          const samples: Uint8Array[] = [];
          for (let c = 0; c < 4; c++) {
            const s = new Uint8Array(await f.slice(c * CHUNK, Math.min((c + 1) * CHUNK, f.size)).arrayBuffer());
            if (s.length) samples.push(s);
          }
          this.core.resolveGzipAuto(base + i, samples);
        }
      }
      this.emitFiles();
      this.log(`appended ${items.length} file(s)`);
      return true;
    } catch (e) {
      this.log(`append failed: ${e}`);
      this.events.step(String(e));
      return false;
    }
  }

  /** Live folder sync: mirror an FSA directory into the session. Reads the
   *  tree now, registers a watched root and returns the entries it staged
   *  (pre-start callers start the share with them; an active live session
   *  gets an APPEND/REMOVE diff directly). Re-picking the same directory
   *  (a fresh handle object) merges into the existing root; a different
   *  directory with the same base name is refused because both would share
   *  the same output folder. */
  async watchFolder(handle: FileSystemDirectoryHandle): Promise<ShareEntry[]> {
    if (this.freshPick() && (this.recs.length || this.watched.length)) this.clearStalePicks();
    let root = this.watched.find((r) => r.name === handle.name && r.handle === handle);
    if (!root) {
      for (const r of this.watched) {
        if (r.name !== handle.name || !r.handle) continue;
        if (await r.handle.isSameEntry(handle)) {
          root = r;
          r.handle = handle;
          break;
        }
      }
    }
    if (!root) {
      if (this.watched.some((r) => r.name === handle.name)) {
        this.events.step(`a different folder named ${handle.name} is already watched; rename one`);
        return [];
      }
      root = { name: handle.name, handle, files: new Map() };
      this.watched.push(root);
    }
    const watched = root;
    const entries = await this.enqueueScan(() => this.syncRoot(watched), []);
    if (this.hook.state === 'transferring') this.startWatchPolling();
    return entries;
  }

  /** Live folder sync for webkitdirectory inputs (Firefox/Safari fallback):
   *  group by first path component, register/refresh each root's baseline,
   *  and diff it against the session. Re-picking the folder is the manual
   *  sync step where FSA handles are unavailable. */
  async addFolderPick(files: File[]): Promise<ShareEntry[]> {
    if (this.freshPick() && (this.recs.length || this.watched.length)) this.clearStalePicks();
    interface PickedFile {
      file: File;
      mtime: number;
    }
    const groups = new Map<string, Map<string, PickedFile>>();
    for (const file of files) {
      const rel = (file.webkitRelativePath ?? '').replace(/^\/+/, '');
      const slash = rel.indexOf('/');
      if (slash < 0) continue; // not a directory pick: nothing to watch
      const rootName = rel.slice(0, slash);
      const sub = rel.slice(slash + 1);
      let group = groups.get(rootName);
      if (!group) groups.set(rootName, (group = new Map()));
      group.set(sub, { file, mtime: file.lastModified });
    }
    const entries: ShareEntry[] = [];
    for (const [rootName, group] of groups) {
      let root = this.watched.find((r) => r.name === rootName && !r.handle);
      if (!root) {
        root = { name: rootName, files: new Map() };
        this.watched.push(root);
      }
      const watched = root;
      const next = new Map<string, { file: File; mtime: number; size: number }>();
      for (const [sub, picked] of group) next.set(sub, { file: picked.file, mtime: picked.mtime, size: picked.file.size });
      entries.push(...(await this.enqueueScan(() => this.applyRootDiff(watched, next), [])));
    }
    return entries;
  }

  /** Live folder sync: re-read every FSA-backed root now (the manual
   *  Re-scan affordance; the ~3 s poll calls this while visible). */
  async rescan(): Promise<void> {
    await this.enqueueScan(async () => {
      for (const root of this.watched) {
        if (root.handle) await this.syncRoot(root);
      }
    }, undefined);
  }

  /** Re-request read access for a watched root (must run from a click:
   *  permission prompts need a user gesture). */
  async grantRoot(name: string): Promise<void> {
    const root = this.watched.find((r) => r.name === name && r.handle);
    if (!root?.handle) return;
    const h = root.handle;
    if (h.requestPermission) {
      const state = await h.requestPermission({ mode: 'read' });
      if (state !== 'granted') {
        this.events.step(`access to ${name} was not granted`);
        return;
      }
    }
    root.needsGrant = false;
    const watched = root;
    await this.enqueueScan(() => this.syncRoot(watched), []);
    this.events.step(`re-granted access to ${name}; watching again`);
  }

  /** Live share: leave cleanly (BYE to the peer, session ends). */
  endSession(): void {
    if (!this.core) return;
    try {
      this.core.endSession();
      void this.applyActions(this.take());
    } catch (e) {
      this.log(`end failed: ${e}`);
    }
  }

  async togglePause(id: number): Promise<void> {
    const rec = this.recById(id);
    if (!rec || !this.core) return;
    rec.paused = !rec.paused;
    if (rec.paused) this.core.pause(rec.id);
    else this.core.resume(rec.id);
    await this.applyActions(this.take());
    this.emitFiles();
  }

  async cancel(id: number): Promise<void> {
    const rec = this.recById(id);
    if (!rec || !this.core) return;
    this.core.cancel(rec.id);
    await this.applyActions(this.take());
    this.log(`cancelled ${rec.name}`);
    this.emitFiles();
  }

  /** Save received files into a user-picked directory (File System Access). */
  setDir(dir: FjDirHandle | null): void {
    this.pickedDir = dir;
  }

  async diagnose(stunUrls: string[]): Promise<DoctorResult> {
    const result = await doctorProbe(stunUrls);
    this.hook.doctor = result;
    this.events.doctor(result);
    this.log(result.detail);
    return result;
  }

  async pathInfo(): Promise<PathInfo | null> {
    return this.transport ? this.transport.pathInfo() : null;
  }

  /** True when the current pairing runs over a signaling relay. */
  get isRelay(): boolean {
    return this.relayMode;
  }

  /** Close transport and timers. The engine is unusable afterwards. */
  destroy(): void {
    this.pumpGen++;
    clearInterval(this.badgeTimer);
    this.stopWatchPolling();
    this.relay?.close();
    this.relay = null;
    this.transport?.close();
    this.transport = null;
  }

  // -- internals --------------------------------------------------------------

  private recById(id: number): FileRec | undefined {
    return this.recs.find((r) => r.id === id);
  }

  private setState(s: JauntState): void {
    this.hook.state = s;
    this.events.state(s);
    if (s === 'transferring') this.startWatchPolling();
    if (s === 'done' || s === 'failed') this.stopWatchPolling();
  }

  private log(line: string): void {
    this.hook.log.push(line);
    if (this.hook.log.length > 500) this.hook.log.splice(0, this.hook.log.length - 500);
    this.events.log(line);
  }

  private syncFilesHook(): void {
    this.hook.files = this.recs.map((r) => ({
      name: r.name,
      sha256: r.sha256,
      verified: r.verified,
      progress: r.progress,
      wireBytes: r.wireBytes,
    }));
    this.hook.wireBytes = this.recs.reduce((n, r) => n + r.wireBytes, 0);
  }

  private emitFiles(): void {
    this.syncFilesHook();
    this.events.files(
      this.recs.map((r) => ({
        id: r.id,
        name: r.name,
        path: r.path,
        size: r.size,
        progress: r.progress,
        wireBytes: r.wireBytes,
        sha256: r.sha256,
        verified: r.verified,
        paused: r.paused,
        removed: r.removed,
        sinkLabel: r.sinkLabel,
      })),
    );
  }

  private take(): FjActionJson[] {
    if (!this.core) return [];
    return this.core.takeActions() as FjActionJson[];
  }

  // -- live folder sync internals ---------------------------------------------

  /** Run `fn` after every previously queued scan: concurrent diffs of the
   *  same root would append the same files twice. */
  private enqueueScan<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
    const run = this.scanChain.then(fn, fn);
    this.scanChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run.catch((e) => {
      this.log(`scan failed: ${e}`);
      return fallback;
    });
  }

  /** No session owns records right now: picks stage a brand-new share. */
  private freshPick(): boolean {
    const s = this.hook.state;
    return s === 'idle' || s === 'done' || s === 'failed';
  }

  private clearStalePicks(): void {
    if (this.recs.length) {
      this.recs.length = 0;
      this.emitFiles();
    }
    for (const root of this.watched) root.files.clear();
  }

  /** True once HELO finished (core Active); guards the first live tick, when
   *  the wrapper already reports "transferring" but appends would fail. */
  private coreActive(): boolean {
    return this.core !== null && coreDebug(this.core).phase === 'active';
  }

  private startWatchPolling(): void {
    if (this.watchTimer !== null || typeof document === 'undefined') return;
    this.watchTimer = setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState === 'visible' && this.isLive) {
        void this.rescan();
      }
    }, 3000);
    document.addEventListener('visibilitychange', this.onVisibility);
    if (typeof window !== 'undefined') window.addEventListener('focus', this.onFocus);
  }

  private stopWatchPolling(): void {
    if (this.watchTimer !== null) {
      clearInterval(this.watchTimer);
      this.watchTimer = null;
    }
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', this.onVisibility);
    if (typeof window !== 'undefined') window.removeEventListener('focus', this.onFocus);
  }

  /** Read a root and diff it against the session. The read is attempted
   *  unconditionally: a fresh picker grant must not depend on
   *  queryPermission's answer, which is not reliably 'granted' right after
   *  showDirectoryPicker. Lost access is detected from the read itself. */
  private async syncRoot(root: WatchedRoot): Promise<ShareEntry[]> {
    const handle = root.handle;
    if (!handle) return [];
    let next: Map<string, { file: File; mtime: number; size: number }>;
    try {
      next = await this.readHandleTree(handle);
    } catch (e) {
      if (await this.permissionLost(root)) return [];
      this.log(`scan ${root.name} failed: ${e}`);
      return [];
    }
    return this.applyRootDiff(root, next);
  }

  /** True when the read failed because FSA access was withdrawn (lost on
   *  reload or revoked): hint once so the chip's Re-grant can fix it. */
  private async permissionLost(root: WatchedRoot): Promise<boolean> {
    const handle = root.handle;
    if (!handle?.queryPermission) return false;
    const state = await handle.queryPermission({ mode: 'read' });
    if (state === 'granted') return false;
    if (!root.needsGrant) this.events.step(`re-grant access to ${root.name} to keep it syncing`);
    root.needsGrant = true;
    return true;
  }

  /** Recursive directory listing: subpath (after the root) -> file metadata. */
  private async readHandleTree(
    dir: FileSystemDirectoryHandle,
    prefix = '',
  ): Promise<Map<string, { file: File; mtime: number; size: number }>> {
    const out = new Map<string, { file: File; mtime: number; size: number }>();
    for await (const entry of dir.values()) {
      const sub = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.kind === 'directory') {
        for (const [k, v] of await this.readHandleTree(entry as FileSystemDirectoryHandle, sub)) out.set(k, v);
      } else {
        const file = await (entry as FileSystemFileHandle).getFile();
        out.set(sub, { file, mtime: file.lastModified, size: file.size });
      }
    }
    return out;
  }

  /** Diff one root against the live session and perform the wire actions:
   *  new subpath = append, missing subpath = REMOVE, changed metadata =
   *  append with `supersedes`. Failed removals (old peer, cancelled target)
   *  are logged and not retried so they cannot rebuild the same diff every
   *  poll; a rejected append is retried per entry so one unsyncable file
   *  cannot wedge the root. */
  private async applyRootDiff(
    root: WatchedRoot,
    next: Map<string, { file: File; mtime: number; size: number }>,
  ): Promise<ShareEntry[]> {
    const entries: ShareEntry[] = [];
    const removals: number[] = [];
    const live = this.hook.state === 'transferring' && !!this.transport && this.coreActive();
    for (const [sub, wf] of next) {
      const rec = this.recForRootPath(root.name, sub);
      const old = root.files.get(sub);
      const changed = !!old && (old.size !== wf.size || old.mtime !== wf.mtime);
      if (!rec) {
        // pre-start: only files seen for the first time (or edited since
        // the last pick) are staged, so re-picking the same folder is a no-op
        if (live || !old || changed) entries.push({ file: wf.file, path: shareDir(root.name, sub) });
      } else if (changed) {
        entries.push({ file: wf.file, path: shareDir(root.name, sub), supersedes: rec.id });
      }
    }
    for (const sub of root.files.keys()) {
      if (next.has(sub)) continue;
      const rec = this.recForRootPath(root.name, sub);
      if (rec) removals.push(rec.id);
    }
    if (live) {
      let removed = 0;
      for (const id of removals) {
        try {
          this.core!.removeFile(id);
          const rec = this.recById(id);
          if (rec) rec.removed = true;
          removed++;
        } catch (e) {
          this.log(`remove failed for ${root.name}: ${e}`);
        }
      }
      if (removed) {
        await this.applyActions(this.take());
        this.emitFiles();
        this.log(`${root.name}: removed ${removed} file(s) on the sender`);
      }
      if (entries.length) {
        if (!(await this.appendFiles(entries))) {
          // a cancelled supersede target or an invalid name rejects the
          // whole batch: retry alone so the other files still sync
          for (const entry of entries) {
            if (!(await this.appendFiles([entry]))) {
              this.log(`dropping unsyncable file ${entry.path}/${entry.file.name}`);
            }
          }
        }
        this.log(`${root.name}: synced ${entries.length} file(s)`);
      }
    }
    // Pre-start staging (no session yet) advances the baseline so a re-pick
    // only stages new/changed files. Once a session exists but is not live
    // (pairing), keep the old baseline: the entries were not applied, so a
    // later scan/re-pick must still see them. Live cycles always advance:
    // failures above were isolated/dropped on purpose.
    if (live || !this.core) root.files = next;
    return entries;
  }

  /** Newest non-removed record for a root-relative subpath. */
  private recForRootPath(rootName: string, sub: string): FileRec | undefined {
    const slash = sub.lastIndexOf('/');
    const path = slash < 0 ? rootName : `${rootName}/${sub.slice(0, slash)}`;
    const name = slash < 0 ? sub : sub.slice(slash + 1);
    return this.recs.findLast((r) => r.path === path && r.name === name && !r.removed);
  }

  private fail(msg: string): void {
    this.setState('failed');
    this.pumpGen++;
    this.log(`error: ${msg}`);
    this.transport?.close();
  }

  private wireTransport(t: Transport): void {
    t.onFrame = (bytes) => this.handleWire(bytes);
    t.onFirstOpen = () => void this.onFirstOpen();
    t.onClosed = () => {
      if (this.hook.state === 'transferring') {
        this.log('connection lost');
        this.setState('failed');
        this.pumpGen++;
      }
    };
  }

  private startBadgeLoop(): void {
    clearInterval(this.badgeTimer);
    const tick = async () => {
      if (!this.transport) return;
      const info = await this.transport.pathInfo();
      if (!info) return;
      this.hook.path = info.detail;
      this.events.path(info);
    };
    void tick();
    this.badgeTimer = setInterval(tick, 1000);
  }

  // -- actions ----------------------------------------------------------------

  private async applyActions(actions: FjActionJson[], announce = false): Promise<void> {
    for (const a of actions) {
      this.hook.lastActions.push(a);
      if (this.hook.lastActions.length > 50) this.hook.lastActions.splice(0, this.hook.lastActions.length - 50);
      switch (a.t) {
        case 'send': {
          const bytes = new Uint8Array((a.bytes as number[]) ?? []);
          if (!this.transport) break;
          if (announce) this.transport.sendAll(bytes);
          else await this.transport.sendBackpressured(0, bytes);
          break;
        }
        case 'saveChunk': {
          const id = a.file as number;
          const rec = this.recById(id);
          const data = new Uint8Array((a.data as number[]) ?? []);
          // a removed record keeps its bytes; late chunks for it are stale
          if (rec && !rec.removed) {
            const sink = (rec.sink ??= await this.store!.sink(rec));
            rec.sinkLabel = sink.describe();
            await sink.writeChunk(a.index as number, rec.chunkSize, data);
            if (this.player && rec.id === this.playerFileId) {
              this.player.considerHead(a.index as number, data, rec.size);
              this.player.push(a.index as number, data);
            }
          }
          break;
        }
        case 'saveState': {
          if (this.core && this.hook.sid) await idbPut(this.hook.sid, this.core.snapshot());
          break;
        }
        case 'progress': {
          const rec = this.recById(a.file as number);
          if (rec) {
            const total = (a.total as number) || rec.size || 1;
            rec.progress = Math.min(100, Math.floor(((a.done as number) / total) * 100));
            rec.wireBytes = (a.wireBytes as number) ?? rec.wireBytes;
            if (a.resumed) this.hook.resumedChunks++;
          }
          this.emitFiles();
          break;
        }
        case 'hashFeed': {
          await this.hashFeedFile(a.file as number);
          break;
        }
        case 'fileDone': {
          const rec = this.recById(a.file as number);
          if (rec) {
            rec.sha256 = a.sha256 as string;
            rec.verified = a.verified as boolean;
            rec.progress = 100;
            await rec.sink?.close();
            if (rec.verified) this.log(`file done: ${rec.name} sha256 ${rec.sha256} verified`);
            else this.log(`file done: ${rec.name} sha256 ${rec.sha256} NOT verified`);
            this.finalizeFile(rec);
          }
          this.emitFiles();
          break;
        }
        case 'receipt': {
          this.hook.receipts.push(a.receipt);
          this.log('receipt stored');
          break;
        }
        case 'filesAdded': {
          // live share: the peer appended files; create receiver records and
          // drop any record the entry supersedes (same name+path re-sent)
          const added = (a.files ?? []) as ManifestFileJson[];
          for (const f of added) {
            if (f.supersedes !== undefined) {
              const idx = this.recs.findIndex((r) => r.id === f.supersedes);
              if (idx >= 0) {
                const old = this.recs[idx];
                await old.sink?.close();
                this.recs.splice(idx, 1);
              }
            }
            if (this.recById(f.id)) continue;
            this.recs.push({
              id: f.id,
              name: f.name,
              path: f.path,
              size: f.size,
              chunks: f.chunks,
              chunkSize: f.chunk_size,
              progress: 0,
              wireBytes: 0,
            });
          }
          this.events.filesAdded?.(added);
          this.emitFiles();
          this.log(`peer appended ${added.length} file(s)`);
          break;
        }
        case 'fileRemoved': {
          // live share: removed on the sender; the local copy is kept
          const rec = this.recById(a.file as number);
          if (rec) {
            rec.removed = true;
            await rec.sink?.close();
            this.log(`peer removed ${rec.name}; kept locally`);
          }
          this.emitFiles();
          break;
        }
        case 'text': {
          this.events.text(a.text as string);
          this.log('text received');
          break;
        }
        case 'done': {
          this.setState('done');
          this.pumpGen++;
          this.log('session complete');
          this.emitFiles();
          this.transport?.close();
          break;
        }
        case 'fail': {
          this.fail(`${a.code}: ${a.msg}`);
          break;
        }
      }
    }
  }

  private finalizeFile(rec: FileRec): void {
    if (this.player && rec.id === this.playerFileId) this.player.finish();
    if (rec.verified && rec.sink) {
      // every storage mode offers a retrieval path: OPFS is origin-private, so
      // the download is the only way out in browsers without FSA
      const sink = rec.sink;
      void sink
        .downloadBlob()
        .then((blob) => {
          this.events.download(rec.name, blob);
          this.log(`download ready: ${rec.name} (${rec.sinkLabel ?? 'memory'})`);
        })
        .catch((e) => this.log(`download failed: ${e}`));
    } else if (rec.sinkLabel) {
      this.log(`saved to ${rec.sinkLabel}`);
    }
  }

  private async hashFeedFile(id: number): Promise<void> {
    const rec = this.recById(id);
    if (!rec || !this.core) return;
    if (rec.size === 0 && !rec.sink && this.store) {
      // zero-chunk files never get saveChunk: create and truncate the target
      // (a superseded old version must not linger) before hashing it empty
      rec.sink = await this.store.sink(rec);
      rec.sinkLabel = rec.sink.describe();
      await rec.sink.writeChunk(0, rec.chunkSize || CHUNK, new Uint8Array(0));
    }
    const sink = rec.sink;
    if (!sink) return;
    await sink.close();
    if (rec.size === 0) {
      this.core.hashFeed(id, new Uint8Array(0));
      await this.applyActions(this.take());
      return;
    }
    // stream the re-read in bounded slices: multi-GB files never sit in RAM
    for (let o = 0; o < rec.size; o += HASH_FEED_SLICE) {
      const slice = await sink.readSlice(o, Math.min(HASH_FEED_SLICE, rec.size - o));
      this.core.hashFeed(id, slice);
      await this.applyActions(this.take());
    }
  }

  // -- frame pipeline ---------------------------------------------------------

  private handleWire(bytes: Uint8Array): void {
    this.chain = this.chain.then(async () => {
      if (!this.core || this.core.isFailed() || this.core.isDone()) return;
      try {
        this.core.onFrame(bytes);
      } catch (e) {
        this.fail(String(e));
        return;
      }
      try {
        await this.applyActions(this.take());
      } catch (e) {
        this.log(`action error: ${e}`);
      }
      await this.refreshManifest();
    });
  }

  private refreshManifest(): Promise<void> {
    if (this.manifestLoaded || !this.core || this.roleValue !== 'receiver') return Promise.resolve();
    const raw = this.core.manifestJson();
    if (!raw) return Promise.resolve();
    this.manifestLoaded = true;
    const m = JSON.parse(raw) as { sid: string; files: ManifestFileJson[] };
    this.hook.sid = m.sid;
    // A resumed session restores a manifest that still lists retired ids:
    // drop superseded entries (their replacement is the row) and mark
    // REMOVE-retired records as removed instead of showing them as pending.
    const rawRetired = coreDebug(this.core).retired;
    const retired = new Set<number>(
      Array.isArray(rawRetired) ? rawRetired.filter((x): x is number => typeof x === 'number') : [],
    );
    const superseded = new Set<number>();
    for (const f of m.files) if (f.supersedes !== undefined) superseded.add(f.supersedes);
    for (const f of m.files) {
      if (superseded.has(f.id)) continue;
      this.recs.push({
        id: f.id,
        name: f.name,
        path: f.path,
        size: f.size,
        chunks: f.chunks,
        chunkSize: f.chunk_size,
        progress: 0,
        wireBytes: 0,
        removed: retired.has(f.id) ? true : undefined,
      });
    }
    const video = this.recs.find((r) => r.name.toLowerCase().endsWith('.mp4'));
    if (video && this.createPlayer) {
      this.player = this.createPlayer();
      this.playerFileId = this.player ? video.id : null;
    }
    this.emitFiles();
    this.log(`manifest: ${m.files.length} file(s)`);
    return Promise.resolve();
  }

  private async onFirstOpen(): Promise<void> {
    if (!this.core || !this.transport) return;
    await this.transport.waitAllOpen();
    this.chain = this.chain.then(async () => {
      if (!this.core || !this.transport) return;
      if (this.hook.state !== 'failed' && this.hook.state !== 'done') this.setState('transferring');
      try {
        this.core.onChannelOpen();
      } catch (e) {
        this.fail(String(e));
        return;
      }
      // HELO (+MANIFEST) go out on every channel so per-channel ordering puts
      // them ahead of chunks regardless of cross-channel arrival order.
      await this.applyActions(this.take(), true);
      this.startBadgeLoop();
      if (this.roleValue === 'sender') void this.pump(++this.pumpGen);
    });
  }

  private async pump(gen: number): Promise<void> {
    const t = this.transport;
    if (!t || !this.core) return;
    for (;;) {
      if (gen !== this.pumpGen || this.core.isDone() || this.core.isFailed() || !t.isOpen()) return;
      const next = this.nextChunkPlan();
      if (!next) {
        // nothing ready yet: HELO may still be in flight, or everything is
        // sent and we are waiting for receipts/done
        const wait = Promise.withResolvers<void>();
        setTimeout(wait.resolve, 25);
        await wait.promise;
        continue;
      }
      const [id, index, len] = next;
      const rec = this.recById(id)!;
      const buf = new Uint8Array(await rec.source!.slice(index * CHUNK, index * CHUNK + len).arrayBuffer());
      if (gen !== this.pumpGen) return;
      // the plan can change while the slice is read (a rescan may REMOVE or
      // supersede this file, an ack may cover the chunk): never push for an
      // id that is no longer next
      if (this.core.nextSendChunk(id)?.[0] !== index) continue;
      let wire: Uint8Array<ArrayBuffer>;
      try {
        wire = this.core.pushChunkData(id, index, buf);
      } catch (e) {
        this.fail(String(e));
        return;
      }
      try {
        await t.sendBackpressured(index % this.channelCount, wire);
      } catch (e) {
        if (gen === this.pumpGen) {
          this.log(`send failed: ${e}`);
          this.setState('failed');
        }
        return;
      }
      if (gen !== this.pumpGen) return;
      try {
        await this.applyActions(this.take());
      } catch (e) {
        this.log(`action error: ${e}`);
      }
    }
  }

  /** First pending (file, index, len) from the core's send plan, if any. */
  private nextChunkPlan(): [number, number, number] | null {
    if (!this.core) return null;
    for (const id of this.core.fileIds()) {
      const rec = this.recById(id);
      if (!rec?.source) continue;
      const next = this.core.nextSendChunk(id);
      if (next) return [id, Number(next[0]), Number(next[1])];
    }
    return null;
  }

  // -- sender setup -----------------------------------------------------------

  private async sha256Hex(file: File): Promise<string> {
    // incremental hashing: never materialize a whole multi-GB file in JS memory
    const h = new Hasher();
    const step = 4 << 20;
    for (let o = 0; o < file.size; o += step) {
      const buf = new Uint8Array(await file.slice(o, Math.min(o + step, file.size)).arrayBuffer());
      h.update(buf);
    }
    return h.finish();
  }

  /** Watched roots whose baseline overlaps the files being sent survive a
   *  new session: the pre-start pick registered them, and the live diff
   *  must compare against exactly those bytes afterwards. */
  private carryWatchedRoots(items: { file: File; path: string }[]): WatchedRoot[] {
    const sent = new Set(items.map(({ file, path }) => (path ? `${path}/${file.name}` : file.name)));
    return this.watched.filter((root) => {
      for (const sub of root.files.keys()) {
        if (sent.has(`${root.name}/${sub}`)) return true;
      }
      return false;
    });
  }

  /** Fresh session state: a second pairing in the same tab must not inherit
   * the previous run's files, player, storage handles or pairing step. */
  private resetSession(): void {
    this.pumpGen++;
    // a relay exchange in flight owns its channel (receiverJoin runs this at
    // its start); only teardown when no exchange is driving the pairing
    if (!this.relayBusy) {
      this.relay?.close();
      this.relay = null;
    }
    this.transport?.close();
    this.transport = null;
    this.player = null;
    this.playerFileId = null;
    this.store = null;
    this.manifestLoaded = false;
    this.expect = 'none';
    this.chain = Promise.resolve();
    this.recs.length = 0;
    this.stopWatchPolling();
    this.watched = [];
    this.hook.files = [];
    this.hook.resumedChunks = 0;
    this.hook.wireBytes = 0;
    this.hook.path = '';
    this.hook.blob1 = '';
    this.hook.code = '';
    this.hook.checksum = '';
    this.hook.receipts = [];
    this.events.reset();
    this.events.blobOut('');
    this.emitFiles();
  }

  private async startSender(entries: (File | ShareEntry)[], opts: SendOptions): Promise<void> {
    const items = entries.map(normalizeEntry);
    if (!items.length) return;
    const carriedRoots = this.carryWatchedRoots(items);
    this.resetSession();
    this.setState('pairing');
    this.events.step('hashing files…');
    this.log(`sending ${items.length} file(s)`);
    this.privatePairing = !!opts.privatePairing;
    this.channelCount = Math.max(1, Math.min(4, opts.channels ?? 1));
    const words = Math.min(12, Math.max(4, opts.words ?? 6));
    this.gzipMode = opts.gzip ?? 'auto';
    const gzipMode = this.gzipMode;
    this.lastIce = opts.ice ?? this.getIce();

    const specs: { name: string; path: string; size: number; sha256: string; gzip: boolean }[] = [];
    for (const { file, path } of items) {
      specs.push({ name: file.name, path, size: file.size, sha256: await this.sha256Hex(file), gzip: gzipMode === 'on' });
    }

    this.events.step('gathering ICE candidates…');
    const t = await Transport.offerer(this.lastIce, this.channelCount);
    this.core = await newFjCore();
    const started = this.core.senderStart(words, this.privatePairing, t.offerSdp, this.channelCount) as SenderStartResult;
    this.passphrase = started.passphrase;
    this.hook.sid = started.sid;
    if (E2E) this.hook.passphrase = this.passphrase;
    this.hook.blob1 = started.blob1;
    this.core.setFilesLive(JSON.stringify(specs), opts.live === true);
    if (gzipMode === 'auto') {
      for (let i = 0; i < items.length; i++) {
        const f = items[i].file;
        const samples: Uint8Array[] = [];
        for (let c = 0; c < 4; c++) {
          const s = new Uint8Array(await f.slice(c * CHUNK, Math.min((c + 1) * CHUNK, f.size)).arrayBuffer());
          if (s.length) samples.push(s);
        }
        this.core.resolveGzipAuto(i, samples);
      }
    }
    this.transport = t;
    this.wireTransport(t);
    this.recs.length = 0;
    specs.forEach((s, i) =>
      this.recs.push({
        id: i,
        name: s.name,
        path: s.path,
        size: s.size,
        chunks: Math.ceil(s.size / CHUNK),
        chunkSize: CHUNK,
        progress: 0,
        wireBytes: 0,
        source: items[i].file,
      }),
    );
    this.watched = carriedRoots;
    this.manifestLoaded = true;
    this.emitFiles();
    this.events.passphrase(this.passphrase);
    const relayUrl = this.getRelay?.() || null;
    this.relayMode = !!relayUrl;
    if (relayUrl) {
      const room = await roomFromPassphrase(this.passphrase);
      const code = `fj-${room}-${this.passphrase}`;
      this.hook.code = code;
      this.events.pairingCode(code);
      this.events.step('send the one-line code; pairing finishes by itself');
      this.expect = 'sender-blob2';
      this.log(`pairing ready (mode ${this.privatePairing ? 'p3' : 'p2'}, channels ${this.channelCount}, sid ${this.hook.sid}, relay room ${room})`);
      void this.senderRelayExchange(relayUrl, room);
      return;
    }
    this.hook.code = '';
    this.events.blobOut(started.blob1);
    this.events.step('paste blob-1 into the receiver, then paste its blob-2 here');
    this.expect = 'sender-blob2';
    this.log(`pairing ready (mode ${this.privatePairing ? 'p3' : 'p2'}, channels ${this.channelCount}, sid ${this.hook.sid})`);
  }

  /** Relay pairing (sender side): exchange blob-1/2 (and 3/4 for p3) through
   *  the relay room instead of pasting. Runs on after send() resolves; the
   *  initiator speaks first, and only once the receiver joined the room. */
  private async senderRelayExchange(url: string, room: string): Promise<void> {
    this.relayBusy = true;
    let rc: RelayChannel;
    try {
      rc = await RelayChannel.connect(url, room);
    } catch (e) {
      this.relayBusy = false;
      this.fail(`relay connect failed: ${e}`);
      return;
    }
    this.relay = rc;
    // no onGone fail-fast: RelayChannel.bye() already rejects any pending
    // waitPeer/nextBlob, so a REAL mid-exchange death still fails the
    // session — while the peer leaving after we hold everything must not
    // (the receiver closes the room as soon as it replied blob-2)
    try {
      this.events.step('waiting for the receiver…');
      await rc.waitPeer();
      rc.send(this.hook.blob1);
      const blob2 = await rc.nextBlob();
      const blob3 = await this.onProcess(blob2, '');
      if (this.privatePairing) {
        if (!blob3) throw new Error('blob-3 missing after initiator accept');
        rc.send(blob3);
        const blob4 = await rc.nextBlob();
        await this.onProcess(blob4, '');
      }
    } catch (e) {
      rc.close();
      if (this.hook.state !== 'failed') this.fail(`relay exchange failed: ${e}`);
    } finally {
      // grace close: the peer may still be digesting our last blob (its
      // peer-left broadcast used to race applyAnswer behind proxies)
      setTimeout(() => rc.close(), 750);
      this.relayBusy = false;
      this.relay = null;
    }
  }

  private async restartSender(): Promise<void> {
    if (!this.core || !this.passphrase) return;
    this.pumpGen++;
    this.transport?.close();
    this.setState('pairing');
    this.events.step('gathering ICE candidates…');
    const t = await Transport.offerer(this.lastIce, this.channelCount);
    let blob1: string;
    try {
      blob1 = this.core.resumeInitiator(this.passphrase, t.offerSdp);
    } catch (e) {
      this.fail(`resume failed: ${e}`);
      return;
    }
    this.transport = t;
    this.wireTransport(t);
    this.hook.blob1 = blob1;
    if (this.relayMode) {
      const url = this.getRelay?.() || null;
      const room = url ? await roomFromPassphrase(this.passphrase) : null;
      if (url && room) {
        this.hook.code = `fj-${room}-${this.passphrase}`;
        this.events.pairingCode(this.hook.code);
        this.events.step('resend the one-line code; pairing finishes by itself');
        this.expect = 'sender-blob2';
        this.log('resume pairing: same room (same passphrase)');
        void this.senderRelayExchange(url, room);
        return;
      }
    }
    this.events.blobOut(blob1);
    this.events.step('paste the new blob-1 into the receiver, then paste its blob-2 here');
    this.expect = 'sender-blob2';
    this.log('resume pairing: new blob-1 ready (same passphrase)');
  }

  // -- receiver setup ---------------------------------------------------------

  /** Returns the outbound blob for the peer (blob-2), or null on failure. */
  private async receiverJoin(blob1: string, pass: string): Promise<string | null> {
    this.resetSession();
    this.setState('pairing');
    let env: Envelope1;
    try {
      env = await inflateBlob1(blob1);
    } catch (e) {
      this.fail(String(e));
      return null;
    }
    const snapshot = await idbGet(env.sid);
    if (!this.core) this.core = await newFjCore();
    const resuming = snapshot !== undefined;
    if (resuming) {
      try {
        this.core.restore(snapshot!);
        this.log(`restored session ${env.sid} (epoch +1 resume)`);
      } catch (e) {
        this.log(`snapshot restore failed, starting fresh: ${e}`);
        this.core = await newFjCore();
      }
    }
    this.store = await ReceiverStore.create(env.sid, this.pickedDir);
    this.log(`storage: ${this.store.mode}${resuming ? ' (resumed session)' : ''}`);
    this.channelCount = env.ch && env.ch > 1 ? env.ch : 1;

    if (env.mode === 'p3') {
      let blob2: string;
      try {
        blob2 = resuming ? this.core.resumeResponder(blob1, pass, '') : this.core.receiverJoin(blob1, pass, '');
      } catch (e) {
        this.fail(String(e));
        return null;
      }
      this.hook.sid = env.sid;
      this.hook.passphrase = pass;
      this.events.blobOut(blob2);
      this.events.step(
        this.relayMode ? 'private pairing: exchanging blobs via the relay…' : 'paste blob-2 into the sender, then paste its blob-3 here',
      );
      this.expect = 'recv-blob3';
      this.log('private pairing: blob-2 ready (PAKE only, no SDP in clear)');
      return blob2;
    }

    this.events.step('gathering ICE candidates…');
    const t = await Transport.answerer(this.getIce(), env.sdp ?? '');
    let blob2: string;
    try {
      blob2 = resuming ? this.core.resumeResponder(blob1, pass, t.answerSdp) : this.core.receiverJoin(blob1, pass, t.answerSdp);
    } catch (e) {
      t.close();
      this.fail(String(e));
      return null;
    }
    this.transport = t;
    this.wireTransport(t);
    this.hook.sid = env.sid;
    this.hook.passphrase = pass;
    this.events.blobOut(blob2);
    this.events.step(
      this.relayMode ? 'pairing complete; connecting' : 'paste blob-2 into the sender; transfer starts when it connects',
    );
    this.expect = 'none';
    this.setState('paired');
    this.emitChecksum();
    this.log(`joined session ${env.sid}${resuming ? ' (resume)' : ''}`);
    return blob2;
  }

  /** Returns the outbound blob for the peer (blob-4), or null on failure. */
  private async receiverBlob3(blob3: string): Promise<string | null> {
    if (!this.core) return null;
    let offer: string;
    try {
      offer = this.core.responderPrivateOffer(blob3);
    } catch (e) {
      this.fail(String(e));
      return null;
    }
    this.events.step('gathering ICE candidates…');
    const t = await Transport.answerer(this.getIce(), offer);
    let blob4: string;
    try {
      blob4 = this.core.responderPrivateBlob4(t.answerSdp);
    } catch (e) {
      t.close();
      this.fail(String(e));
      return null;
    }
    this.transport = t;
    this.wireTransport(t);
    this.events.blobOut(blob4);
    this.events.step(this.relayMode ? 'pairing complete; connecting' : 'paste blob-4 into the sender');
    this.expect = 'none';
    this.setState('paired');
    this.emitChecksum();
    this.log('private pairing: blob-4 ready');
    return blob4;
  }

  // -- #process -----------------------------------------------------------------

  /** CRLF line endings and a final terminator (libwebrtc rejects a bare last line). */
  private normalizeSdp(sdp: string): string {
    const crlf = sdp.replace(/\r?\n/g, '\r\n');
    return crlf.endsWith('\r\n') ? crlf : `${crlf}\r\n`;
  }

  /** Drive one inbound blob through the pairing state machine. Returns the
   *  outbound blob it produced for the peer (blob-2/3/4), or null — the
   *  relay exchange sends that straight to the room instead of a paste. */
  private async onProcess(blob: string, pass: string): Promise<string | null> {
    if (!blob) return null;
    if (this.roleValue === 'receiver' && this.expect === 'recv-blob1') {
      return this.receiverJoin(blob, pass);
    }
    if (this.roleValue === 'receiver' && this.expect === 'recv-blob3') {
      return this.receiverBlob3(blob);
    }
    if (this.roleValue === 'sender' && this.expect === 'sender-blob2' && this.core) {
      try {
        this.core.initiatorAccept(blob);
      } catch (e) {
        this.fail(String(e));
        return null;
      }
      if (this.privatePairing) {
        const blob3 = this.core.initiatorPrivateBlob3();
        this.events.blobOut(blob3);
        this.events.step(this.relayMode ? 'private pairing: exchanging blobs via the relay…' : 'paste blob-3 into the receiver, then paste its blob-4 here');
        this.expect = 'sender-blob4';
        this.log('private pairing: blob-3 ready');
        return blob3;
      }
      await this.senderFinishPairing();
      return null;
    }
    if (this.roleValue === 'sender' && this.expect === 'sender-blob4' && this.core) {
      try {
        this.core.initiatorPrivateFinal(blob);
      } catch (e) {
        this.fail(String(e));
        return null;
      }
      await this.senderFinishPairing();
    }
    return null;
  }

  private async senderFinishPairing(): Promise<void> {
    if (!this.core || !this.transport) return;
    const answer = this.normalizeSdp(this.core.answerSdp());
    try {
      await this.transport.applyAnswer(answer);
    } catch (e) {
      this.fail(`bad answer SDP: ${e}`);
      return;
    }
    this.expect = 'none';
    this.setState('paired');
    this.emitChecksum();
    this.events.step('connecting…');
    this.log('pairing complete; connecting');
  }

  /** Relay pairing only: surface the "XXXX XXXX" checksum both peers must
   *  compare (a mismatch = MITM in the signaling path). */
  private emitChecksum(): void {
    if (!this.relayMode || !this.core) return;
    const sum = this.core.verifyChecksum();
    if (!sum) return;
    this.hook.checksum = sum;
    this.events.checksum(sum);
    this.log(`verification checksum: ${sum} — compare on both screens`);
  }
}

/** Best-effort parse of `FjCore.debugJson()` (our own Rust output, still
 *  never trusted blindly): only the fields the engine reads are surfaced. */
function coreDebug(core: FjCore): { phase?: unknown; retired?: unknown } {
  try {
    const value: unknown = JSON.parse(core.debugJson());
    if (!value || typeof value !== 'object') return {};
    const record = value as Record<string, unknown>;
    return { phase: record.phase, retired: record.retired };
  } catch {
    return {};
  }
}

/** File or {file, path} entry to its (file, folder-path) pair. */
function normalizeEntry(e: File | ShareEntry): { file: File; path: string; supersedes?: number } {
  if ('file' in e) return { file: e.file, path: e.path.replace(/^\/+|\/+$/g, ''), supersedes: e.supersedes };
  const parts = (e.webkitRelativePath ?? '').split('/').filter(Boolean);
  parts.pop(); // last component is the name itself
  return { file: e, path: parts.join('/') };
}

/** Folder path for a root + root-relative subpath ("photos" + "a/x.jpg" ->
 *  "photos/a"). */
function shareDir(root: string, sub: string): string {
  const slash = sub.lastIndexOf('/');
  return slash < 0 ? root : `${root}/${sub.slice(0, slash)}`;
}
