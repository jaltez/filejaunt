// filejaunt web client orchestration: DOM <-> transport <-> WASM core <-> storage.
//
// Pairing (p2, default): sender creates the offer, then blob-1 (offer in
// clear); receiver answers, blob-2 carries the answer ENCRYPTED. The WASM
// facade does not expose the decrypted answer to JS, so the receiver appends
// its own clear answer below the blob (separator line "-----"); the HELO
// fingerprint (HMAC-SHA256 over offer+answer) still detects any SDP
// substitution, so this keeps p2's authentication guarantees.

import { Hasher, newFjCore, type FjCore, type FjActionJson } from './wasm';
import { Transport, doctorProbe, type IceConfig, type PathInfo } from './transport';
import { ReceiverStore, type FjDirHandle, type Sink } from './storage';
import { StreamPlayer } from './media';
import * as ui from './ui';

const CHUNK = 16384;
const FILE_ALL = 65535;
const HASH_FEED_SLICE = 1 << 20;

type Expect = 'none' | 'sender-blob2' | 'sender-blob4' | 'recv-blob1' | 'recv-blob3';
type FjState = 'idle' | 'pairing' | 'paired' | 'transferring' | 'done' | 'failed';

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
}

interface FjHook {
  state: FjState;
  lastActions: FjActionJson[];
  files: { name: string; sha256?: string; verified?: boolean; progress: number; wireBytes: number }[];
  resumedChunks: number;
  wireBytes: number;
  path: string;
  sid: string;
  passphrase: string;
  blob1: string;
  log: string[];
  receipts: unknown[];
  doctor: { klass: string; detail: string } | null;
}

const fj: FjHook = {
  state: 'idle',
  lastActions: [],
  files: [],
  resumedChunks: 0,
  wireBytes: 0,
  path: '',
  sid: '',
  passphrase: '',
  blob1: '',
  log: [],
  receipts: [],
  doctor: null,
};
(window as unknown as { __fj: FjHook }).__fj = fj;

function setState(s: FjState): void {
  fj.state = s;
}

function log(line: string): void {
  fj.log.push(line);
  if (fj.log.length > 500) fj.log.splice(0, fj.log.length - 500);
  ui.log(line);
}

function syncFilesHook(): void {
  fj.files = recs.map((r) => ({
    name: r.name,
    sha256: r.sha256,
    verified: r.verified,
    progress: r.progress,
    wireBytes: r.wireBytes,
  }));
  fj.wireBytes = recs.reduce((n, r) => n + r.wireBytes, 0);
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

async function readStreamBytes(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
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
  const DS = (globalThis as unknown as { DecompressionStream?: new (f: 'gzip') => DecompressionStream }).DecompressionStream;
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

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

let core: FjCore | null = null;
let transport: Transport | null = null;
let store: ReceiverStore | null = null;
let player: StreamPlayer | null = null;
let playerFileId: number | null = null;
let pickedDir: FjDirHandle | null = null;
let role: 'sender' | 'receiver' | null = null;
let expect: Expect = 'none';
let private3 = false;
let passphrase = '';
let channelCount = 1;
let manifestLoaded = false;
let chain: Promise<void> = Promise.resolve();
let pumpGen = 0;
let badgeTimer = 0;
const recs: FileRec[] = [];

function recById(id: number): FileRec | undefined {
  return recs.find((r) => r.id === id);
}

function iceConfig(): IceConfig {
  const stun = ui
    .qs<HTMLInputElement>('#stun')
    .value.split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const turnUrl = ui.qs<HTMLInputElement>('#turn-url').value.trim();
  const turnUser = ui.qs<HTMLInputElement>('#turn-user').value.trim();
  const turnPass = ui.qs<HTMLInputElement>('#turn-pass').value;
  return stun.length || turnUrl
    ? {
        stunUrls: stun,
        turn: turnUrl ? { urls: [turnUrl], username: turnUser, credential: turnPass } : undefined,
      }
    : { stunUrls: [] };
}

function take(): FjActionJson[] {
  if (!core) return [];
  return core.takeActions() as FjActionJson[];
}

function fail(msg: string): void {
  setState('failed');
  pumpGen++;
  log(`error: ${msg}`);
  transport?.close();
}

function wireTransport(t: Transport): void {
  t.onFrame = (bytes) => handleWire(bytes);
  t.onFirstOpen = () => void onFirstOpen();
  t.onClosed = () => {
    if (fj.state === 'transferring') {
      log('connection lost');
      setState('failed');
      pumpGen++;
    }
  };
}

function setBlobOut(blob: string): void {
  ui.qs<HTMLTextAreaElement>('#blob-out').value = blob;
}

function startBadgeLoop(): void {
  window.clearInterval(badgeTimer);
  const tick = async () => {
    if (!transport) return;
    const info: PathInfo | null = await transport.pathInfo();
    if (!info) return;
    fj.path = info.detail;
    if (info.kind === 'relay') {
      ui.badge('RELAY', '#b8860b');
    } else if (info.kind === 'unknown') {
      ui.badge(info.text, '#555');
    } else {
      ui.badge(info.text, '#0a7d0a');
    }
  };
  void tick();
  badgeTimer = window.setInterval(tick, 1000);
}

// -- actions ----------------------------------------------------------------

async function applyActions(actions: FjActionJson[], announce = false): Promise<void> {
  for (const a of actions) {
    fj.lastActions.push(a);
    if (fj.lastActions.length > 50) fj.lastActions.splice(0, fj.lastActions.length - 50);
    switch (a.t) {
      case 'send': {
        const bytes = new Uint8Array((a.bytes as number[]) ?? []);
        if (!transport) break;
        if (announce) transport.sendAll(bytes);
        else await transport.sendBackpressured(0, bytes);
        break;
      }
      case 'saveChunk': {
        const id = a.file as number;
        const rec = recById(id);
        const data = new Uint8Array((a.data as number[]) ?? []);
        if (rec) {
          const sink = (rec.sink ??= await store!.sink(rec));
          rec.sinkLabel = sink.describe();
          await sink.writeChunk(a.index as number, rec.chunkSize, data);
          if (player && rec.id === playerFileId) {
            player.considerHead(a.index as number, data, rec.size);
            player.push(a.index as number, data);
          }
        }
        break;
      }
      case 'saveState': {
        if (core && fj.sid) await idbPut(fj.sid, core.snapshot());
        break;
      }
      case 'progress': {
        const rec = recById(a.file as number);
        if (rec) {
          const total = (a.total as number) || rec.size || 1;
          rec.progress = Math.min(100, Math.floor(((a.done as number) / total) * 100));
          rec.wireBytes = (a.wireBytes as number) ?? rec.wireBytes;
          if (a.resumed) fj.resumedChunks++;
        }
        syncFilesHook();
        renderLists();
        break;
      }
      case 'hashFeed': {
        await hashFeedFile(a.file as number);
        break;
      }
      case 'fileDone': {
        const rec = recById(a.file as number);
        if (rec) {
          rec.sha256 = a.sha256 as string;
          rec.verified = a.verified as boolean;
          rec.progress = 100;
          await rec.sink?.close();
          if (rec.verified) log(`file done: ${rec.name} sha256 ${rec.sha256} verified`);
          else log(`file done: ${rec.name} sha256 ${rec.sha256} NOT verified`);
          finalizeFile(rec);
        }
        syncFilesHook();
        renderLists();
        break;
      }
      case 'receipt': {
        fj.receipts.push(a.receipt);
        log('receipt stored (see window.__fj.receipts)');
        break;
      }
      case 'text': {
        ui.appendText(a.text as string);
        log('text received');
        break;
      }
      case 'done': {
        setState('done');
        pumpGen++;
        log('session complete');
        renderLists();
        transport?.close();
        break;
      }
      case 'fail': {
        fail(`${a.code}: ${a.msg}`);
        break;
      }
    }
  }
}

function finalizeFile(rec: FileRec): void {
  if (player && rec.id === playerFileId) player.finish();
  if (rec.verified && rec.sink) {
    // every storage mode offers a retrieval path: OPFS is origin-private, so
    // the download link is the only way out in browsers without FSA
    void rec.sink
      .downloadBlob()
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = rec.name;
        a.textContent = `download ${rec.name}`;
        a.rel = 'noopener';
        ui.qs<HTMLElement>('#files').append(a);
        log(`download link ready: ${rec.name} (${rec.sinkLabel ?? 'memory'})`);
      })
      .catch((e) => log(`download link failed: ${e}`));
  } else if (rec.sinkLabel) {
    log(`saved to ${rec.sinkLabel}`);
  }
}

async function hashFeedFile(id: number): Promise<void> {
  const rec = recById(id);
  if (!rec || !core || !rec.sink) return;
  await rec.sink.close();
  if (rec.size === 0) {
    core.hashFeed(id, new Uint8Array(0));
    await applyActions(take());
    return;
  }
  // stream the re-read in bounded slices: multi-GB files never sit in RAM
  for (let o = 0; o < rec.size; o += HASH_FEED_SLICE) {
    const slice = await rec.sink.readSlice(o, Math.min(HASH_FEED_SLICE, rec.size - o));
    core.hashFeed(id, slice);
    await applyActions(take());
  }
}

// -- frame pipeline -----------------------------------------------------------

function handleWire(bytes: Uint8Array): void {
  chain = chain.then(async () => {
    if (!core || core.isFailed() || core.isDone()) return;
    try {
      core.onFrame(bytes);
    } catch (e) {
      fail(String(e));
      return;
    }
    try {
      await applyActions(take());
    } catch (e) {
      log(`action error: ${e}`);
    }
    await refreshManifest();
  });
}

function refreshManifest(): Promise<void> {
  if (manifestLoaded || !core || role !== 'receiver') return Promise.resolve();
  const raw = core.manifestJson();
  if (!raw) return Promise.resolve();
  manifestLoaded = true;
  const m = JSON.parse(raw) as {
    sid: string;
    files: { id: number; name: string; path: string; size: number; chunks: number; chunk_size: number; sha256: string }[];
  };
  fj.sid = m.sid;
  for (const f of m.files) {
    recs.push({
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
  const video = recs.find((r) => r.name.toLowerCase().endsWith('.mp4'));
  if (video) {
    player = new StreamPlayer(ui.qs<HTMLVideoElement>('#video'));
    playerFileId = video.id;
  }
  syncFilesHook();
  renderLists();
  log(`manifest: ${m.files.length} file(s)`);
  return Promise.resolve();
}

async function onFirstOpen(): Promise<void> {
  if (!core || !transport) return;
  await transport.waitAllOpen();
  chain = chain.then(async () => {
    if (!core || !transport) return;
    if (fj.state !== 'failed' && fj.state !== 'done') setState('transferring');
    try {
      core.onChannelOpen();
    } catch (e) {
      fail(String(e));
      return;
    }
    // HELO (+MANIFEST) go out on every channel so per-channel ordering puts
    // them ahead of chunks regardless of cross-channel arrival order.
    await applyActions(take(), true);
    startBadgeLoop();
    if (role === 'sender') void pump(++pumpGen);
  });
}

async function pump(gen: number): Promise<void> {
  const t = transport;
  if (!t || !core) return;
  for (;;) {
    if (gen !== pumpGen || core.isDone() || core.isFailed() || !t.isOpen()) return;
    const next = nextChunkPlan();
    if (!next) {
      // nothing ready yet: HELO may still be in flight, or everything is
      // sent and we are waiting for receipts/done
      await new Promise((r) => setTimeout(r, 25));
      continue;
    }
    const [id, index, len] = next;
    const rec = recById(id)!;
    const buf = new Uint8Array(await rec.source!.slice(index * CHUNK, index * CHUNK + len).arrayBuffer());
    if (gen !== pumpGen) return;
    let wire: Uint8Array<ArrayBuffer>;
    try {
      wire = core.pushChunkData(id, index, buf);
    } catch (e) {
      fail(String(e));
      return;
    }
    try {
      await t.sendBackpressured(index % channelCount, wire);
    } catch (e) {
      if (gen === pumpGen) {
        log(`send failed: ${e}`);
        setState('failed');
      }
      return;
    }
    if (gen !== pumpGen) return;
    try {
      await applyActions(take());
    } catch (e) {
      log(`action error: ${e}`);
    }
   }
}

/** First pending (file, index, len) from the core's send plan, if any. */
function nextChunkPlan(): [number, number, number] | null {
  if (!core) return null;
  for (const id of core.fileIds()) {
    const rec = recById(id);
    if (!rec?.source) continue;
    const next = core.nextSendChunk(id);
    if (next) return [id, Number(next[0]), Number(next[1])];
  }
  return null;
}

// -- sender setup ---------------------------------------------------------------

async function sha256Hex(file: File): Promise<string> {
  // incremental hashing: never materialize a whole multi-GB file in JS memory
  const h = new Hasher();
  const step = 4 << 20;
  for (let o = 0; o < file.size; o += step) {
    const buf = new Uint8Array(await file.slice(o, Math.min(o + step, file.size)).arrayBuffer());
    h.update(buf);
  }
  return h.finish();
}

/** Fresh session state: a second pairing in the same tab must not inherit
 * the previous run's files, player, storage handles or pairing step. */
function resetSession(): void {
  pumpGen++;
  transport?.close();
  transport = null;
  player = null;
  playerFileId = null;
  store = null;
  manifestLoaded = false;
  expect = 'none';
  chain = Promise.resolve();
  recs.length = 0;
  fj.files = [];
  fj.resumedChunks = 0;
  fj.wireBytes = 0;
  fj.path = '';
  fj.blob1 = '';
  fj.receipts = [];
  ui.qs<HTMLElement>('#files').replaceChildren();
  ui.qs<HTMLElement>('#queue').replaceChildren();
  ui.qs<HTMLTextAreaElement>('#blob-out').value = '';
  ui.qs<HTMLElement>('#video').classList.add('hide');
}

async function startSender(files: File[]): Promise<void> {
  if (!files.length) return;
  resetSession();
  setState('pairing');
  ui.setStep('hashing files…');
  log(`sending ${files.length} file(s)`);
  private3 = ui.qs<HTMLInputElement>('#private3').checked;
  channelCount = Number(ui.qs<HTMLSelectElement>('#channels').value) || 1;
  const words = Math.min(12, Math.max(4, Number(ui.qs<HTMLInputElement>('#words').value) || 6));
  const gzipMode = ui.qs<HTMLSelectElement>('#gzip').value;

  const specs: { name: string; path: string; size: number; sha256: string; gzip: boolean }[] = [];
  for (const f of files) {
    const rel = (f as File & { webkitRelativePath?: string }).webkitRelativePath ?? '';
    const parts = rel.split('/').filter(Boolean);
    parts.pop(); // last component is the name itself
    specs.push({ name: f.name, path: parts.join('/'), size: f.size, sha256: await sha256Hex(f), gzip: gzipMode === 'on' });
  }

  ui.setStep('gathering ICE candidates…');
  const t = await Transport.offerer(iceConfig(), channelCount);
  core = await newFjCore();
  const started = core.senderStart(words, private3, t.offerSdp, channelCount) as {
    sid: string;
    passphrase: string;
    blob1: string;
  };
  passphrase = started.passphrase;
  fj.sid = started.sid;
  fj.passphrase = passphrase;
  fj.blob1 = started.blob1;
  core.setFiles(JSON.stringify(specs));
  if (gzipMode === 'auto') {
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const samples: Uint8Array[] = [];
      for (let c = 0; c < 4; c++) {
        const s = new Uint8Array(await f.slice(c * CHUNK, Math.min((c + 1) * CHUNK, f.size)).arrayBuffer());
        if (s.length) samples.push(s);
      }
      core.resolveGzipAuto(i, samples);
    }
  }
  transport = t;
  wireTransport(t);
  recs.length = 0;
  specs.forEach((s, i) =>
    recs.push({
      id: i,
      name: s.name,
      path: s.path,
      size: s.size,
      chunks: Math.ceil(s.size / CHUNK),
      chunkSize: CHUNK,
      progress: 0,
      wireBytes: 0,
      source: files[i],
    }),
  );
  manifestLoaded = true;
  syncFilesHook();
  renderLists();
  ui.qs<HTMLElement>('#passphrase-wrap').classList.remove('hide');
  ui.qs<HTMLElement>('#passphrase-out').textContent = passphrase;
  setBlobOut(started.blob1);
  ui.setStep('paste blob-1 into the receiver, then paste its blob-2 here');
  expect = 'sender-blob2';
  log(`pairing ready (mode ${private3 ? 'p3' : 'p2'}, channels ${channelCount}, sid ${fj.sid})`);
}

async function restartSender(): Promise<void> {
  if (!core || !passphrase) return;
  pumpGen++;
  transport?.close();
  setState('pairing');
  ui.setStep('gathering ICE candidates…');
  const t = await Transport.offerer(iceConfig(), channelCount);
  let blob1: string;
  try {
    blob1 = core.resumeInitiator(passphrase, t.offerSdp);
  } catch (e) {
    fail(`resume failed: ${e}`);
    return;
  }
  transport = t;
  wireTransport(t);
  fj.blob1 = blob1;
  setBlobOut(blob1);
  ui.setStep('paste the new blob-1 into the receiver, then paste its blob-2 here');
  expect = 'sender-blob2';
  log('resume pairing: new blob-1 ready (same passphrase)');
}

// -- receiver setup --------------------------------------------------------------

async function receiverJoin(blob1: string, pass: string): Promise<void> {
  resetSession();
  setState('pairing');
  let env: Envelope1;
  try {
    env = await inflateBlob1(blob1);
  } catch (e) {
    fail(String(e));
    return;
  }
  const snapshot = await idbGet(env.sid);
  if (!core) core = await newFjCore();
  const resuming = snapshot !== undefined;
  if (resuming) {
    try {
      core.restore(snapshot!);
      log(`restored session ${env.sid} (epoch +1 resume)`);
    } catch (e) {
      log(`snapshot restore failed, starting fresh: ${e}`);
      core = await newFjCore();
    }
  }
  store = await ReceiverStore.create(env.sid, pickedDir);
  log(`storage: ${store.mode}${resuming ? ' (resumed session)' : ''}`);
  channelCount = env.ch && env.ch > 1 ? env.ch : 1;

  if (env.mode === 'p3') {
    let blob2: string;
    try {
      blob2 = resuming ? core.resumeResponder(blob1, pass, '') : core.receiverJoin(blob1, pass, '');
    } catch (e) {
      fail(String(e));
      return;
    }
    fj.sid = env.sid;
    fj.passphrase = pass;
  setBlobOut(blob2);
    ui.setStep('paste blob-2 into the sender, then paste its blob-3 here');
    expect = 'recv-blob3';
    log('private pairing: blob-2 ready (PAKE only, no SDP in clear)');
    return;
  }

  ui.setStep('gathering ICE candidates…');
  const t = await Transport.answerer(iceConfig(), env.sdp ?? '');
  let blob2: string;
  try {
    blob2 = resuming ? core.resumeResponder(blob1, pass, t.answerSdp) : core.receiverJoin(blob1, pass, t.answerSdp);
  } catch (e) {
    t.close();
    fail(String(e));
    return;
  }
  transport = t;
  wireTransport(t);
  fj.sid = env.sid;
  fj.passphrase = pass;
  setBlobOut(blob2);
  ui.setStep('paste blob-2 into the sender; transfer starts when it connects');
  expect = 'none';
  setState('paired');
  log(`joined session ${env.sid}${resuming ? ' (resume)' : ''}`);
}

async function receiverBlob3(blob3: string): Promise<void> {
  if (!core) return;
  let offer: string;
  try {
    offer = core.responderPrivateOffer(blob3);
  } catch (e) {
    fail(String(e));
    return;
  }
  ui.setStep('gathering ICE candidates…');
  const t = await Transport.answerer(iceConfig(), offer);
  let blob4: string;
  try {
    blob4 = core.responderPrivateBlob4(t.answerSdp);
  } catch (e) {
    t.close();
    fail(String(e));
    return;
  }
  transport = t;
  wireTransport(t);
  setBlobOut(blob4);
  ui.setStep('paste blob-4 into the sender');
  expect = 'none';
  setState('paired');
  log('private pairing: blob-4 ready');
}

// -- #process ---------------------------------------------------------------------

/** CRLF line endings and a final terminator (libwebrtc rejects a bare last line). */
function normalizeSdp(sdp: string): string {
  const crlf = sdp.replace(/\r?\n/g, '\r\n');
  return crlf.endsWith('\r\n') ? crlf : `${crlf}\r\n`;
}

async function onProcess(): Promise<void> {
  const blob = ui.qs<HTMLTextAreaElement>('#blob-in').value.trim();
  if (!blob) return;
  if (role === 'receiver' && expect === 'recv-blob1') {
    await receiverJoin(blob, ui.qs<HTMLInputElement>('#pass-in').value.trim());
    return;
  }
  if (role === 'receiver' && expect === 'recv-blob3') {
    await receiverBlob3(blob);
    return;
  }
  if (role === 'sender' && expect === 'sender-blob2' && core) {
    try {
      core.initiatorAccept(blob);
    } catch (e) {
      fail(String(e));
      return;
    }
    if (private3) {
      const blob3 = core.initiatorPrivateBlob3();
      setBlobOut(blob3);
      ui.setStep('paste blob-3 into the receiver, then paste its blob-4 here');
      expect = 'sender-blob4';
      log('private pairing: blob-3 ready');
      return;
    }
    await senderFinishPairing();
    return;
  }
  if (role === 'sender' && expect === 'sender-blob4' && core) {
    try {
      core.initiatorPrivateFinal(blob);
    } catch (e) {
      fail(String(e));
      return;
    }
    await senderFinishPairing();
  }
}

async function senderFinishPairing(): Promise<void> {
  if (!core || !transport) return;
  const answer = normalizeSdp(core.answerSdp());
  try {
    await transport.applyAnswer(answer);
  } catch (e) {
    fail(`bad answer SDP: ${e}`);
    return;
  }
  expect = 'none';
  setState('paired');
  ui.setStep('connecting…');
  log('pairing complete; connecting');
}

// -- rendering --------------------------------------------------------------------

function renderLists(): void {
  if (role === 'sender') {
    ui.renderQueue(
      recs.map((r) => ({
        id: r.id,
        name: r.name,
        progress: r.progress,
        detail: `${r.progress}% ${fmtBytes(r.wireBytes)} on wire${r.verified ? ' verified' : ''}`,
        paused: !!r.paused,
        onPause: () => void togglePause(r),
        onCancel: () => void cancelFile(r),
      })),
    );
  } else {
    ui.renderFiles(
      recs.map((r) => ({
        name: r.name,
        progress: r.progress,
        detail: `${r.progress}% ${fmtBytes(r.wireBytes)}${r.verified ? ' verified' : ''}`,
      })),
    );
  }
}

function fmtBytes(n: number): string {
  return n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MiB` : `${(n / 1024).toFixed(1)} KiB`;
}

async function togglePause(rec: FileRec): Promise<void> {
  if (!core) return;
  rec.paused = !rec.paused;
  if (rec.paused) core.pause(rec.id);
  else core.resume(rec.id);
  await applyActions(take());
  renderLists();
}

async function cancelFile(rec: FileRec): Promise<void> {
  if (!core) return;
  core.cancel(rec.id);
  await applyActions(take());
  log(`cancelled ${rec.name}`);
  renderLists();
}

// -- boot ---------------------------------------------------------------------------

async function boot(): Promise<void> {
  void newFjCore(); // warm the WASM module
  ui.badge('—', '#555');
  ui.qs<HTMLElement>('#btn-send').onclick = () => {
    role = 'sender';
    ui.qs<HTMLElement>('#send-panel').classList.remove('hide');
    ui.qs<HTMLElement>('#pair').classList.remove('hide');
    ui.setStep('pick files to send');
    expect = 'none';
    log('role: sender');
  };
  ui.qs<HTMLElement>('#btn-recv').onclick = () => {
    role = 'receiver';
    ui.qs<HTMLElement>('#recv-panel').classList.remove('hide');
    ui.qs<HTMLElement>('#pair').classList.remove('hide');
    ui.setStep('paste blob-1 and the passphrase, then press Process');
    expect = 'recv-blob1';
    log('role: receiver');
  };
  ui.qs<HTMLInputElement>('#file-input').addEventListener('change', (e) => {
    const input = e.target as HTMLInputElement;
    void startSender([...(input.files ?? [])]).catch((e) => fail(String(e)));
  });
  ui.qs<HTMLElement>('#process').onclick = () => void onProcess().catch((e) => fail(String(e)));
  ui.qs<HTMLElement>('#restart').onclick = () => void restartSender().catch((e) => fail(String(e)));
  ui.qs<HTMLElement>('#copy-pass').onclick = () => void navigator.clipboard?.writeText(passphrase);
  ui.qs<HTMLElement>('#copy-blob').onclick = () => void navigator.clipboard?.writeText(ui.qs<HTMLTextAreaElement>('#blob-out').value);
  ui.qs<HTMLElement>('#text-send-btn').onclick = () => {
    const input = ui.qs<HTMLInputElement>('#text-send');
    const text = input.value;
    if (!text || !core || !transport) return;
    try {
      void transport.sendBackpressured(0, core.sendText(text));
      input.value = '';
    } catch (e) {
      log(`text send failed: ${e}`);
    }
  };
  ui.qs<HTMLElement>('#choose-dir').onclick = () => {
    const w = window as unknown as { showDirectoryPicker?: () => Promise<FjDirHandle> };
    if (!w.showDirectoryPicker) {
      ui.qs<HTMLElement>('#dir-note').textContent = 'will save via private storage / browser download';
      return;
    }
    void w
      .showDirectoryPicker()
      .then((d) => {
        pickedDir = d;
        ui.qs<HTMLElement>('#dir-note').textContent = `saving into ${d.name}/`;
        log(`output folder: ${d.name}`);
      })
      .catch(() => log('folder picker cancelled/unavailable; using private storage'));
  };
  ui.qs<HTMLElement>('#doctor').onclick = () => {
    const urls = ui
      .qs<HTMLInputElement>('#stun')
      .value.split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    ui.qs<HTMLElement>('#doctor-out').textContent = 'probing…';
    void doctorProbe(urls).then((r) => {
      fj.doctor = r;
      ui.qs<HTMLElement>('#doctor-out').textContent = r.detail;
      log(r.detail);
    });
  };
  log('ready');
}

void boot();
