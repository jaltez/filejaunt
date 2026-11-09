// WASM bootstrap: decode the inlined base64 wasm, initialize the module once,
// and wrap the snake_case wasm-bindgen API in a camelCase facade.
import init, {
  FjCore as RawFjCore,
  Hasher as RawHasher,
  WASM_B64,
  fj_parse_pairing_code,
  fj_room_from_passphrase,
  type FjActionJson,
} from 'fj-wasm';

// The decrypted answer SDP lives only inside the WASM core; the page applies
// it with `core.answerSdp()` after initiatorAccept — no clear SDP in any blob.

export type { FjActionJson };

// serde_wasm_bindgen hands back JS Maps for JSON objects; flatten to plain
// objects so the rest of the app can use property access.

// The test hook (window.__fj.passphrase) is only populated in e2e mode
// (?e2e=1 in the URL); production pages do not expose it.
export const E2E = typeof location !== 'undefined' && location.search.includes('e2e');

function plain(value: unknown): unknown {
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value) out[k as string] = plain(v);
    return out;
  }
  if (Array.isArray(value)) return value.map(plain);
  return value;
}

/** Incremental SHA-256 (streaming source hashing). */
export class Hasher {
  private readonly raw = new RawHasher();
  update(bytes: Uint8Array): void {
    this.raw.update(bytes);
  }
  finish(): string {
    return this.raw.finish();
  }
}

export interface SenderStart {
  sid: string;
  passphrase: string;
  blob1: string;
}

export class FjCore {
  /** Prefer newFjCore(); construct directly only after WASM init. */
  constructor(private readonly raw: RawFjCore) {}

  senderStart(words: number, private3: boolean, offerSdp: string, channels: number): SenderStart {
    return plain(this.raw.sender_start(words, private3, offerSdp, channels)) as SenderStart;
  }
  receiverJoin(blob1: string, passphrase: string, answerSdp: string): string {
    return this.raw.receiver_join(blob1, passphrase, answerSdp);
  }
  initiatorAccept(blob2: string): void {
    this.raw.initiator_accept(blob2);
  }
  initiatorPrivateBlob3(): string {
    return this.raw.initiator_private_blob3();
  }
  responderPrivateOffer(blob3: string): string {
    return this.raw.responder_private_offer(blob3);
  }
  responderPrivateBlob4(answerSdp: string): string {
    return this.raw.responder_private_blob4(answerSdp);
  }
  initiatorPrivateFinal(blob4: string): void {
    this.raw.initiator_private_final(blob4);
  }
  resumeInitiator(passphrase: string, offerSdp: string): string {
    return this.raw.resume_initiator(passphrase, offerSdp);
  }
  resumeResponder(blob1: string, passphrase: string, answerSdp: string): string {
    return this.raw.resume_responder(blob1, passphrase, answerSdp);
  }
  setFiles(filesJson: string): void {
    this.raw.set_files(filesJson);
  }
  setFilesLive(filesJson: string, live: boolean): void {
    this.raw.set_files_live(filesJson, live);
  }
  appendFiles(filesJson: string): void {
    this.raw.append_files(filesJson);
  }
  removeFile(file: number): void {
    this.raw.remove_file(file);
  }
  endSession(): void {
    this.raw.end_session();
  }
  isLive(): boolean {
    return this.raw.is_live();
  }
  resolveGzipAuto(file: number, samples: Uint8Array[]): boolean {
    return this.raw.resolve_gzip_auto(file, samples);
  }
  onChannelOpen(): void {
    this.raw.on_channel_open();
  }
  onFrame(bytes: Uint8Array): void {
    this.raw.on_frame(bytes);
  }
  nextSendChunk(file: number): number[] | null {
    return this.raw.next_send_chunk(file) ?? null;
  }
  pushChunkData(file: number, index: number, bytes: Uint8Array): Uint8Array<ArrayBuffer> {
    return this.raw.push_chunk_data(file, index, bytes);
  }
  hashFeed(file: number, bytes: Uint8Array): void {
    this.raw.hash_feed(file, bytes);
  }
  sendText(text: string): Uint8Array<ArrayBuffer> {
    return this.raw.send_text(text);
  }
  pause(file: number): void {
    this.raw.pause(file);
  }
  resume(file: number): void {
    this.raw.resume(file);
  }
  cancel(file: number): void {
    this.raw.cancel(file);
  }
  takeActions(): FjActionJson[] {
    return (this.raw.take_actions() as unknown[]).map((a) => plain(a)) as FjActionJson[];
  }
  snapshot(): string {
    return this.raw.snapshot();
  }
  restore(json: string): void {
    this.raw.restore(json);
  }
  sid(): string {
    return this.raw.sid();
  }
  /** "XXXX XXXX" — equal on both peers after relay pairing; null before. */
  verifyChecksum(): string | null {
    return this.raw.verify_checksum() ?? null;
  }
  offerSdp(): string {
    return this.raw.offer_sdp();
  }
  answerSdp(): string {
    return this.raw.answer_sdp();
  }
  isDone(): boolean {
    return this.raw.is_done();
  }
  isFailed(): boolean {
    return this.raw.is_failed();
  }
  fileIds(): number[] {
    return this.raw.file_ids();
  }
  debugJson(): string {
    return this.raw.debug_json();
  }
  manifestJson(): string | null {
    return this.raw.manifest_json() ?? null;
  }
  dupCount(file: number): number {
    return this.raw.dup_count(file);
  }
  static verifyReceipt(receiptJson: string, passphrase: string): boolean {
    return RawFjCore.verify_receipt(receiptJson, passphrase);
  }
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let ready: Promise<void> | null = null;

/** Create the core once the WASM module is up (initialization is one-shot). */
export async function newFjCore(): Promise<FjCore> {
  await ensureReady();
  return new FjCore(new RawFjCore());
}

function ensureReady(): Promise<void> {
  if (!ready) {
    ready = init({ module_or_path: b64ToBytes(WASM_B64) }).then(() => undefined);
  }
  return ready;
}

/** Relay room id: first 8 hex of SHA-256 over the canonical passphrase. */
export async function roomFromPassphrase(passphrase: string): Promise<string> {
  await ensureReady();
  return fj_room_from_passphrase(passphrase);
}

export interface ParsedPairingCode {
  room: string;
  passphrase: string;
}

/** Split `fj-<room8>-<words>` into {room, passphrase}; null for bare input. */
export async function parsePairingCode(input: string): Promise<ParsedPairingCode | null> {
  await ensureReady();
  const parsed = fj_parse_pairing_code(input);
  return parsed ? (plain(parsed) as ParsedPairingCode) : null;
}

