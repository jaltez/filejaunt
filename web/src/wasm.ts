// WASM bootstrap: decode the inlined base64 wasm, initialize the module once,
// and wrap the snake_case wasm-bindgen API in a camelCase facade.
import init, { FjCore as RawFjCore, WASM_B64, type FjActionJson } from 'fj-wasm';

export type { FjActionJson };

// serde_wasm_bindgen hands back JS Maps for JSON objects; flatten to plain
// objects so the rest of the app can use property access.
function plain(value: unknown): unknown {
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value) out[k as string] = plain(v);
    return out;
  }
  if (Array.isArray(value)) return value.map(plain);
  return value;
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
  isDone(): boolean {
    return this.raw.is_done();
  }
  isFailed(): boolean {
    return this.raw.is_failed();
  }
  fileIds(): number[] {
    return this.raw.file_ids();
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
  if (!ready) {
    ready = init({ module_or_path: b64ToBytes(WASM_B64) }).then(() => undefined);
  }
  await ready;
  return new FjCore(new RawFjCore());
}

