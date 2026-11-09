// Type declarations for the build-time virtual module 'fj-wasm'.
// At build time build.mjs resolves 'fj-wasm' to the wasm-bindgen glue
// (crates/fj-wasm/pkg/filejaunt_wasm.js) plus the inlined WASM bytes.
//
// wasm-bindgen keeps Rust method names (snake_case); wasm.ts wraps them into
// a camelCase facade. Methods throw on error with a plain string
// "CODE: message" where CODE is a protocol ErrorCode (SEC_*, PROTO_*, ...).
declare module 'fj-wasm' {
  export class Hasher {
    constructor();
    update(bytes: Uint8Array): void;
    finish(): string;
  }
  export class FjCore {
    constructor();
    offer_sdp(): string;
    debug_json(): string;
    answer_sdp(): string;
    sender_start(words: number, private3: boolean, offer_sdp: string, channels: number): unknown;
    receiver_join(blob1: string, passphrase: string, answer_sdp: string): string;
    initiator_accept(blob2: string): void;
    initiator_private_blob3(): string;
    responder_private_offer(blob3: string): string;
    responder_private_blob4(answer_sdp: string): string;
    initiator_private_final(blob4: string): void;
    resume_initiator(passphrase: string, offer_sdp: string): string;
    resume_responder(blob1: string, passphrase: string, answer_sdp: string): string;
    set_files(files_json: string): void;
    set_files_live(files_json: string, live: boolean): void;
    append_files(files_json: string): void;
    remove_file(file: number): void;
    end_session(): void;
    is_live(): boolean;
    resolve_gzip_auto(file: number, samples: Uint8Array[]): boolean;
    on_channel_open(): void;
    on_frame(bytes: Uint8Array): void;
    next_send_chunk(file: number): number[] | undefined;
    push_chunk_data(file: number, index: number, bytes: Uint8Array): Uint8Array<ArrayBuffer>;
    hash_feed(file: number, bytes: Uint8Array): void;
    send_text(text: string): Uint8Array<ArrayBuffer>;
    pause(file: number): void;
    resume(file: number): void;
    cancel(file: number): void;
    take_actions(): unknown[];
    snapshot(): string;
    restore(json: string): void;
    verify_checksum(): string | undefined;
    sid(): string;
    is_done(): boolean;
    is_failed(): boolean;
    file_ids(): number[];
    manifest_json(): string | undefined;
    dup_count(file: number): number;
    static FILE_ALL(): number;
    static verify_receipt(receipt_json: string, passphrase: string): boolean;
  }

  /** JSON action shapes returned by take_actions(). */
  export interface FjActionJson {
    t: 'send' | 'saveChunk' | 'saveState' | 'progress' | 'hashFeed' | 'fileDone' | 'receipt' | 'text' | 'done' | 'fail' | 'filesAdded' | 'fileRemoved';
    bytes?: number[];
    file?: number;
    index?: number;
    data?: number[];
    done?: number;
    total?: number;
    wireBytes?: number;
    resumed?: boolean;
    sha256?: string;
    verified?: boolean;
    text?: string;
    code?: string;
    msg?: string;
    receipt?: unknown;
    [k: string]: unknown;
  }

  export function fj_room_from_passphrase(passphrase: string): string;
  /** {room, passphrase} for a `fj-<room8>-<words>` code, else null. */
  export function fj_parse_pairing_code(input: string): { room: string; passphrase: string } | null;
  export function fj_role(core: FjCore): string;
  export const WASM_B64: string;
  export default function init(opts?: { module_or_path?: Uint8Array }): Promise<unknown>;
}
