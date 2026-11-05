// Receiver-side storage. Preferred: a picked File System Access directory;
// else OPFS (origin-private, survives reloads — required for resume); else an
// in-memory map finalized through an <a download> blob URL.

// Bytes backed by a plain ArrayBuffer (DOM BufferSource-compatible).
export type Bytes = Uint8Array<ArrayBuffer>;

export interface Sink {
  writeChunk(index: number, chunkSize: number, data: Bytes): Promise<void>;
  close(): Promise<void>;
  /** Read a bounded range (streaming verification; never load whole files). */
  readSlice(offset: number, length: number): Promise<Bytes>;
  /** Disk-backed file/blob for the download link (no full read into RAM). */
  downloadBlob(): Promise<Blob>;
  describe(): string;
}

export interface StoredFile {
  id: number;
  name: string;
  path: string;
  size: number;
}

// Minimal structural types for OPFS/FSA handles (lib.dom coverage varies).
export interface FjDirHandle {
  kind: 'directory';
  name: string;
  getDirectoryHandle(name: string, opts?: { create?: boolean }): Promise<FjDirHandle>;
  getFileHandle(name: string, opts?: { create?: boolean }): Promise<FjFileHandle>;
}
export interface FjFileHandle {
  kind: 'file';
  name: string;
  createWritable(opts?: { keepExistingData?: boolean }): Promise<FjWritable>;
  getFile(): Promise<File>;
}
export interface FjWritable {
  write(
    opts:
      | { type: 'write'; position: number; data: BufferSource }
      | { type: 'truncate'; size: number },
  ): Promise<void>;
  close(): Promise<void>;
}

function newBytes(n: number): Bytes {
  return new Uint8Array(new ArrayBuffer(n));
}

class DirSink implements Sink {
  private writable: FjWritable | null = null;
  private sinceFlush = 0;
  private initialized = false;
  constructor(
    private readonly file: FjFileHandle,
    private readonly label: string,
    private readonly size: number,
  ) {}

  private async w(): Promise<FjWritable> {
    if (!this.writable) {
      // keepExistingData preserves chunks already on disk (resume); the
      // one-shot truncate fixes a stale larger file's tail immediately.
      this.writable = await this.file.createWritable({ keepExistingData: true });
      if (!this.initialized) {
        this.initialized = true;
        await this.writable.write({ type: 'truncate', size: this.size });
      }
    }
    return this.writable;
  }

  async writeChunk(index: number, chunkSize: number, data: Bytes): Promise<void> {
    const w = await this.w();
    await w.write({ type: 'write', position: index * chunkSize, data });
    // OPFS writables are transactional: an abrupt page death discards
    // everything since the last close(). Commit every 128 chunks (2 MiB) so
    // committed data always runs ahead of the 256-chunk snapshot cadence.
    if (++this.sinceFlush >= 128) {
      this.sinceFlush = 0;
      await w.close();
      this.writable = null;
    }
  }

  async close(): Promise<void> {
    await this.writable?.close();
    this.writable = null;
  }

  async readSlice(offset: number, length: number): Promise<Bytes> {
    const f = await this.file.getFile();
    const end = Math.min(offset + length, f.size);
    if (offset >= end) return newBytes(0);
    return new Uint8Array(await f.slice(offset, end).arrayBuffer()) as Bytes;
  }

  async downloadBlob(): Promise<Blob> {
    // File is disk-backed: the object URL streams, no RAM copy.
    return this.file.getFile();
  }

  describe(): string {
    return this.label;
  }
}

class MemorySink implements Sink {
  private parts: (Bytes | undefined)[] = [];
  constructor(readonly entry: StoredFile) {}

  async writeChunk(index: number, _chunkSize: number, data: Bytes): Promise<void> {
    this.parts[index] = data;
  }

  async close(): Promise<void> {
    /* nothing to flush */
  }

  async readSlice(offset: number, length: number): Promise<Bytes> {
    const chunkSize = 16384;
    let out = newBytes(0);
    let o = 0;
    for (let i = Math.floor(offset / chunkSize); i * chunkSize < offset + length; i++) {
      const p = this.parts[i];
      if (!p) continue;
      const start = Math.max(0, offset - i * chunkSize);
      const end = Math.min(p.length, offset + length - i * chunkSize);
      if (end <= start) continue;
      const part = p.subarray(start, end) as Bytes;
      const merged = newBytes(out.length + part.length);
      merged.set(out, 0);
      merged.set(part, out.length);
      out = merged;
      o += part.length;
    }
    void o;
    return out;
  }

  async downloadBlob(): Promise<Blob> {
    return new Blob(this.parts.filter((p): p is Bytes => !!p));
  }

  describe(): string {
    return 'memory';
  }
}

export class ReceiverStore {
  private constructor(
    readonly sid: string,
    private readonly dir: FjDirHandle | null,
    readonly mode: 'fsa' | 'opfs' | 'memory',
  ) {}

  static async create(sid: string, pickedDir: FjDirHandle | null): Promise<ReceiverStore> {
    let dir = pickedDir;
    let mode: 'fsa' | 'opfs' | 'memory' = 'fsa';
    if (!dir) {
      try {
        const storage = navigator.storage as unknown as { getDirectory(): Promise<FjDirHandle> };
        const root = await storage.getDirectory();
        dir = await root.getDirectoryHandle(`filejaunt-${sid}`, { create: true });
        mode = 'opfs';
      } catch {
        dir = null;
        mode = 'memory';
      }
    }
    return new ReceiverStore(sid, dir, mode);
  }

  async sink(entry: StoredFile): Promise<Sink> {
    if (!this.dir) return new MemorySink(entry);
    let d = this.dir;
    if (entry.path) {
      for (const part of entry.path.split('/').filter(Boolean)) {
        d = await d.getDirectoryHandle(part, { create: true });
      }
    }
    const fh = await d.getFileHandle(entry.name, { create: true });
    const where = this.mode === 'opfs' ? `private storage: filejaunt-${this.sid}/` : '';
    return new DirSink(
      fh,
      `${where}${entry.path ? entry.path + '/' : ''}${entry.name}`,
      entry.size,
    );
  }
}
