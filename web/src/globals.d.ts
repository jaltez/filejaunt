// Ambient browser APIs the example adapter uses but lib.dom omits or keeps
// optional, plus the debug hook e2e reads. Declared once so no call site
// needs an inline cast.

import type { JauntHook } from './engine';

/** File System Access permission descriptor (missing from lib.dom). */
export interface FsaPermissionDescriptor {
  mode?: 'read' | 'readwrite';
}

declare global {
  interface Window {
    /** Populated by the example adapter; e2e polls it via page.evaluate. */
    __fj?: JauntHook;
    /** Chromium-only File System Access entry point. */
    showDirectoryPicker?: () => Promise<FileSystemDirectoryHandle>;
  }

  /** Directory iteration (lib.dom lacks entries()/keys()/values()). */
  interface FileSystemDirectoryHandle {
    values(): AsyncIterableIterator<FileSystemHandle>;
  }

  /** Permission query/request (Chromium; absent elsewhere). */
  interface FileSystemHandle {
    queryPermission?(descriptor?: FsaPermissionDescriptor): Promise<PermissionState>;
    requestPermission?(descriptor?: FsaPermissionDescriptor): Promise<PermissionState>;
  }
}

export {};
