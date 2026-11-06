// Ambient browser APIs the example adapter uses but lib.dom omits or keeps
// optional, plus the debug hook e2e reads. Declared once so no call site
// needs an inline cast.

import type { JauntHook } from './engine';
import type { FjDirHandle } from './storage';

declare global {
  interface Window {
    /** Populated by the example adapter; e2e polls it via page.evaluate. */
    __fj?: JauntHook;
    /** Chromium-only File System Access entry point. */
    showDirectoryPicker?: () => Promise<FjDirHandle>;
  }
}

export {};
