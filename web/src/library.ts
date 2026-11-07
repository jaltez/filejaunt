// Public entry point for the filejaunt web library.
//
// Everything here is DOM-free: a host page supplies a canvas (files, blobs,
// logs) through callbacks and owns all rendering. `web/index.html` is the
// minimal reference implementation; filejaunt.com's app is the rich one.
//
//   import { Jaunt } from './fj.js';
//   const jaunt = await Jaunt.create({ events: { log: console.log } });
//   jaunt.setRole('sender');
//   await jaunt.send(files, { words: 6, channels: 1 });
//   jaunt.hook.blob1; // paste into the other side
export { Jaunt } from './engine';
export type {
  FileView,
  JauntEvents,
  JauntHook,
  JauntOptions,
  JauntPlayer,
  JauntRole,
  JauntState,
  SendOptions,
  SenderStartResult,
  ShareEntry,
} from './engine';
export { doctorProbe } from './transport';
export type { DoctorResult, IceConfig, PathInfo } from './transport';
export { Hasher, newFjCore, FjCore } from './wasm';
export { StreamPlayer } from './media';
export type { FjActionJson } from './wasm';
export type { Bytes, FjDirHandle } from './storage';
