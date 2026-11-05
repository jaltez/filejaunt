// Shared helpers for the filejaunt web e2e specs: deterministic PRNG file
// creation inside the page, blob exchange between pages, polling on __fj.

import { type Page, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

export const APP = '/filejaunt.html';

/** Same mulberry-style fill used in-page and in-Node (deterministic bytes). */
export const PRNG_FILL_SRC = `(seed, arr) => {
  let s = seed >>> 0;
  for (let i = 0; i < arr.length; i++) {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    arr[i] = (t ^ (t >>> 14)) & 0xff;
  }
}`;

export function prngFill(seed: number, len: number): Uint8Array {
  const arr = new Uint8Array(len);
  const fill = eval(`(${PRNG_FILL_SRC})`) as (s: number, a: Uint8Array) => void;
  fill(seed, arr);
  return arr;
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Deterministic pseudo-random file on the sender's #file-input. */
export async function attachRandomFile(page: Page, name: string, size: number, seed: number): Promise<string> {
  const handle = await page.evaluateHandle(
    ({ name, size, seed, src }) => {
      const arr = new Uint8Array(size);
      const fill = eval(`(${src})`) as (s: number, a: Uint8Array) => void;
      fill(seed, arr);
      const file = new File([arr], name);
      const dt = new DataTransfer();
      dt.items.add(file);
      return dt;
    },
    { name, size, seed, src: PRNG_FILL_SRC },
  );
  await page.$eval(
    '#file-input',
    (el, dt) => {
      (el as HTMLInputElement).files = (dt as unknown as DataTransfer).files;
      el.dispatchEvent(new Event('change', { bubbles: true }));
    },
    handle,
  );
  return sha256Hex(prngFill(seed, size));
}

/** Attach an existing file (Node-side bytes) to the sender's #file-input. */
export async function attachFile(page: Page, name: string, mime: string, bytes: Uint8Array): Promise<void> {
  const handle = await page.evaluateHandle(
    ({ name, mime, bytes }) => {
      const file = new File([new Uint8Array(bytes)], name, { type: mime });
      const dt = new DataTransfer();
      dt.items.add(file);
      return dt;
    },
    { name, mime, bytes: bytes as unknown as number[] },
  );
  await page.$eval(
    '#file-input',
    (el, dt) => {
      (el as HTMLInputElement).files = (dt as unknown as DataTransfer).files;
      el.dispatchEvent(new Event('change', { bubbles: true }));
    },
    handle,
  );
}
/** Repetitive CSV (compressible) built in-page; returns the exact content hash. */
export async function attachCsvFile(page: Page, name: string, approxSize: number): Promise<{ sha: string; size: number }> {
  return page.evaluate(
    ({ name, approxSize }) => {
      const rows: string[] = [];
      let total = 0;
      const pad = 'x'.repeat(64);
      for (let i = 0; total < approxSize; i++) {
        const row = `${i},${i * i},${i * 7},${pad}\n`;
        rows.push(row);
        total += row.length;
      }
      const text = rows.join('');
      const file = new File([text], name, { type: 'text/csv' });
      const dt = new DataTransfer();
      dt.items.add(file);
      const input = document.querySelector('#file-input') as HTMLInputElement;
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
      const buf = new Uint8Array(text.length);
      for (let i = 0; i < text.length; i++) buf[i] = text.charCodeAt(i) & 0xff;
      const p = crypto.subtle
        .digest('SHA-256', buf)
        .then((d) => [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join(''))
        .then((sha) => ({ sha, size: file.size }));
      return p;
    },
    { name, approxSize },
  );
}

export async function fj(page: Page): Promise<any> {
  return page.evaluate(() => (window as unknown as { __fj: unknown }).__fj);
}

export async function waitForState(page: Page, state: string, timeout = 60_000): Promise<void> {
  await expect
    .poll(async () => (await fj(page)).state, { timeout })
    .toBe(state);
}

export async function waitForBlob1(page: Page, timeout = 90_000): Promise<string> {
  await expect
    .poll(async () => (await fj(page)).blob1 as string, { timeout })
    .toBeTruthy();
  return (await fj(page)).blob1;
}

/** Receiver: paste blob-1 + passphrase and press Process; returns blob-2(+answer). */
export async function receiverProcess(page: Page, blob1: string, passphrase: string): Promise<string> {
  await page.fill('#pass-in', passphrase);
  await page.fill('#blob-in', blob1);
  await page.click('#process');
  await expect
    .poll(async () => page.inputValue('#blob-out'), { timeout: 60_000 })
    .not.toBe('');
  return page.inputValue('#blob-out');
}

/** Sender: paste blob-2 (with answer) and press Process. */
export async function senderAccept(page: Page, blobOut: string): Promise<void> {
  await page.fill('#blob-in', blobOut);
  await page.click('#process');
}

export async function startSender(page: Page): Promise<void> {
  await page.goto(APP);
  await page.click('#btn-send');
}

export async function startReceiver(page: Page): Promise<void> {
  await page.goto(APP);
  await page.click('#btn-recv');
}

export async function expectVerifiedFile(page: Page, index: number, sha: string, timeout = 180_000): Promise<void> {
  await expect
    .poll(
      async () => {
        const f = (await fj(page)).files[index];
        return f ? `${f.verified}|${f.sha256}` : 'missing';
      },
      { timeout },
    )
    .toBe(`true|${sha}`);
}

/** Assert no CSP violations / console errors / page errors were logged. */
export function watchConsole(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (m) => {
    // Firefox's own FaviconLoader asks for /favicon.ico and trips img-src —
    // a browser-internal request, not the app fetching anything.
    if (m.type() === 'error' && !m.text().includes('FaviconLoader')) {
      problems.push(`console.error: ${m.text()}`);
    }
  });
  page.on('pageerror', (e) => problems.push(`pageerror: ${String(e)}`));
  return problems;
}
