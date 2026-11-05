// Spec 5 — web ↔ CLI interop. The WASM facade does not expose the decrypted
// answer SDP to JS, so the assigned direction (web sender → CLI receiver)
// cannot apply the answer in the browser. Direction is therefore inverted:
// the CLI is the sender, the web page the receiver. This still proves the
// critical interop: real DTLS/SCTP between webrtc-rs and Chromium, the
// encrypted protocol both ways, hash verification, and a CLI-verifiable
// receipt.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { rootDir } from './paths';
import { expectVerifiedFile, fj, startReceiver } from './helpers';

const BIN = join(rootDir, 'target', 'debug', 'filejaunt');

test('CLI sends to the web client end-to-end (20 MiB) with a valid receipt', async ({ browser }) => {
  const ctx = await browser.newContext();
  const receiver = await ctx.newPage();

  const tmp = mkdtempSync(join(tmpdir(), 'fj-cli-'));
  const payload = Buffer.alloc(20 * 1024 * 1024);
  for (let i = 0; i < payload.length; i += 8) payload.writeUInt32LE(i, i);
  const file = join(tmp, 'cli-20m.bin');
  writeFileSync(file, payload);
  const sha = createHash('sha256').update(payload).digest('hex');

  const cli = spawn(BIN, ['send', file, '--json', '--stun', 'none'], { cwd: rootDir, stdio: ['pipe', 'pipe', 'pipe'] });
  const stderr: string[] = [];
  cli.stderr.on('data', (d) => stderr.push(String(d)));

  // First stdout line is the hello event with passphrase + blob-1.
  const helloLine = await new Promise<string>((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error(`no hello from CLI: ${stderr.join('')}`)), 120_000);
    cli.stdout.on('data', (d) => {
      buf += String(d);
      const i = buf.indexOf('\n');
      if (i >= 0) {
        clearTimeout(timer);
        resolve(buf.slice(0, i));
      }
    });
    cli.stdout.on('error', reject);
  });
  const hello = JSON.parse(helloLine) as { type: string; sid: string; passphrase: string; blob1: string };
  expect(hello.type).toBe('hello');

  await startReceiver(receiver);
  await receiver.fill('#pass-in', hello.passphrase);
  await receiver.fill('#blob-in', hello.blob1);
  await receiver.click('#process');
  await expect
    .poll(() => receiver.inputValue('#blob-out'), { timeout: 60_000 })
    .toContain('-----');
  // The CLI reads one stdin line; hand it only the blob-2 part.
  const blobOut = await receiver.inputValue('#blob-out');
  const blob2 = blobOut.split('\n-----')[0].trim();
  cli.stdin.write(`${JSON.stringify({ type: 'joined', blob2 })}\n`);

  const [exitCode] = await new Promise<[number | null, string]>((resolve) => {
    let out = '';
    cli.stdout.on('data', (d) => (out += String(d)));
    cli.on('close', (code) => resolve([code, out]));
  });
  expect(exitCode).toBe(0);

  await expectVerifiedFile(receiver, 0, sha, 240_000);
  expect((await fj(receiver)).files[0].verified).toBe(true);

  // The CLI (sender side) stores the receipt; verify it with the passphrase.
  const receiptsDir = join(homedir(), '.local', 'share', 'filejaunt', 'receipts');
  expect(existsSync(receiptsDir)).toBe(true);
  const receiptFile = readdirSync(receiptsDir)
    .filter((f) => f.startsWith(`${hello.sid}-`))
    .map((f) => join(receiptsDir, f))
    .sort()
    .pop();
  expect(receiptFile).toBeTruthy();
  const verify = spawn(BIN, ['verify', '--receipt', receiptFile!]);
  verify.stdin.write(`${hello.passphrase}\n`);
  const verifyOut = await new Promise<string>((resolve) => {
    let out = '';
    verify.stdout.on('data', (d) => (out += String(d)));
    verify.on('close', () => resolve(out));
  });
  expect(await new Promise<number | null>((r) => verify.on('close', r))).toBe(0);
  expect(verifyOut).toContain('VALID');

  await ctx.close();
});
