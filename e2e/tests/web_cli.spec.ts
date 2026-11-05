// Spec 5 — web ↔ CLI interop, original direction: sender = the web page,
// receiver = `filejaunt receive`. The page applies the CLI's answer via
// core.answerSdp() after initiatorAccept. Proves real DTLS/SCTP interop
// between Chromium and webrtc-rs with one shared protocol implementation.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { rootDir } from './paths';
import {
  APP,
  attachRandomFile,
  expectVerifiedFile,
  fj,
  senderAccept,
  startSender,
  waitForBlob1,
} from './helpers';

const BIN = join(rootDir, 'target', 'debug', 'filejaunt');

interface CliEvent {
  type: string;
  blob2?: string;
  file?: number;
  sha256?: string;
  verified?: boolean;
  ok?: boolean;
  code?: string;
}

test('web sends to the CLI receiver end-to-end (20 MiB) with a valid receipt', async ({ browser }) => {
  const ctx = await browser.newContext();
  const sender = await ctx.newPage();

  const outDir = mkdtempSync(join(tmpdir(), 'fj-cli-recv-'));
  const cli = spawn(BIN, ['receive', '--json', '--yes', '--stun', 'none', '--out', outDir], {
    cwd: rootDir,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const stderr: string[] = [];
  cli.stderr.on('data', (d) => stderr.push(String(d)));

  const events: CliEvent[] = [];
  const lines = createInterface({ input: cli.stdout });
  lines.on('line', (line) => {
    if (line.trim().startsWith('{')) {
      try {
        events.push(JSON.parse(line) as CliEvent);
      } catch {
        /* non-JSON noise */
      }
    }
  });

  await startSender(sender);
  const sha = await attachRandomFile(sender, 'web-20m.bin', 20 * 1024 * 1024, 0x51d5);
  const blob1 = await waitForBlob1(sender, 120_000);
  const passphrase: string = (await fj(sender)).passphrase;

  // Feed the CLI receiver: blob-1 (JSON event line), then the passphrase line.
  cli.stdin.write(`${JSON.stringify({ type: 'hello', blob1 })}\n`);
  cli.stdin.write(`${passphrase}\n`);


  const joined = await new Promise<CliEvent>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`CLI never joined: ${stderr.join('')}`)), 60_000);
    const check = () => {
      const ev = events.find((e) => e.type === 'joined' && e.blob2);
      if (ev) {
        clearTimeout(timer);
        resolve(ev);
      } else if (cli.exitCode !== null) {
        clearTimeout(timer);
        reject(new Error(`CLI exited ${cli.exitCode} before joining: ${stderr.join('')}`));
      } else {
        setTimeout(check, 100);
      }
    };
    check();
  });


  // Sender consumes blob-2 (answer applied internally via core.answerSdp()).
  await senderAccept(sender, joined.blob2!);


  // CLI writes the file and exits 0.
  const [exitCode] = await new Promise<[number | null]>((resolve) => {
    cli.on('close', (code) => resolve([code]));
  });
  expect(stderr.join('')).not.toMatch(/error/i);
  expect(exitCode).toBe(0);

  const fileDone = events.find((e) => e.type === 'fileDone');
  expect(fileDone?.sha256).toBe(sha);
  expect(fileDone?.verified).toBe(true);
  const onDisk = readdirSync(outDir).find((f) => f === 'web-20m.bin');
  expect(onDisk).toBeTruthy();
  const diskSha = createHash('sha256').update(readFileSync(join(outDir, onDisk!))).digest('hex');
  expect(diskSha).toBe(sha);

  // Web sender got its receipt + verification too.
  await expectVerifiedFile(sender, 0, sha, 120_000);
  expect((await fj(sender)).receipts.length).toBe(1);

  // Verify the CLI-stored receipt with the passphrase.
  const receiptsDir = join(homedir(), '.local', 'share', 'filejaunt', 'receipts');
  expect(existsSync(receiptsDir)).toBe(true);
  const sid: string = (await fj(sender)).sid;
  const receiptFile = readdirSync(receiptsDir)
    .filter((f) => f.startsWith(`${sid}-`))
    .map((f) => join(receiptsDir, f))
    .sort()
    .pop();
  expect(receiptFile).toBeTruthy();
  const verify = spawn(BIN, ['verify', '--receipt', receiptFile!]);
  verify.stdin.write(`${passphrase}\n`);
  const { verifyOut, verifyCode } = await new Promise<{ verifyOut: string; verifyCode: number | null }>((resolve) => {
    let out = '';
    verify.stdout.on('data', (d) => (out += String(d)));
    verify.on('close', (code) => resolve({ verifyOut: out, verifyCode: code }));
  });
  expect(verifyCode).toBe(0);
  expect(verifyOut).toContain('VALID');

  await ctx.close();
});
