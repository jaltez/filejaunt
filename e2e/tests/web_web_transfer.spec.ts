// Spec 1 — web ↔ web transfer: 2 browser contexts, 5 MiB random file.
// Verifies end-to-end: pairing, HELO, transfer, hash verification, receipt,
// DIRECT badge, and zero CSP violations.
import { test, expect } from '@playwright/test';
import {
  APP,
  attachRandomFile,
  expectVerifiedFile,
  fj,
  receiverProcess,
  senderAccept,
  startReceiver,
  startSender,
  waitForBlob1,
  watchConsole,
} from './helpers';

test('web to web: 5 MiB random file transfers and verifies', async ({ browser }) => {
  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();
  const problems = watchConsole(sender);
  watchConsole(receiver);

  await startSender(sender);
  await startReceiver(receiver);

  const sha = await attachRandomFile(sender, 'random-5m.bin', 5 * 1024 * 1024, 0xc0ffee);
  const blob1 = await waitForBlob1(sender);
  const passphrase: string = (await fj(sender)).passphrase;
  expect(passphrase.split('-').length).toBeGreaterThanOrEqual(4);

  const blobOut = await receiverProcess(receiver, blob1, passphrase);
  await senderAccept(sender, blobOut);

  await expectVerifiedFile(receiver, 0, sha);
  await expectVerifiedFile(sender, 0, sha);

  // Badge shows a direct path.
  const badge = await receiver.locator('#badge').textContent();
  expect(badge?.startsWith('DIRECT')).toBeTruthy();
  expect((await fj(receiver)).path).toContain('host');

  // Session completes on both sides.
  await expect
    .poll(async () => (await fj(receiver)).state, { timeout: 60_000 })
    .toBe('done');
  await expect
    .poll(async () => (await fj(sender)).state, { timeout: 60_000 })
    .toBe('done');

  // Receipt recorded by the sender.
  const receipts = (await fj(sender)).receipts as unknown[];
  expect(receipts.length).toBe(1);

  // No CSP violations or page errors on either side.
  expect(problems, problems.join('\n')).toEqual([]);

  await senderCtx.close();
  await recvCtx.close();
});
