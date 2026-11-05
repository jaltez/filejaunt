// Spec 3 — tamper: one flipped base64 char in blob-1 aborts the session with
// a SEC_/PROTO_ error before anything transfers.
import { test, expect } from '@playwright/test';
import { APP, attachRandomFile, fj, startReceiver, startSender, waitForBlob1 } from './helpers';

test('tampered blob-1 fails the session with a protocol/security error', async ({ browser }) => {
  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();

  await startSender(sender);
  await startReceiver(receiver);

  await attachRandomFile(sender, 'tamper.bin', 64 * 1024, 42);
  const blob1 = await waitForBlob1(sender);
  const passphrase: string = (await fj(sender)).passphrase;

  // flip one character in the middle of the base64url payload (a flip near
  // the head can land in gzip's harmless MTIME field)
  const chars = blob1.split('');
  const i = 4 + Math.floor((blob1.length - 4) / 2);
  chars[i] = chars[i] === 'A' ? 'B' : 'A';
  const tampered = chars.join('');
  expect(tampered).not.toBe(blob1);

  await receiver.fill('#pass-in', passphrase);
  await receiver.fill('#blob-in', tampered);
  await receiver.click('#process');

  await expect
    .poll(async () => (await fj(receiver)).state, { timeout: 30_000 })
    .toBe('failed');
  const log: string = (await fj(receiver)).log.join('\n');
  expect(log).toMatch(/SEC_|PROTO_/);

  // Nothing was ever received.
  expect((await fj(receiver)).files).toEqual([]);

  await senderCtx.close();
  await recvCtx.close();
});
