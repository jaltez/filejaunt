// Spec 2 — private 4-paste pairing (p3): no SDP in the clear inside blobs.
import { test, expect } from '@playwright/test';
import { attachRandomFile, expectVerifiedFile, fj, startReceiver, startSender, waitForBlob1 } from './helpers';

test('private (p3) pairing: 4 pastes, 1 MiB transfers and verifies', async ({ browser }) => {
  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();

  await startSender(sender);
  await sender.check('#private3');

  await startReceiver(receiver);
  await receiver.waitForSelector('#pass-in');

  const sha = await attachRandomFile(sender, 'private-1m.bin', 1024 * 1024, 0xfeed);
  await waitForBlob1(sender);
  const passphrase: string = (await fj(sender)).passphrase;

  // paste 1: blob-1 -> receiver
  await receiver.fill('#pass-in', passphrase);
  await receiver.fill('#blob-in', (await fj(sender)).blob1);
  await receiver.click('#process');
  // blob-2 must NOT contain any SDP (p3 keeps it PAKE-only)
  await expect
    .poll(() => receiver.inputValue('#blob-out'))
    .toContain('FJ1.');
  const blob2 = await receiver.inputValue('#blob-out');
  expect(/v=0|o=-|s=-/.test(blob2)).toBeFalsy();

  // paste 2: blob-2 -> sender (emits blob-3)
  const blob1Out = await sender.inputValue('#blob-out');
  await sender.fill('#blob-in', blob2);
  await sender.click('#process');
  await expect
    .poll(() => sender.inputValue('#blob-out'), { timeout: 30_000 })
    .not.toBe(blob1Out);
  const blob3 = await sender.inputValue('#blob-out');
  expect(blob3).toContain('FJ1.');
  expect(/v=0|o=-|s=-/.test(blob3)).toBeFalsy();

  // paste 3: blob-3 -> receiver (emits blob-4)
  const recvOutBefore = await receiver.inputValue('#blob-out');
  await receiver.fill('#blob-in', blob3);
  await receiver.click('#process');
  await expect
    .poll(() => receiver.inputValue('#blob-out'), { timeout: 30_000 })
    .not.toBe(recvOutBefore);

  // paste 4: blob-4 -> sender
  await sender.fill('#blob-in', await receiver.inputValue('#blob-out'));
  await sender.click('#process');

  await expectVerifiedFile(receiver, 0, sha);
  await expectVerifiedFile(sender, 0, sha);
  await expect
    .poll(async () => (await fj(receiver)).state)
    .toBe('done');

  await senderCtx.close();
  await recvCtx.close();
});
