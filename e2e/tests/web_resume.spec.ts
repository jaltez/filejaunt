// Spec 4 — resume: reload the receiver mid-transfer, re-pair with the same
// passphrase, and finish. The receiver must restore its IndexedDB snapshot
// (auto-restore) and skip already-received chunks.
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
} from './helpers';

test('receiver reload mid-transfer resumes and completes', async ({ browser }) => {
  const recvCtx = await browser.newContext();
  const senderCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  let receiver = await recvCtx.newPage();

  await startSender(sender);
  await startReceiver(receiver);

  const sha = await attachRandomFile(sender, 'resume-64m.bin', 64 * 1024 * 1024, 0xbadc0de);
  const blob1 = await waitForBlob1(sender, 180_000);
  const passphrase: string = (await fj(sender)).passphrase;

  const blobOut = await receiverProcess(receiver, blob1, passphrase);
  await senderAccept(sender, blobOut);

  // Interrupt early enough that plenty of the file remains (loopback is fast);
  // then kill the receiver page mid-transfer.
  await expect
    .poll(async () => (await fj(receiver)).files[0]?.progress ?? 0, { timeout: 240_000 })
    .toBeGreaterThan(20);
  await receiver.reload();
  await receiver.click('#btn-recv');
  // Sender re-pairs: new offer, same session/passphrase.
  await sender.click('#restart');
  await expect
    .poll(async () => (await fj(sender)).blob1 as string, { timeout: 120_000 })
    .not.toBe(blob1);
  const blob1b: string = (await fj(sender)).blob1;

  const blobOut2 = await receiverProcess(receiver, blob1b, passphrase);
  await senderAccept(sender, blobOut2);

  await expectVerifiedFile(receiver, 0, sha, 300_000);
  const hook = await fj(receiver);
  expect(hook.resumedChunks).toBeGreaterThan(0);
  expect(hook.files[0].sha256).toBe(sha);

  await senderCtx.close();
  await recvCtx.close();
});
