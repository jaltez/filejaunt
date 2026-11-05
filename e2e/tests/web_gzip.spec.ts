// Spec 7 — gzip: 10 MiB of repetitive CSV must arrive with
// wireBytes < 0.6 * size (auto compression decides "on").
import { test, expect } from '@playwright/test';
import {
  attachCsvFile,
  expectVerifiedFile,
  fj,
  receiverProcess,
  senderAccept,
  startReceiver,
  startSender,
  waitForBlob1,
} from './helpers';

test('gzip auto compresses repetitive CSV on the wire', async ({ browser }) => {
  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();

  await startSender(sender);
  await startReceiver(receiver);

  const { sha, size } = await attachCsvFile(sender, 'table.csv', 10 * 1024 * 1024);
  const blob1 = await waitForBlob1(sender, 120_000);
  const passphrase: string = (await fj(sender)).passphrase;

  const blobOut = await receiverProcess(receiver, blob1, passphrase);
  await senderAccept(sender, blobOut);

  await expectVerifiedFile(receiver, 0, sha, 240_000);
  const hook = await fj(receiver);
  const wire: number = hook.files[0].wireBytes;
  expect(wire).toBeGreaterThan(0);
  expect(wire).toBeLessThan(0.6 * size);

  await senderCtx.close();
  await recvCtx.close();
});
