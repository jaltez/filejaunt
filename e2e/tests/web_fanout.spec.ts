// Spec 8 — fan-out shape on the web: two independent sender pages, each
// paired with its own receiver context; both receive identical bytes.
import type { Browser } from '@playwright/test';
import { test, expect } from '@playwright/test';
import {
  attachRandomFile,
  expectVerifiedFile,
  fj,
  receiverProcess,
  senderAccept,
  startReceiver,
  startSender,
  waitForBlob1,
} from './helpers';

test('two independent sessions transfer the same file to two receivers', async ({ browser }) => {
  const sha = await runPair(browser, 'fanout-a.bin', 1024 * 1024, 7);
  const sha2 = await runPair(browser, 'fanout-a.bin', 1024 * 1024, 7);
  expect(sha).toBe(sha2);
});

async function runPair(browser: Browser, name: string, size: number, seed: number): Promise<string> {
  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();

  await startSender(sender);
  await startReceiver(receiver);

  const sha = await attachRandomFile(sender, name, size, seed);
  const blob1 = await waitForBlob1(sender);
  const passphrase: string = (await fj(sender)).passphrase;

  const blobOut = await receiverProcess(receiver, blob1, passphrase);
  await senderAccept(sender, blobOut);

  await expectVerifiedFile(receiver, 0, sha);
  await expect
    .poll(async () => (await fj(receiver)).state)
    .toBe('done');

  await senderCtx.close();
  await recvCtx.close();
  return sha;
}
