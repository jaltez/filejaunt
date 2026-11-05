// Spec 6 — streaming playback: faststart mp4 starts playing while the
// transfer is still running, and verifies at the end.
import { test, expect } from '@playwright/test';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { rootDir } from './paths';
import {
  attachFile,
  expectVerifiedFile,
  fj,
  receiverProcess,
  senderAccept,
  startReceiver,
  startSender,
  waitForBlob1,
} from './helpers';

test('video plays before the transfer completes', async ({ browser }) => {
  // The committed fixture is fragmented (empty moov + moof), which Chromium
  // MSE can stream directly; no runtime remux is involved.
  const fixture = join(rootDir, 'fixtures', 'video-faststart.mp4');
  const bytes = readFileSync(fixture);
  const sha = createHash('sha256').update(bytes).digest('hex');

  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();

  await startSender(sender);
  await startReceiver(receiver);

  await attachFile(sender, 'video-faststart.mp4', 'video/mp4', new Uint8Array(bytes));
  const blob1 = await waitForBlob1(sender, 120_000);
  const passphrase: string = (await fj(sender)).passphrase;

  const blobOut = await receiverProcess(receiver, blob1, passphrase);
  await senderAccept(sender, blobOut);

  // While the transfer runs the video element must be visible (MediaSource
  // streaming engaged, not the download-at-end fallback); playback itself is
  // asserted below once the transfer settles.
  const deadline = Date.now() + 60_000;
  for (;;) {
    const hook = await fj(receiver);
    const file = hook.files[0];
    if (file && file.progress >= 100) break;
    if (file && file.progress > 0) {
      await expect(receiver.locator('#video')).toBeVisible();
    }
    if (Date.now() > deadline) throw new Error('transfer did not finish in time');
    await receiver.waitForTimeout(100);
  }

  await expectVerifiedFile(receiver, 0, sha, 60_000);
  // Streaming (not a download-at-end fallback) actually started playback.
  await expect
    .poll(
      () =>
        receiver.evaluate(() => {
          const v = document.querySelector('#video') as HTMLVideoElement;
          return Math.max(v.currentTime, v.readyState >= 2 ? 1 : 0);
        }),
      { timeout: 15_000 },
    )
    .toBeGreaterThan(0);
  const log: string = (await fj(receiver)).log.join('\n');
  expect(log).not.toContain('streaming disabled');

  await senderCtx.close();
  await recvCtx.close();
});
