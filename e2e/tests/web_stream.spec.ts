// Spec 6 — streaming playback: faststart mp4 starts playing while the
// transfer is still running, and verifies at the end.
import { test, expect } from '@playwright/test';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { rootDir } from './paths';
import {
  expectVerifiedFile,
  fj,
  receiverProcess,
  senderAccept,
  startReceiver,
  startSender,
  waitForBlob1,
} from './helpers';

test('video plays before the transfer completes', async ({ browser }) => {
  const fixture = join(rootDir, 'fixtures', 'video-faststart.mp4');
  const bytes = readFileSync(fixture);
  const sha = createHash('sha256').update(bytes).digest('hex');

  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();

  await startSender(sender);
  await startReceiver(receiver);

  await sender.setInputFiles('#file-input', fixture);
  const blob1 = await waitForBlob1(sender, 120_000);
  const passphrase: string = (await fj(sender)).passphrase;

  const blobOut = await receiverProcess(receiver, blob1, passphrase);
  await senderAccept(sender, blobOut);

  // While the transfer runs, the video element must be visible and buffering.
  const deadline = Date.now() + 60_000;
  for (;;) {
    const hook = await fj(receiver);
    const file = hook.files[0];
    if (file && file.progress >= 100) break;
    const video = receiver.locator('#video');
    if (file && file.progress > 0) {
      await expect(video).toBeVisible();
      const state = await receiver.evaluate(() => {
        const v = document.querySelector('#video') as HTMLVideoElement;
        return { t: v.currentTime, rs: v.readyState };
      });
      expect(state.t > 0 || state.rs >= 2).toBeTruthy();
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
