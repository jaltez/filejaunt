// Live share: session stays open after the files settle; chat works past
// completion, appended files transfer and verify, and BYE ends both sides.
import { test, expect, type Page } from '@playwright/test';
import {
  APP,
  attachRandomFile,
  expectVerifiedFile,
  fj,
  prngFill,
  receiverProcess,
  senderAccept,
  sha256Hex,
  startReceiver,
  startSender,
  waitForBlob1,
  watchConsole,
} from './helpers';

async function appendRandomFile(page: Page, name: string, size: number, seed: number): Promise<string> {
  const handle = await page.evaluateHandle(
    ({ name, size, seed }) => {
      const arr = new Uint8Array(size);
      let s = seed >>> 0;
      for (let i = 0; i < arr.length; i++) {
        s = (s + 0x6d2b79f5) | 0;
        let t = Math.imul(s ^ (s >>> 15), 1 | s);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        arr[i] = (t ^ (t >>> 14)) & 0xff;
      }
      const file = new File([arr], name);
      const dt = new DataTransfer();
      dt.items.add(file);
      return dt;
    },
    { name, size, seed },
  );
  await page.$eval(
    '#append-input',
    (el, dt) => {
      (el as HTMLInputElement).files = (dt as unknown as DataTransfer).files;
      el.dispatchEvent(new Event('change', { bubbles: true }));
    },
    handle,
  );
  return sha256Hex(prngFill(seed, size));
}

test('live share: chat past completion, append verifies, BYE ends both', async ({ browser }) => {
  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();
  const problems = watchConsole(sender);
  watchConsole(receiver);

  await startSender(sender);
  await startReceiver(receiver);
  await sender.check('#live');

  const sha = await attachRandomFile(sender, 'live-first.bin', 2 * 1024 * 1024, 0x11beef);
  const blob1 = await waitForBlob1(sender);
  const passphrase: string = (await fj(sender)).passphrase;
  const blobOut = await receiverProcess(receiver, blob1, passphrase);
  await senderAccept(sender, blobOut);

  await expectVerifiedFile(receiver, 0, sha);
  await expectVerifiedFile(sender, 0, sha);

  // Live session: neither side is done after the files settle.
  await expect
    .poll(async () => (await fj(receiver)).state, { timeout: 30_000 })
    .toBe('transferring');

  // Chat still works after the last byte.
  await sender.fill('#text-send', 'post-completion hello');
  await sender.click('#text-send-btn');
  await expect
    .poll(async () => receiver.locator('#text-log').textContent(), { timeout: 15_000 })
    .toContain('post-completion hello');

  // Append a second file mid-session; it appears and verifies on the receiver.
  const sha2 = await appendRandomFile(sender, 'live-added.bin', 1024 * 1024, 0x22beef);
  await expectVerifiedFile(receiver, 1, sha2, 120_000);
  await expectVerifiedFile(sender, 1, sha2, 120_000);

  // Still open, still live.
  expect((await fj(sender)).state).toBe('transferring');

  // BYE from the sender ends both sides cleanly.
  await sender.click('#end-share');
  await expect
    .poll(async () => (await fj(receiver)).state, { timeout: 30_000 })
    .toBe('done');
  await expect
    .poll(async () => (await fj(sender)).state, { timeout: 30_000 })
    .toBe('done');

  expect(problems, problems.join('\n')).toEqual([]);
  await senderCtx.close();
  await recvCtx.close();
});
