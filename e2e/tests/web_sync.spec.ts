// Live folder sync (M4): re-picking the same folder after edits propagates
// them — edited file re-verifies with new bytes (supersede), a new file
// arrives, and a deleted file is marked "removed on the sender" while the
// receiver keeps its copy. The live session survives all of it.
import { test, expect, type Page } from '@playwright/test';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
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

async function expectVerifiedByName(page: Page, name: string, sha: string, timeout = 120_000): Promise<void> {
  await expect
    .poll(
      async () => {
        const files = (await fj(page)).files as { name: string; verified?: boolean; sha256?: string }[];
        // a superseded record stays in the sender's list; the newest wins
        const f = files.findLast((x) => x.name === name);
        return f ? `${f.verified}|${f.sha256}` : 'missing';
      },
      { timeout },
    )
    .toBe(`true|${sha}`);
}

/** Read a received file straight from the receiver's OPFS store. */
async function opfsBytes(page: Page, sid: string, rel: string): Promise<Uint8Array> {
  const bytes = await page.evaluate(
    async ({ sid, rel }) => {
      const storage = navigator.storage as unknown as { getDirectory(): Promise<FileSystemDirectoryHandle> };
      let dir = await (await storage.getDirectory()).getDirectoryHandle(`filejaunt-${sid}`);
      const parts = rel.split('/');
      const name = parts.pop() ?? '';
      for (const part of parts) dir = await dir.getDirectoryHandle(part);
      const file = await (await dir.getFileHandle(name)).getFile();
      return [...new Uint8Array(await file.arrayBuffer())];
    },
    { sid, rel },
  );
  return Uint8Array.from(bytes);
}

test('live folder sync: edit, add, delete propagate while the share stays open', async ({ browser }) => {
  const root = await mkdtemp(join(tmpdir(), 'fj-sync-'));
  const dir = join(root, 'syncroot');
  await mkdir(join(dir, 'sub'), { recursive: true });
  const aBytes = prngFill(0xa1, 64 * 1024);
  const bBytes = prngFill(0xb2, 128 * 1024);
  const shaEmpty = sha256Hex(new Uint8Array(0));
  await writeFile(join(dir, 'a.txt'), aBytes);
  await writeFile(join(dir, 'sub', 'b.bin'), bBytes);
  await writeFile(join(dir, 'empty.txt'), new Uint8Array(0));

  const senderCtx = await browser.newContext();
  const recvCtx = await browser.newContext();
  const sender = await senderCtx.newPage();
  const receiver = await recvCtx.newPage();
  const problems = watchConsole(sender);
  watchConsole(receiver);

  try {
    await startSender(sender);
    await startReceiver(receiver);
    await sender.check('#live');

    // webkitdirectory pick starts the live share (folder keeps its structure)
    await sender.setInputFiles('#file-input-dir', dir);
    const blob1 = await waitForBlob1(sender);
    const passphrase: string = (await fj(sender)).passphrase;
    const blobOut = await receiverProcess(receiver, blob1, passphrase);
    await senderAccept(sender, blobOut);

    const shaA = sha256Hex(aBytes);
    const shaB = sha256Hex(bBytes);
    await expectVerifiedByName(receiver, 'a.txt', shaA);
    await expectVerifiedByName(receiver, 'b.bin', shaB);
    await expectVerifiedByName(receiver, 'empty.txt', shaEmpty);
    await expectVerifiedByName(sender, 'a.txt', shaA);
    await expectVerifiedByName(sender, 'b.bin', shaB);
    await expect.poll(async () => (await fj(receiver)).state, { timeout: 30_000 }).toBe('transferring');

    // edit a.txt, add c.txt, delete sub/b.bin on disk; re-pick the folder
    const a2 = prngFill(0xa2, 72 * 1024);
    const cBytes = prngFill(0xc3, 32 * 1024);
    await writeFile(join(dir, 'a.txt'), a2);
    await writeFile(join(dir, 'c.txt'), cBytes);
    await rm(join(dir, 'sub', 'b.bin'));
    await sender.setInputFiles('#file-input-dir', dir);

    const shaA2 = sha256Hex(a2);
    const shaC = sha256Hex(cBytes);
    // edited file: new bytes, old id superseded on both sides
    await expectVerifiedByName(receiver, 'a.txt', shaA2);
    await expectVerifiedByName(sender, 'a.txt', shaA2);
    // exactly one row: the superseded record was dropped, not left behind
    await expect(receiver.locator('#files li', { hasText: 'a.txt' })).toHaveCount(1);
    // new file arrives
    await expectVerifiedByName(receiver, 'c.txt', shaC);
    // deleted file: receiver keeps its copy and marks it removed
    await expect
      .poll(async () => receiver.locator('#files').textContent(), { timeout: 60_000 })
      .toContain('removed on the sender');
    const bRow = receiver.locator('#files li', { hasText: 'b.bin' });
    await expect(bRow).toContainText('removed on the sender');
    // the retained copy is still a verified record with its bytes on disk
    const bRec = ((await fj(receiver)).files as { name: string; verified?: boolean }[]).find((f) => f.name === 'b.bin');
    expect(bRec?.verified).toBe(true);
    const sid = (await fj(receiver)).sid as string;
    expect(sha256Hex(await opfsBytes(receiver, sid, 'syncroot/sub/b.bin'))).toBe(shaB);

    // truncating a watched file supersedes it with a zero-byte file: the
    // old bytes must be gone and the empty replacement verified
    await writeFile(join(dir, 'c.txt'), new Uint8Array(0));
    await sender.setInputFiles('#file-input-dir', dir);
    await expectVerifiedByName(receiver, 'c.txt', shaEmpty);
    await expect(receiver.locator('#files li', { hasText: 'c.txt' })).toHaveCount(1);
    expect((await opfsBytes(receiver, sid, 'syncroot/c.txt')).length).toBe(0);

    // session is still live in both directions after all of it
    expect((await fj(sender)).state).toBe('transferring');
    expect((await fj(receiver)).state).toBe('transferring');
    await sender.fill('#text-send', 'sync chat still works');
    await sender.click('#text-send-btn');
    await expect
      .poll(async () => receiver.locator('#text-log').textContent(), { timeout: 15_000 })
      .toContain('sync chat still works');

    // after the share ends, picking the folder again stages the whole tree
    // (records from the finished session must not mask unchanged files)
    await sender.click('#end-share');
    await expect.poll(async () => (await fj(sender)).state, { timeout: 30_000 }).toBe('done');
    await expect.poll(async () => (await fj(receiver)).state, { timeout: 30_000 }).toBe('done');
    await sender.setInputFiles('#file-input-dir', dir);
    await expect
      .poll(
        async () => {
          const h = await fj(sender);
          return `${h.state}|${h.files.length}`;
        },
        { timeout: 30_000 },
      )
      .toBe('pairing|3');

    expect(problems, problems.join('\n')).toEqual([]);
  } finally {
    await senderCtx.close();
    await recvCtx.close();
    await rm(root, { recursive: true, force: true });
  }
});
