// Spec 9 — doctor: bogus STUN completes with a classification (no hang);
// with no STUN configured it explains that LAN/host candidates are used.
import { test, expect } from '@playwright/test';
import { APP, fj } from './helpers';

test('doctor with unreachable STUN completes without hanging', async ({ page }) => {
  await page.goto(APP);
  await page.click('#advanced summary');
  await page.fill('#stun', 'stun:127.0.0.1:1');
  await page.click('#doctor');
  await expect
    .poll(() => page.textContent('#doctor-out'), { timeout: 30_000 })
    .toContain('doctor:');
  const hook = await fj(page);
  expect(['blocked', 'symmetric', 'cone']).toContain(hook.doctor.klass);
});

test('doctor without STUN reports the LAN-only default', async ({ page }) => {
  await page.goto(APP);
  await page.click('#advanced summary');
  await page.fill('#stun', '');
  await page.click('#doctor');
  await expect
    .poll(() => page.textContent('#doctor-out'), { timeout: 10_000 })
    .toContain('no STUN servers configured');
  expect((await fj(page)).doctor.klass).toBe('none');
});

