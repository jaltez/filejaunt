import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 240_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4173' },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: { args: ['--autoplay-policy=no-user-gesture-required'] },
      },
    },
    {
      name: 'firefox',
      testMatch: /web_web_transfer\.spec\.ts/,
      use: { ...devices['Desktop Firefox'] },
    },
  ],
  webServer: {
    command: 'node ../web/build.mjs && npx serve ../web/dist -l 4173',
    url: 'http://localhost:4173/filejaunt.html',
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
  },
});
