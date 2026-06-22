import { defineConfig, devices } from '@playwright/test';
import * as os from 'os';

/**
 * Testcontainers e2e config (Option D): every worker boots its own isolated
 * DB + OxiCloud app container (Svelte SPA baked in) via the worker-scoped
 * `stack` fixture in `scenarios/helpers.ts`.
 *
 * Differences from `playwright.config.ts` (legacy single-server flow):
 *   - No `webServer`     — the app is a container started per worker.
 *   - No `globalSetup`   — each worker seeds its own admin in the fixture.
 *   - No `use.baseURL`   — the fixture supplies a per-worker random port.
 *   - `fullyParallel` + N workers — stacks are fully isolated, so parallel.
 *
 * Run with: OXICLOUD_E2E_CONTAINERS=1 playwright test -c playwright.containers.config.ts
 * Set $OXICLOUD_IMAGE to a prebuilt tag to skip the per-run Dockerfile build.
 */
export default defineConfig({
  testDir: './scenarios',
  // The recorder harnesses in scenarios/codegen/ call page.pause() and are run
  // only via `just front-codegen` (playwright.codegen.config.ts) — never as
  // part of the e2e suite.
  testIgnore: ['**/codegen/**'],
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // One DB + one app container per worker — cap so we don't exhaust Docker.
  workers: process.env.CI ? 2 : Math.max(1, Math.floor(os.cpus().length / 4)),
  // Real container app is slower than a local cargo process; give actions room.
  timeout: 60_000,
  reporter: process.env.CI ? [['line'], ['github'], ['html']] : [['list'], ['html']],

  use: {
    trace: 'on-first-retry',
    headless: true,
    screenshot: 'only-on-failure',
    // Tile/file rows expose a `data-testid` of the item name (kept only in e2e
    // builds via VITE_E2E); makes getByTestId + codegen prefer stable selectors.
    testIdAttribute: 'data-testid',
    // On NixOS (and other distros where Playwright's downloaded chromium can't
    // run due to the generic dynamic linker), point at a system/Nix chromium
    // via PW_CHROMIUM_PATH. Unset → use Playwright's bundled browser (CI).
    launchOptions: process.env.PW_CHROMIUM_PATH
      ? { executablePath: process.env.PW_CHROMIUM_PATH }
      : {},
  },

  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.01 },
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
