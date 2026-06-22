/**
 * Scaffold for a recorded spec — NOT collected by the runner (no `.spec`/`.test`
 * in the name). Turn a codegen recording into a real test:
 *
 *   1. cp scenarios/example.template.ts scenarios/<name>.spec.ts
 *   2. Match the setup to the codegen TEMPLATE you recorded from (below).
 *   3. Paste the recorded steps from the Playwright Inspector where marked.
 *   4. Add assertions.
 *
 * Run it with: npm run test:containers
 */
import { test, apiLogin } from './helpers';
// import { expect } from '@playwright/test'; // ← uncomment when you add assertions

test('describe the behaviour under test', async ({ page }) => {
  // ── Setup: mirror your codegen TEMPLATE ──────────────────────────────────
  // template "authed" / "authed-*":
  await apiLogin(page);
  await page.goto('/');
  // template "login":   (remove the two lines above)  await page.goto('/login');
  // template "anon":    (remove the two lines above)  await page.goto('/');

  // ── ▼ Paste recorded steps from the Inspector below ▼ ────────────────────

  // ── ▲ End recorded steps ▲ ───────────────────────────────────────────────

  // Assertions, e.g.:
  // await expect(page.getByRole('heading', { name: 'Files' })).toBeVisible();
});
