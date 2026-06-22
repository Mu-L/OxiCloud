import { test, apiLogin } from '../helpers';

/**
 * Codegen recorder — START: signed in, on the file browser.
 *
 * Run via `just front-codegen` → pick "authed". Boots an isolated container
 * stack, runs the setup below, then page.pause() opens the Inspector. Click
 * the Record ⏺ button to start generating; copy the code into a real
 * *.spec.ts (see scenarios/example.template.ts).
 *
 * Extend the setup to record from a deeper state (e.g. open a folder, start an
 * upload) — everything before page.pause() runs first, so you record the
 * continuation.
 */
test('codegen: authed', async ({ page }) => {
  test.setTimeout(0); // recorder stays open until you close the Inspector
  await apiLogin(page);
  await page.goto('/');
  await page.pause();
});
