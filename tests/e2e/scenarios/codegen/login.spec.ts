import { test } from '../helpers';

/**
 * Codegen recorder — START: the SPA sign-in screen (not authenticated).
 *
 * Run via `just front-codegen` → pick "login". Use this to record the login
 * flow itself. Click the Record ⏺ button in the Inspector to start generating.
 */
test('codegen: login', async ({ page }) => {
  test.setTimeout(0); // recorder stays open until you close the Inspector
  await page.goto('/login');
  await page.pause();
});
