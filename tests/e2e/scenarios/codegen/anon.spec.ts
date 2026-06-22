import { test } from '../helpers';

/**
 * Codegen recorder — START: anonymous at the app root.
 *
 * Run via `just front-codegen` → pick "anon". No login; navigates to `/` and
 * lets the app route an unauthenticated visitor (currently it redirects to
 * /login?redirect=/). Use this to record the logged-out redirect behaviour or
 * a future public landing page. Click the Record ⏺ button to start generating.
 */
test('codegen: anon', async ({ page }) => {
  test.setTimeout(0); // recorder stays open until you close the Inspector
  await page.goto('/');
  await page.pause();
});
