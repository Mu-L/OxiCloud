import { test, apiLogin } from '../helpers';

/**
 * Codegen recorder — START: signed in, on the trash view.
 *
 * Run via `just front-codegen` → pick "authed-trash". An example of a
 * deep-linked start point — copy this file (apiLogin + goto a route) to add
 * your own recorders; `just front-codegen` discovers every *.spec.ts here
 * automatically. Click the Record ⏺ button in the Inspector to start generating.
 */
test('codegen: authed-trash', async ({ page }) => {
  test.setTimeout(0); // recorder stays open until you close the Inspector
  await apiLogin(page);
  await page.goto('/trash');
  await page.pause();
});
