import { test, apiLogin, seedFilesAndFolders } from '../helpers';

/**
 * Codegen recorder — START: signed in, on a file browser already populated
 * with folders and files of different types.
 *
 * Builds on the "authed" template: same `apiLogin`, but also seeds a small
 * tree via the API before pausing, so you record flows that need existing
 * content (move/copy/delete, drag-drop, previews, multi-select, sorting by
 * type, …) without first creating it by hand.
 *
 * Seeded in the home folder (see `seedFilesAndFolders`):
 *   config.json, pixel.png            (root)
 *   Documents/  → README.md, notes.txt
 *   Documents/Reports/ → data.csv, sample.pdf
 *   Images/     → pixel.png
 *
 * Run via `just front-codegen` → pick "authed-files". Click the Record ⏺
 * button in the Inspector to start generating; copy the code into a real
 * *.spec.ts (see scenarios/example.template.ts). Note the saved test must run
 * `seedFilesAndFolders(page)` in its setup too, or the recorded selectors
 * won't have anything to act on.
 */
test('codegen: authed-files', async ({ page }) => {
  test.setTimeout(0); // recorder stays open until you close the Inspector
  await apiLogin(page);
  await seedFilesAndFolders(page);
  await page.goto('/');
  await page.pause();
});
