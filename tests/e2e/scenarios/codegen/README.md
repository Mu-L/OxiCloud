# Codegen recorder templates

Each file here is a **starting point** for `just front-codegen`. It boots an
isolated container stack, runs your setup, then opens the Playwright Inspector
so you record from a known state. The file name is what shows up in the menu —
drop a new `*.spec.ts` here and it appears automatically.

## Anatomy

```ts
import { test, apiLogin } from '../helpers';

test('codegen: <name>', async ({ page }) => {
  test.setTimeout(0);   // no timeout — recorder stays open until you close it
  await apiLogin(page); // setup: get to the state you want to record from
  await page.goto('/files');
  await page.pause();    // MUST be last — opens the Inspector
});
```

Rules:

- Import `test` (and any helpers) from `../helpers` — **not** `@playwright/test`.
  That wires in the container-stack fixture and the JS-error guard.
- Set `test.setTimeout(0)` so the recorder doesn't time out while you work.
- End with `await page.pause()`. Everything **before** it runs first, so put as
  much setup as you like there (log in, open a folder, start an upload, …) and
  you'll record the continuation from that state.
- Use the helpers for setup: `apiLogin(page)` signs in via the API (no UI
  clicks, selector-independent). Skip it for an anonymous/login flow.

## What carries into the saved spec

When you save a recording, the setup lines (everything before `page.pause()`,
minus `test.setTimeout`) are copied into the generated `scenarios/<name>.spec.ts`,
then your recorded steps are spliced in. So a recorder's setup == the saved
test's setup — keep it to the state you want every recording from this template
to start in.

## Seeding content before you record

To record flows that need existing files/folders (move, copy, delete,
multi-select, previews, sorting by type), seed them via the API in the setup —
no UI clicks, just like `apiLogin`. The `authed-files` template does this:

```ts
import { test, apiLogin, seedFilesAndFolders } from '../helpers';

test('codegen: authed-files', async ({ page }) => {
  test.setTimeout(0);
  await apiLogin(page);
  await seedFilesAndFolders(page); // Documents/, Documents/Reports/, Images/ + files of each type
  await page.goto('/');
  await page.pause();
});
```

`helpers.ts` exposes the building blocks: `apiCreateFolder`, `apiUploadFile`,
`SAMPLE_FILES` (text / markdown / JSON / CSV / PNG / PDF), and the
`seedFilesAndFolders` convenience that lays down a small mixed-type tree.
**Remember:** the saved spec inherits this setup, so the recorded selectors only
have content to act on if `seedFilesAndFolders(page)` runs there too — it does,
because the template's setup is copied into the saved test.

## Add one

```sh
cp authed.spec.ts my-start.spec.ts   # edit the setup, keep page.pause() last
just front-codegen                   # "my-start" is now in the menu
```
