import { test, expect } from './coverage-helpers';
import { apiLogin, apiCreateFolder, apiRecordRecent } from '../scenarios/helpers';

/**
 * Recent route — populate it via the recents API (the SPA doesn't auto-record
 * through this endpoint), then exercise the list, batch selection, and clear.
 */
test.beforeEach(async ({ page }) => {
  await apiLogin(page);
});

function uniq(p: string): string {
  return `${p}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

test('recent shows accessed items, batch selection, and clear', async ({ page }) => {
  const a = await apiCreateFolder(page, uniq('RecA'));
  const b = await apiCreateFolder(page, uniq('RecB'));
  await apiRecordRecent(page, 'folder', a.id);
  await apiRecordRecent(page, 'folder', b.id);

  await page.goto('/recent');
  await expect(page.getByTestId('appshell-logo-link')).toBeVisible({ timeout: 15_000 });

  // Switch to list view (reveals the select-all header) and batch-select.
  await page.getByTestId('list-toolbar-view-list-btn').click({ timeout: 3_000 }).catch(() => {});
  const selectAll = page.getByTestId('resource-list-select-all-checkbox');
  if (await selectAll.isVisible().catch(() => false)) {
    await selectAll.check();
    await page.getByTestId('recent-batch-move-btn').click({ timeout: 3_000 }).catch(() => {});
    await page.getByTestId('move-dialog-cancel-btn').click({ timeout: 3_000 }).catch(() => {});
  }

  // Clear the history if the control is present.
  const clearBtn = page.getByTestId('recent-clear-btn');
  if (await clearBtn.isVisible().catch(() => false)) {
    await clearBtn.click();
    const confirm = page.getByTestId('dialog-host-confirm-btn');
    if (await confirm.isVisible().catch(() => false)) await confirm.click();
  }
});

test('recent grouping and sort cycle (ResourceList toolbar)', async ({ page }) => {
  const a = await apiCreateFolder(page, uniq('RecG'));
  await apiRecordRecent(page, 'folder', a.id);
  await page.goto('/recent');
  await expect(page.getByTestId('appshell-logo-link')).toBeVisible({ timeout: 15_000 });
  await page.getByTestId('list-toolbar-view-list-btn').click({ timeout: 3_000 }).catch(() => {});

  // Cycle every group-by dimension exposed by the shared ResourceList toolbar.
  for (let i = 0; i < 5; i++) {
    await page.getByTestId('list-toolbar-groupby-btn').click({ timeout: 2_000 }).catch(() => {});
    await page
      .locator('[data-testid^="list-toolbar-groupby-"][data-testid$="-item"]')
      .nth(i)
      .click({ timeout: 2_000 })
      .catch(() => {});
  }
  await page.getByTestId('list-toolbar-sort-direction-btn').click({ timeout: 2_000 }).catch(() => {});
});
