import { test, apiLogin, seedFilesAndFolders } from './helpers';
import { expect } from '@playwright/test';

test('TextFilesShowContents', async ({ page }) => {
  await apiLogin(page);
  await seedFilesAndFolders(page);
  await page.goto('/');

  // recorded steps
  await page.getByTestId('Documents').click();
  await page.getByTestId('notes.txt').click();
  await expect(page.locator('pre')).toContainText('Hello from the codegen seed. Line two.');
  await page.getByTestId('file-viewer-close-btn').click();
  await page.getByTestId('README.md').click();
  await expect(page.locator('pre')).toContainText('# Seeded A **markdown** file for the file browser.');
  await page.getByTestId('file-viewer-close-btn').click();
});
