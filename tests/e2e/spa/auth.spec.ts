import { test, expect, uiLogin, TEST_ADMIN } from './coverage-helpers';

test.describe('SPA · authentication', () => {
  test('login page renders the sign-in form', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByTestId('login-form')).toBeVisible();
    await expect(page.getByTestId('login-username-input')).toBeVisible();
    await expect(page.getByTestId('login-password-input')).toBeVisible();
    await expect(page.getByTestId('login-submit-btn')).toBeVisible();
    await expect(page).toHaveTitle(/OxiCloud/i);
  });

  test('wrong password is rejected with an error', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('login-username-input').fill(TEST_ADMIN.username);
    await page.getByTestId('login-password-input').fill('definitely-wrong-password');
    await page.getByTestId('login-submit-btn').click();

    await expect(page.locator('.auth-error[role="alert"]')).toBeVisible();
    // Still on the login page — no redirect into the app.
    await expect(page.getByTestId('login-form')).toBeVisible();
  });

  test('register and setup panels are reachable from login', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('login-to-register-btn').click();
    await expect(page.getByTestId('login-register-form')).toBeVisible();
    await page.getByTestId('login-register-to-login-btn').click();
    await expect(page.getByTestId('login-form')).toBeVisible();
  });

  test('magic-link panel toggles open', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('login-magic-toggle-btn').click();
    await expect(page.getByTestId('login-magic-form')).toBeVisible();
    await expect(page.getByTestId('login-magic-email-input')).toBeVisible();
  });

  test('successful login reaches the files app shell', async ({ page }) => {
    await uiLogin(page);
    await expect(page).toHaveURL(/\/files/);
    await expect(page.getByTestId('appshell-logo-link')).toBeVisible();
    await expect(page.getByTestId('appshell-user-menu-btn')).toBeVisible();
  });

  test('logout returns to the login page', async ({ page }) => {
    await uiLogin(page);
    await page.getByTestId('appshell-user-menu-btn').click();
    await page.getByTestId('appshell-user-menu-logout-btn').click();
    await page.waitForURL('**/login**', { timeout: 15_000 });
    await expect(page.getByTestId('login-form')).toBeVisible();
  });
});
