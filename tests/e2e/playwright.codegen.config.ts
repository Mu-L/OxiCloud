import { defineConfig } from '@playwright/test';
import containers from './playwright.containers.config';

/**
 * Codegen recorder config — reuses the isolated-stack setup from the container
 * e2e config (worker-scoped DB + app container, Nix-chromium executablePath via
 * PW_CHROMIUM_PATH, etc.), but points at the per-template recorder files in
 * scenarios/codegen/ instead of the e2e suite.
 *
 * Driven by `just front-codegen`, which sets OXICLOUD_E2E_CONTAINERS=1 (so the
 * stack boots) and runs one chosen scenarios/codegen/<name>.spec.ts headed.
 */
export default defineConfig({
  ...containers,
  testDir: './scenarios/codegen',
  testIgnore: [],
});
