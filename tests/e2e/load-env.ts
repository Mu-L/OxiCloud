import * as fs from 'fs';

/**
 * Parse a `KEY=VALUE` env file, skipping blank lines and comments.
 *
 * Shared by `playwright.config.ts` (legacy webServer flow) and
 * `fixtures/oxicloud-stack.ts` (Testcontainers flow) so the test server
 * env is defined in exactly one place (`tests/common/server.env`).
 */
export function loadEnv(filePath: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const line of fs.readFileSync(filePath, 'utf-8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx);
    let value = trimmed.slice(idx + 1);
    // Strip matching surrounding quotes, as `source`-ing the file in a shell
    // would. Without this, values like RUST_LOG="warn,audit=info" keep their
    // literal quotes and break the consumer (e.g. tracing's filter parser).
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    env[key] = value;
  }
  return env;
}
