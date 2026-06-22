/**
 * Combined-coverage collector for the unit tests.
 *
 * When `COVERAGE=1`, `vite-plugin-istanbul` (wired in vite.config.ts) instruments
 * `src/` during Vitest's transform — the SAME instrumenter the Playwright e2e
 * build uses — so the two coverage sets are mergeable. After every test file we
 * dump the accumulated `globalThis.__coverage__` into `tests/e2e/.nyc_output_unit`
 * (separate from the e2e `.nyc_output`). `tests/e2e/coverage-report.cjs` can then
 * report unit-only, e2e-only, or the merge of both.
 *
 * Off unless `COVERAGE=1`, so the normal `npm run test:unit` is unaffected.
 */
import { afterAll } from 'vitest';

afterAll(async () => {
	if (process.env.COVERAGE !== '1') return;
	const cov = (globalThis as Record<string, unknown>).__coverage__;
	if (!cov) return;
	const fs = await import('node:fs');
	const path = await import('node:path');
	const dir = path.resolve(process.cwd(), '../tests/e2e/.nyc_output_unit');
	fs.mkdirSync(dir, { recursive: true });
	const id = `${process.pid}-${Math.random().toString(36).slice(2)}`;
	fs.writeFileSync(path.join(dir, `unit-${id}.json`), JSON.stringify(cov));
});
