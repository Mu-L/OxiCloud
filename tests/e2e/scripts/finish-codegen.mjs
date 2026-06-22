// Assemble a real spec from a codegen recording.
//
// Usage:  node scripts/finish-codegen.mjs <templatePath> <outName>   (recording on stdin)
//
// Takes the recorder template the user started from (scenarios/codegen/<x>.spec.ts),
// keeps its SETUP (everything before page.pause(), minus test.setTimeout), and
// splices in the recorded steps read from stdin — writing scenarios/<outName>.spec.ts.
//
// The pasted recording may be either bare action lines, e.g.
//     await page.getByText('…').click();
// or a whole codegen file, e.g.
//     import { test, expect } from '@playwright/test';
//     test('test', async ({ page }) => { await page.…; });
// In the latter case the import + test(...) wrapper are stripped, leaving the body.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const argv = process.argv.slice(2);

/** Sanitize a name to scenarios/<base>.spec.ts; exit non-zero if invalid/taken. */
function resolveOutPath(rawName) {
  const base = (rawName ?? '')
    .trim()
    .replace(/\.spec\.ts$/, '')
    .replace(/[^a-zA-Z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  if (!base) {
    console.error('finish-codegen: empty/invalid output name');
    process.exit(1);
  }
  const outPath = `scenarios/${base}.spec.ts`;
  if (existsSync(outPath)) {
    console.error(`finish-codegen: ${outPath} already exists — pick another name`);
    process.exit(1);
  }
  return { base, outPath };
}

// `--resolve <name>`: validate a name + print its spec path (no stdin, no write).
// The just recipe loops this to re-prompt until a free, valid name is given.
if (argv[0] === '--resolve') {
  console.log(resolveOutPath(argv[1]).outPath);
  process.exit(0);
}

const [templatePath, rawOutName] = argv;
if (!templatePath || !rawOutName) {
  console.error('usage: finish-codegen.mjs <templatePath> <outName>   (recording on stdin)');
  console.error('   or: finish-codegen.mjs --resolve <outName>');
  process.exit(1);
}

const recording = readFileSync(0, 'utf-8'); // stdin
const template = readFileSync(templatePath, 'utf-8');
const { base, outPath } = resolveOutPath(rawOutName);

/** Body between the first `=> {` and the final `});` of a test file/snippet. */
function callbackBody(src) {
  const m = src.match(/=>\s*\{([\s\S]*)\}\s*\)\s*;?\s*$/);
  return m ? m[1] : null;
}

/** Re-indent non-empty lines to a common 2-space base. */
function reindent(lines, spaces = 2) {
  const body = lines.filter((l) => l.trim());
  const min = body.length ? Math.min(...body.map((l) => l.match(/^\s*/)[0].length)) : 0;
  const pad = ' '.repeat(spaces);
  return lines.map((l) => (l.trim() ? pad + l.slice(min) : ''));
}

// ── 1. helpers import from the template (fix ../helpers → ./helpers) ──────────
const helperImport =
  (template.match(/^import .*from ['"]\.\.\/helpers['"];?$/m) || [])[0]?.replace(
    /\.\.\/helpers/,
    './helpers',
  ) ?? "import { test } from './helpers';";

// ── 2. setup lines = template body before page.pause(), minus setTimeout ──────
const tBody = callbackBody(template);
const setupLines = reindent(
  (tBody ?? '')
    .split('\n')
    .filter((l) => l.trim() && !/page\.pause\(/.test(l) && !/test\.setTimeout\(/.test(l)),
);

// ── 3. recorded steps from stdin (strip wrapper if a whole file was pasted) ───
let recBody = recording;
if (/^\s*(import\b|test\s*\()/.test(recording)) {
  recBody = callbackBody(recording) ?? recording;
}
let actionLines = recBody.split('\n').filter((l) => !/^\s*import\s/.test(l));
while (actionLines.length && !actionLines[0].trim()) actionLines.shift();
while (actionLines.length && !actionLines[actionLines.length - 1].trim()) actionLines.pop();
actionLines = reindent(actionLines);
if (!actionLines.length) {
  console.error('finish-codegen: no recorded steps found in the pasted input');
  process.exit(1);
}

// ── 4. compose ───────────────────────────────────────────────────────────────
const imports = [helperImport];
if (/\bexpect\(/.test(actionLines.join('\n'))) {
  imports.push("import { expect } from '@playwright/test';");
}

const out = [
  ...imports,
  '',
  `test('${base.replace(/'/g, "\\'")}', async ({ page }) => {`,
  ...setupLines,
  '',
  '  // recorded steps',
  ...actionLines,
  '});',
  '',
].join('\n');

writeFileSync(outPath, out);
console.error(`✓ wrote ${outPath}`);
console.log(outPath); // stdout = machine-readable path; the recipe runs it
