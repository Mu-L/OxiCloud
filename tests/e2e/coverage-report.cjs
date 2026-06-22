#!/usr/bin/env node
/**
 * Coverage reporter for the SPA suites.
 *
 *   node coverage-report.cjs            # e2e only   (.nyc_output)
 *   node coverage-report.cjs unit       # unit only  (.nyc_output_unit)
 *   node coverage-report.cjs combined   # e2e + unit, merged BY SOURCE LINE
 *
 * Each mode writes html + json-summary + text-summary under its own report dir
 * and prints a per-file table + totals. Paths in the coverage data are absolute
 * (.../frontend/src/...); we report them relative to the repo root.
 *
 * ── Why combined isn't a plain istanbul merge ────────────────────────────
 * The e2e build (vite dev server) and the unit build (vitest + the
 * @testing-library/svelte client compile) both instrument with
 * vite-plugin-istanbul, but they compile each `.svelte` file differently, so
 * the resulting statement/fn/branch MAPS have different shapes and ids for the
 * same source. istanbul's `CoverageMap.merge` keys by statement INDEX, so
 * merging two mismatched maps UNIONS them — inflating the denominator and
 * dragging the percentage toward a blend of the two passes instead of the true
 * union of covered code (e.g. admin: e2e 2498 + unit 2717 lines → 4042 merged).
 *
 * Source LINE NUMBERS, however, are identical across the two instrumenters
 * (same source file). So for `combined` we merge by line: we take the e2e
 * FileCoverage as the canonical structure (it instruments the whole app, the
 * widest denominator) and fold the unit pass in by marking any e2e
 * statement/fn/branch whose source line the unit pass covered. Files only the
 * unit pass loaded pass through unchanged. The denominator stays stable; the
 * covered set becomes the genuine e2e ∪ unit union.
 */
const fs = require('fs');
const path = require('path');
const libCoverage = require('istanbul-lib-coverage');
const libReport = require('istanbul-lib-report');
const reports = require('istanbul-reports');

const REPO_ROOT = path.join(__dirname, '..', '..');
const E2E_DIR = path.join(__dirname, '.nyc_output');
const UNIT_DIR = path.join(__dirname, '.nyc_output_unit');

const MODES = {
  e2e: { dirs: [E2E_DIR], report: path.join(__dirname, 'coverage-report'), label: 'E2E' },
  unit: { dirs: [UNIT_DIR], report: path.join(__dirname, 'coverage-report-unit'), label: 'UNIT' },
  combined: {
    report: path.join(__dirname, 'coverage-report-combined'),
    label: 'COMBINED (e2e ∪ unit, by source line)',
  },
};

const mode = process.argv[2] || 'e2e';
const cfg = MODES[mode];
if (!cfg) {
  console.error(`Unknown mode "${mode}". Use: e2e | unit | combined`);
  process.exit(1);
}

/** Merge every coverage-*.json under `dirs` into one istanbul CoverageMap. */
function loadMap(dirs) {
  const m = libCoverage.createCoverageMap({});
  let n = 0;
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
      m.merge(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
      n++;
    }
  }
  return { map: m, count: n };
}

/** `{ sourceLine: maxHits }` for every function, keyed by its declaration line. */
function fnHitsByLine(fc) {
  const out = {};
  const d = fc.data;
  for (const id of Object.keys(d.fnMap)) {
    const loc = d.fnMap[id].decl || d.fnMap[id].loc;
    const line = loc && loc.start ? loc.start.line : undefined;
    if (line != null) out[line] = Math.max(out[line] || 0, d.f[id] || 0);
  }
  return out;
}

/** `{ sourceLine: maxArmHits }` across all branch arms, keyed by arm line. */
function branchHitsByLine(fc) {
  const out = {};
  const d = fc.data;
  for (const id of Object.keys(d.branchMap)) {
    const arms = d.b[id] || [];
    const locs = d.branchMap[id].locations || [];
    for (let k = 0; k < arms.length; k++) {
      const loc = locs[k] || d.branchMap[id].loc;
      const line = loc && loc.start ? loc.start.line : undefined;
      if (line != null) out[line] = Math.max(out[line] || 0, arms[k] || 0);
    }
  }
  return out;
}

/**
 * Build the combined map: e2e structure + unit coverage folded in by line.
 * Anything the unit pass covered on a given source line marks the
 * corresponding (uncovered) e2e statement/fn/branch arm on that line.
 */
function buildLineUnion(mapE2E, mapUnit) {
  const out = libCoverage.createCoverageMap({});
  const e2eFiles = new Set(mapE2E.files());
  const unitFiles = new Set(mapUnit.files());
  const all = new Set([...e2eFiles, ...unitFiles]);

  for (const file of all) {
    if (!e2eFiles.has(file)) {
      out.addFileCoverage(mapUnit.fileCoverageFor(file).data);
      continue;
    }
    if (!unitFiles.has(file)) {
      out.addFileCoverage(mapE2E.fileCoverageFor(file).data);
      continue;
    }
    // Present in both → base on e2e, overlay unit hits by source line.
    const raw = JSON.parse(JSON.stringify(mapE2E.fileCoverageFor(file).data));
    const unitFc = mapUnit.fileCoverageFor(file);
    const unitLines = unitFc.getLineCoverage(); // { line: hits }
    const unitFnLine = fnHitsByLine(unitFc);
    const unitBranchLine = branchHitsByLine(unitFc);

    for (const id of Object.keys(raw.statementMap)) {
      if ((raw.s[id] || 0) === 0) {
        const line = raw.statementMap[id].start.line;
        if (unitLines[line] > 0) raw.s[id] = unitLines[line];
      }
    }
    for (const id of Object.keys(raw.fnMap)) {
      if ((raw.f[id] || 0) === 0) {
        const loc = raw.fnMap[id].decl || raw.fnMap[id].loc;
        const line = loc && loc.start ? loc.start.line : undefined;
        if (line != null && unitFnLine[line] > 0) raw.f[id] = unitFnLine[line];
      }
    }
    for (const id of Object.keys(raw.branchMap)) {
      const arms = raw.b[id] || [];
      const locs = raw.branchMap[id].locations || [];
      for (let k = 0; k < arms.length; k++) {
        if ((arms[k] || 0) === 0) {
          const loc = locs[k] || raw.branchMap[id].loc;
          const line = loc && loc.start ? loc.start.line : undefined;
          if (line != null && unitBranchLine[line] > 0) raw.b[id][k] = unitBranchLine[line];
        }
      }
    }
    out.addFileCoverage(raw);
  }
  return out;
}

let map;
let merged;
if (mode === 'combined') {
  const e2e = loadMap([E2E_DIR]);
  const unit = loadMap([UNIT_DIR]);
  merged = e2e.count + unit.count;
  if (merged === 0) {
    console.error(`No coverage files found for combined in: ${E2E_DIR}, ${UNIT_DIR}`);
    process.exit(1);
  }
  map = buildLineUnion(e2e.map, unit.map);
} else {
  const loaded = loadMap(cfg.dirs);
  map = loaded.map;
  merged = loaded.count;
  if (merged === 0) {
    console.error(`No coverage files found for mode "${mode}" in: ${cfg.dirs.join(', ')}`);
    process.exit(1);
  }
}

const context = libReport.createContext({ dir: cfg.report, coverageMap: map });
reports.create('html').execute(context);
reports.create('json-summary').execute(context);
reports.create('text-summary').execute(context);

const rows = map.files().map((file) => {
  const s = map.fileCoverageFor(file).toSummary();
  return {
    file: path.relative(REPO_ROOT, file),
    pct: s.lines.pct,
    covered: s.lines.covered,
    total: s.lines.total,
  };
});
rows.sort((a, b) => a.pct - b.pct);

console.log(`\n[${cfg.label}] merged ${merged} coverage file(s); ${rows.length} source files.\n`);
console.log('Least-covered files (line %):');
for (const r of rows.slice(0, 30)) {
  console.log(`  ${String(r.pct).padStart(6)}%  ${r.covered}/${r.total}  ${r.file}`);
}

const total = map.getCoverageSummary();
console.log(`\n=== ${cfg.label} TOTAL ===`);
console.log(`Statements : ${total.statements.pct}%  (${total.statements.covered}/${total.statements.total})`);
console.log(`Branches   : ${total.branches.pct}%  (${total.branches.covered}/${total.branches.total})`);
console.log(`Functions  : ${total.functions.pct}%  (${total.functions.covered}/${total.functions.total})`);
console.log(`Lines      : ${total.lines.pct}%  (${total.lines.covered}/${total.lines.total})`);
console.log(`HTML report: ${path.relative(process.cwd(), cfg.report)}/index.html`);
