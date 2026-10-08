// HPSC rehearsal: runs the four demonstrations in presentation order as separate processes and
// writes one index (artifacts/hpsc-rehearsal/index.{json,md}). Every demonstration runs even if
// an earlier one fails, so the index shows the complete state; the run fails if any failed.
// Laboratory only; excluded from release builds. Synthetic data only.

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sourceRevision, runtimeDescription } from './lib/demo-report.mjs';

const OUTPUT = resolve(process.env.SIEPMU_EVIDENCE_DIR || 'artifacts/hpsc-rehearsal');
/** Per-demonstration ceiling; the slowest (Trust Before Release, 5 iterations) takes ~10 s. */
const DEMO_TIMEOUT_MS = 300000;

/** Presentation order. `report` is the JSON each script writes; `steps` reads its step count. */
export const DEMOS = Object.freeze([
  {
    id: 'demo-1',
    title: 'Secure exchange',
    script: 'scripts/demo.mjs',
    report: 'artifacts/demo/results.json',
    env: {},
  },
  {
    id: 'demo-2',
    title: 'Trust Before Release',
    script: 'scripts/trust-before-release.mjs',
    report: 'artifacts/trust-before-release/report.json',
    env: { SIEPMU_TBR_ITERATIONS: '5' },
  },
  {
    id: 'demo-3',
    title: 'Existing-system integration (synthetic)',
    script: 'scripts/demo-document-exchange.mjs',
    report: 'artifacts/demo-document-exchange/report.json',
    env: {},
  },
  {
    id: 'demo-4',
    title: 'Monitoring and recovery',
    script: 'scripts/demo-monitoring-recovery.mjs',
    report: 'artifacts/demo-monitoring-recovery/report.json',
    env: {},
  },
]);

/**
 * Counts passed and total steps in a demonstration report. Demo 1 writes `results` and Demos 2-4
 * write `steps`; both are arrays of {step, outcome}. Anything else counts as zero steps.
 */
export function stepCounts(report) {
  const list = Array.isArray(report?.steps)
    ? report.steps
    : Array.isArray(report?.results)
      ? report.results
      : [];
  return { passed: list.filter((s) => s?.outcome === 'PASS').length, total: list.length };
}

/**
 * Pure summary: overall PASS only if every demonstration exited 0 and reported all steps passed
 * with at least one step. A missing or unreadable report is a failure, never a pass.
 */
export function summarise(results) {
  const rows = results.map((r) => {
    const counts = stepCounts(r.report);
    const pass = r.exitCode === 0 && counts.total > 0 && counts.passed === counts.total;
    return { ...r, ...counts, outcome: pass ? 'PASS' : 'FAIL' };
  });
  return {
    outcome: rows.length > 0 && rows.every((r) => r.outcome === 'PASS') ? 'PASS' : 'FAIL',
    rows,
  };
}

/** Markdown index for the rehearsal. */
export function indexMarkdown(index) {
  return [
    '# HPSC rehearsal',
    '',
    `Outcome: **${index.outcome}**. Commit \`${index.source.commit}\`${index.source.dirty ? ' (dirty tree)' : ''}. Node ${index.runtime.node}. ${index.finishedAt}.`,
    '',
    '| Demonstration | Outcome | Steps | Seconds | Report |',
    '| --- | --- | --- | ---: | --- |',
    ...index.rows.map(
      (r) =>
        `| ${r.title} | ${r.outcome} | ${r.passed}/${r.total} | ${r.seconds} | \`${r.reportPath}\` |`,
    ),
    '',
    'Synthetic data; single-host laboratory evidence. Not an acceptance test or TRL decision.',
    '',
  ].join('\n');
}

function readReport(path) {
  try {
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
  } catch {
    return null;
  }
}

export function runRehearsal() {
  const results = [];
  for (const demo of DEMOS) {
    console.log(`== ${demo.id}: ${demo.title}`);
    const started = performance.now();
    const run = spawnSync(process.execPath, [demo.script], {
      env: { ...process.env, ...demo.env },
      stdio: 'inherit',
      timeout: DEMO_TIMEOUT_MS,
    });
    results.push({
      id: demo.id,
      title: demo.title,
      exitCode: run.status ?? -1,
      seconds: Math.round((performance.now() - started) / 100) / 10,
      reportPath: demo.report,
      report: readReport(demo.report),
    });
  }
  const summary = summarise(results);
  const index = {
    schemaVersion: 1,
    kind: 'hpsc-rehearsal',
    source: sourceRevision(),
    runtime: runtimeDescription(),
    finishedAt: new Date().toISOString(),
    outcome: summary.outcome,
    // Reports are referenced by path, not embedded, so the index stays small and reviewable.
    rows: summary.rows.map(({ report: _report, ...row }) => row),
  };
  mkdirSync(OUTPUT, { recursive: true });
  writeFileSync(join(OUTPUT, 'index.json'), JSON.stringify(index, null, 2) + '\n');
  writeFileSync(join(OUTPUT, 'index.md'), indexMarkdown(index));
  return index;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const index = runRehearsal();
  console.log(`HPSC rehearsal ${index.outcome}: ${join(OUTPUT, 'index.md')}`);
  if (index.outcome !== 'PASS') process.exitCode = 1;
}
