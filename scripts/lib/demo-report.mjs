// Shared evidence recording for the scripted HPSC demonstrations (laboratory only; excluded
// from release builds). Every step records PASS/FAIL with its own evidence; a demonstration
// passes only if every step passes. Nothing here hides a failed step.

import { execFileSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { cpus, platform, release, totalmem } from 'node:os';
import { join } from 'node:path';

/** Commit and dirty-tree flag of the working copy the demonstration ran from. */
export function sourceRevision() {
  const git = (args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
  try {
    return { commit: git(['rev-parse', 'HEAD']), dirty: git(['status', '--porcelain']) !== '' };
  } catch {
    return { commit: null, dirty: null };
  }
}

/** Host description recorded with every report; results apply to this host only. */
export function runtimeDescription() {
  return {
    node: process.version,
    openssl: process.versions.openssl,
    platform: `${platform()} ${release()}`,
    cpu: cpus()[0]?.model ?? null,
    cpuCount: cpus().length,
    memoryBytes: totalmem(),
  };
}

const elapsed = (start) => Math.round((performance.now() - start) * 100) / 100;

/**
 * Creates a report and a step runner. A failing step is recorded and rethrown so the
 * demonstration stops at the first failure instead of reporting later steps out of context.
 * @param {{kind: string, title: string, configuration: object, limitations: string[]}} meta
 */
export function createDemoReport({ kind, title, configuration, limitations }) {
  const report = {
    schemaVersion: 1,
    kind,
    title,
    synthetic: true,
    startedAt: new Date().toISOString(),
    source: sourceRevision(),
    runtime: runtimeDescription(),
    configuration,
    steps: [],
    limitations,
    outcome: 'INCOMPLETE',
  };
  /** @param {string} name @param {() => Promise<object | void>} fn */
  const step = async (name, fn) => {
    const started = performance.now();
    try {
      const evidence = (await fn()) ?? {};
      report.steps.push({ step: name, outcome: 'PASS', durationMs: elapsed(started), ...evidence });
      console.log(`PASS: ${name}`);
    } catch (error) {
      report.steps.push({
        step: name,
        outcome: 'FAIL',
        durationMs: elapsed(started),
        error: /** @type {Error} */ (error).message,
      });
      console.log(`FAIL: ${name}: ${/** @type {Error} */ (error).message}`);
      throw error;
    }
  };
  return { report, step };
}

/** Markdown rendering of a report: outcome, provenance, step table and limitations. */
export function markdownReport(report) {
  return [
    `# ${report.title}`,
    '',
    `Outcome: **${report.outcome}**. Commit \`${report.source.commit}\`${report.source.dirty ? ' (dirty tree)' : ''}.`,
    `Run ${report.startedAt} → ${report.finishedAt}. Node ${report.runtime.node}, OpenSSL ${report.runtime.openssl}, ${report.runtime.platform}, ${report.runtime.cpuCount}× ${report.runtime.cpu}.`,
    '',
    'Synthetic data only. Laboratory engineering evidence on one host; not an acceptance test, TRL decision, SAG grading or operational trial.',
    '',
    '| # | Step | Outcome | ms |',
    '| --- | --- | --- | --- |',
    ...report.steps.map((s, i) => `| ${i + 1} | ${s.step} | ${s.outcome} | ${s.durationMs} |`),
    '',
    '## Limitations',
    '',
    ...report.limitations.map((l) => `- ${l}`),
    '',
  ].join('\n');
}

/** Writes report.json and report.md into `directory` and returns the report. */
export async function writeDemoReport(directory, report) {
  report.finishedAt = new Date().toISOString();
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  await writeFile(join(directory, 'report.md'), markdownReport(report));
  return report;
}
