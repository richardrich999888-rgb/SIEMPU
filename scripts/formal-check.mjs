#!/usr/bin/env node
/**
 * Runs TLC on formal/ReleaseAuthority.tla and enforces the expected outcome of every config:
 * the faithful model must pass; each deliberately broken design must violate exactly the
 * property it was built to break (otherwise the passing result could be vacuous).
 *
 * Requires Java 11+ and the TLA+ tools jar named by SIEPMU_TLA2TOOLS (CI downloads the
 * release v1.8.0 asset and checks its SHA-256 before use). Writes artifacts/formal/report.json.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const formal = join(root, 'formal');
const jar = process.env.SIEPMU_TLA2TOOLS;
if (!jar || !existsSync(jar)) throw new Error('Set SIEPMU_TLA2TOOLS to the verified tla2tools.jar');
/** Upper bound per TLC run; the faithful instance completes in about one minute on 4 cores. */
const TIMEOUT_MS = 20 * 60 * 1000;

const EXPECTED = [
  { config: 'faithful', violation: null },
  { config: 'nonatomic', violation: 'IssueRequiresCurrentAuthority' },
  { config: 'unguarded', violation: 'AckedRevocationHolds' },
];

function runTlc(config) {
  const meta = mkdtempSync(join(tmpdir(), 'siepmu-tlc-'));
  try {
    const run = spawnSync(
      'java',
      [
        '-XX:+UseParallelGC',
        '-cp',
        jar,
        'tlc2.TLC',
        '-workers',
        'auto',
        '-deadlock',
        '-noGenerateSpecTE',
        '-metadir',
        meta,
        '-config',
        `ReleaseAuthority.${config}.cfg`,
        'MCReleaseAuthority.tla',
      ],
      { cwd: formal, encoding: 'utf8', timeout: TIMEOUT_MS, maxBuffer: 256 * 1024 * 1024 },
    );
    if (run.error) throw run.error;
    return { status: run.status, output: run.stdout + run.stderr };
  } finally {
    rmSync(meta, { recursive: true, force: true });
  }
}

/** Last match wins: TLC prints running totals in progress lines before the final summary. */
const number = (text, pattern) => {
  const m = [...text.matchAll(new RegExp(pattern, 'g'))].at(-1);
  return m ? Number(m[1].replace(/,/g, '')) : null;
};

const results = [];
let failed = false;
let tlcVersion = null;
for (const { config, violation } of EXPECTED) {
  const { status, output } = runTlc(config);
  const violatedName = output.match(/(?:Invariant|property) (\w+) is violated/)?.[1] ?? null;
  const passed = /Model checking completed\. No error has been found\./.test(output);
  const ok = violation === null ? passed && status === 0 : violatedName === violation;
  const result = {
    config,
    expected: violation ? `violation of ${violation}` : 'no error',
    observed: passed ? 'no error' : violatedName ? `violation of ${violatedName}` : 'TLC failure',
    ok,
    exitStatus: status,
    distinctStates: number(output, /([\d,]+) distinct states found/),
    depth: number(output, /depth of the complete state graph search is (\d+)/),
    counterexampleStates: violatedName ? (output.match(/^State \d+:/gm) ?? []).length : 0,
  };
  tlcVersion ??= output.match(/TLC2 Version [^\n]+/)?.[0] ?? null;
  results.push(result);
  console.log(JSON.stringify(result));
  if (!ok) {
    failed = true;
    console.error(output.split('\n').slice(-60).join('\n'));
  }
}
mkdirSync(join(root, 'artifacts/formal'), { recursive: true });
writeFileSync(
  join(root, 'artifacts/formal/report.json'),
  JSON.stringify(
    {
      model: 'formal/ReleaseAuthority.tla',
      instance: 'formal/MCReleaseAuthority.tla',
      tlc: tlcVersion,
      results,
      limitations: [
        'Bounded model checking of one finite instance (see formal/README.md), not a proof for all sizes.',
        'The model abstracts the implementation; conformance of core.mjs to the model is argued, not mechanically checked.',
      ],
    },
    null,
    2,
  ) + '\n',
);
process.exitCode = failed ? 1 : 0;
