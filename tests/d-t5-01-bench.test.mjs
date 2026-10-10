import test from 'node:test';
import assert from 'node:assert/strict';
import { LENGTHS, repeatsFor, renderBaseline } from '../assurance/bench/d-t5-01.mjs';

test('baseline configuration matches the requested chain lengths', () => {
  assert.deepEqual([...LENGTHS], [1000, 10000, 100000]);
  assert.equal(repeatsFor(1000), 20);
  assert.equal(repeatsFor(100000), 10);
});

test('baseline report renders rows, the commit and the per-request ceiling', () => {
  const md = renderBaseline({
    result: {
      warmup: 1,
      fit: { msPerRecord: 0.1, fixedMs: 2 },
      rows: [
        {
          records: 1000,
          repeats: 2,
          authorizeMsMedian: 100,
          authorizeMsMean: 100,
          authorizeMsP95: 110,
          authorizeMsMax: 110,
          authorisationsPerSecond: 10,
        },
      ],
    },
    revision: { commit: 'a'.repeat(40), dirty: false },
    command: 'node assurance/bench/d-t5-01.mjs',
    startedAt: 's',
    finishedAt: 'f',
    runtime: { 'Node.js': 'test' },
    cpu: 'test',
  });
  assert.match(md, /\| 1,000 \| 2 \| 100 \| 100 \| 110 \| 110 \| 10 \| 5 \|/);
  assert.match(md, /clean working tree/);
  assert.match(md, /Production code is unchanged/);
});

test('comparison report renders both modes, the speed-up and the v1 limit', async () => {
  const { renderComparison, INCREMENTAL_LENGTHS, APPEND_PER_AUTHORISATION } = await import(
    '../assurance/bench/d-t5-01-compare.mjs'
  );
  assert.deepEqual([...INCREMENTAL_LENGTHS], [1000, 10000, 100000, 250000]);
  assert.equal(APPEND_PER_AUTHORISATION, 4);
  const r = (records, mode, verified, ms) => ({
    records,
    mode,
    appendPerAuthorisation: mode === 'incremental' ? 4 : 0,
    recordsVerifiedPerAuthorisationMax: verified,
    repeats: 2,
    authorizeMsMedian: ms,
    authorizeMsP95: ms,
    authorizeMsMax: ms,
    authorisationsPerSecond: 1000 / ms,
  });
  const md = renderComparison({
    full: {
      warmup: 1,
      fit: { msPerRecord: 0.15, fixedMs: 0 },
      rows: [r(1000, 'full-chain', 1000, 150)],
    },
    incremental: {
      warmup: 1,
      fit: { msPerRecord: 0, fixedMs: 3 },
      rows: [r(1000, 'incremental', 4, 3)],
    },
    revision: { commit: 'b'.repeat(40), dirty: true },
    command: 'node assurance/bench/d-t5-01-compare.mjs',
    startedAt: 's',
    finishedAt: 'f',
    runtime: { 'Node.js': 'test' },
    cpu: 'test',
  });
  assert.match(md, /\| 1,000 \| 1,000 \| 2 \| 150 \|/);
  assert.match(md, /\| 1,000 \| 4 \| 2 \| 3 \|/);
  assert.match(md, /\| 1,000 \| 50× \|/);
  assert.match(md, /uncommitted changes/);
  assert.match(md, /Evidence export exceeds verifier record limit/);
});

test('committed D-T5-01 comparison report is exactly the rendering of its recorded measurements', async () => {
  const { readFileSync } = await import('node:fs');
  const { renderComparison } = await import('../assurance/bench/d-t5-01-compare.mjs');
  const recorded = JSON.parse(
    readFileSync(
      new URL('../docs/assurance/evidence/d-t5-01-compare-d879b4a.json', import.meta.url),
    ),
  );
  const report = readFileSync(
    new URL('../docs/assurance/d-t5-01-incremental.md', import.meta.url),
    'utf8',
  );
  assert.equal(report, renderComparison(recorded));
  assert.equal(recorded.revision.dirty, false, 'measured on a clean tree');
  // Exact, machine-independent outcome of the fix: four records verified per incremental
  // authorisation at every chain length, versus the whole chain for full-chain custody.
  assert.ok(recorded.incremental.rows.every((r) => r.recordsVerifiedPerAuthorisationMax === 4));
  assert.ok(recorded.full.rows.every((r) => r.recordsVerifiedPerAuthorisationMax === r.records));
});
