import test from 'node:test';
import assert from 'node:assert/strict';
import { iterationsFromEnv, markdownReport, percentile } from '../scripts/trust-before-release.mjs';

test('nearest-rank percentile is deterministic and order independent', () => {
  assert.equal(percentile([5, 1, 4, 2, 3], 50), 3);
  assert.equal(percentile([5, 1, 4, 2, 3], 95), 5);
  assert.equal(percentile([7], 50), 7);
  assert.equal(percentile([1, 2, 3, 4], 0), 1);
});

test('iteration count is bounded and malformed input fails closed', () => {
  assert.equal(iterationsFromEnv(undefined), 20);
  assert.equal(iterationsFromEnv('5'), 5);
  assert.equal(iterationsFromEnv('200'), 200);
  for (const bad of ['4', '201', '10.5', 'ten', '', '-1'])
    assert.throws(() => iterationsFromEnv(bad), /SIEPMU_TBR_ITERATIONS/);
});

test('markdown report states outcome, commit, dirty flag, steps and limitations', () => {
  const md = markdownReport({
    outcome: 'FAIL',
    source: { commit: 'a'.repeat(40), dirty: true },
    startedAt: 's',
    finishedAt: 'f',
    runtime: { node: 'v24', openssl: '3', platform: 'linux', cpuCount: 1, cpu: 'cpu' },
    steps: [{ step: 'one', outcome: 'FAIL', durationMs: 1 }],
    limitations: ['synthetic only'],
  });
  assert.match(md, /Outcome: \*\*FAIL\*\*/);
  assert.match(md, /dirty tree/);
  assert.match(md, /\| 1 \| one \| FAIL \| 1 \|/);
  assert.match(md, /- synthetic only/);
});
