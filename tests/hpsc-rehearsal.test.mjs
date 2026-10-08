// Rehearsal summary: a demonstration passes only with exit 0 and every reported step passing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { DEMOS, stepCounts, summarise, indexMarkdown } from '../scripts/hpsc-rehearsal.mjs';

const steps = (...outcomes) => outcomes.map((outcome, i) => ({ step: `s${i}`, outcome }));
const row = (exitCode, report) => ({
  id: 'd',
  title: 'D',
  exitCode,
  seconds: 1,
  reportPath: 'r',
  report,
});

test('both report shapes are counted; unknown shapes count as zero', () => {
  assert.deepEqual(stepCounts({ steps: steps('PASS', 'FAIL') }), { passed: 1, total: 2 });
  assert.deepEqual(stepCounts({ results: steps('PASS', 'PASS') }), { passed: 2, total: 2 });
  assert.deepEqual(stepCounts(null), { passed: 0, total: 0 });
  assert.deepEqual(stepCounts({ stages: steps('PASS') }), { passed: 0, total: 0 });
});

test('overall PASS requires every demonstration to pass completely', () => {
  assert.equal(
    summarise([row(0, { steps: steps('PASS') }), row(0, { results: steps('PASS') })]).outcome,
    'PASS',
  );
  const failures = [
    [row(1, { steps: steps('PASS') })], // non-zero exit
    [row(0, { steps: steps('PASS', 'FAIL') })], // a failed step
    [row(0, { steps: [] })], // no steps at all
    [row(0, null)], // report missing
    [], // nothing ran
  ];
  for (const results of failures) assert.equal(summarise(results).outcome, 'FAIL');
});

test('the index lists every demonstration and the scripts exist', () => {
  assert.equal(DEMOS.length, 4);
  for (const demo of DEMOS) assert.ok(existsSync(demo.script), demo.script);
  const summary = summarise([row(0, { steps: steps('PASS') })]);
  const md = indexMarkdown({
    ...summary,
    source: { commit: 'abc', dirty: false },
    runtime: { node: 'v24' },
    finishedAt: 't',
  });
  assert.match(md, /\| D \| PASS \| 1\/1 \|/);
});
