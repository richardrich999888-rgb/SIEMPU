import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluateSarif, gateDirectory } from './sarif-gate.mjs';

function report(score, { level = 'warning', tags = ['security'], suppressions = [] } = {}) {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeQL',
            rules: [
              {
                id: 'synthetic/security-rule',
                properties: {
                  ...(score === undefined ? {} : { 'security-severity': score }),
                  tags,
                },
                defaultConfiguration: { level },
              },
            ],
          },
        },
        results: [{ ruleId: 'synthetic/security-rule', ruleIndex: 0, level, suppressions }],
      },
    ],
  };
}
test('SAST gate blocks high/critical, error and ungraded security findings', () => {
  for (const score of ['7.0', '8.9', '9.0', '10'])
    assert.equal(evaluateSarif(report(score)).status, 'FAIL');
  assert.equal(evaluateSarif(report(undefined)).status, 'FAIL');
  assert.equal(evaluateSarif(report('2', { level: 'error' })).status, 'FAIL');
  assert.equal(
    evaluateSarif(report('9.8', { suppressions: [{ kind: 'external', status: 'accepted' }] }))
      .status,
    'FAIL',
  );
});
test('SAST gate reports lower severity without inventing criticality and fails malformed output', () => {
  assert.equal(evaluateSarif(report('6.9')).status, 'PASS');
  assert.equal(evaluateSarif(report(undefined, { tags: ['maintainability'] })).status, 'PASS');
  const clean = report('9');
  clean.runs[0].results = [];
  assert.equal(evaluateSarif(clean).status, 'PASS');
  assert.throws(() => evaluateSarif({ version: '2.1.0', runs: [] }));
  assert.throws(() => evaluateSarif(report('not-a-score')));
  const unresolved = report('8');
  unresolved.runs[0].results[0].ruleId = 'different';
  assert.throws(() => evaluateSarif(unresolved));
});
test('SAST directory gate rejects missing outputs and preserves a blocking report', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-sarif-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await assert.rejects(gateDirectory(dir), /No CodeQL/);
  await writeFile(join(dir, 'javascript.sarif'), JSON.stringify(report('7.5')));
  assert.equal((await gateDirectory(dir)).status, 'FAIL');
});
