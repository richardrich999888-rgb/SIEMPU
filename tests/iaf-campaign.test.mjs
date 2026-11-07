import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validatePlan, tapOutcome, executeFamily, redact } from '../assurance/iaf/run.mjs';
const plan = JSON.parse(readFileSync('assurance/iaf/plan.json'));
const source = new Set(
  execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
    encoding: 'utf8',
  })
    .trim()
    .split('\n'),
);

test('adversarial plan covers every requirement, preserves open gates and rejects invented qualification', () => {
  assert.equal(validatePlan(plan, source), plan);
  for (const mutate of [
    (p) => {
      p.qualification = 'COMPLETE';
    },
    (p) => {
      p.currentAssessment = 'TRL8';
    },
    (p) => {
      p.families.pop();
    },
    (p) => {
      p.families[0].tests = ['../outside.test.mjs'];
    },
    (p) => {
      p.families[0].requirements = [];
    },
    (p) => {
      p.gaps[0].status = 'CLOSED';
    },
    (p) => {
      p.gaps[0].exitEvidence = '';
    },
  ]) {
    const changed = structuredClone(plan);
    mutate(changed);
    assert.throws(() => validatePlan(changed, source));
  }
});

test('campaign requires complete successful execution with no skipped or fabricated summaries', () => {
  const pass = '# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
  assert.equal(tapOutcome(pass, 0).outcome, 'PASS');
  for (const [output, code, terminated] of [
    [pass, 1, false],
    [pass, 0, true],
    ['', 0, false],
    [pass.replace('# skipped 0', '# skipped 1'), 0, false],
    [pass.replace('# tests 2', '# tests 0'), 0, false],
    [pass + '# tests 2\n', 0, false],
    [pass.replace('# pass 2', '# pass 1'), 0, false],
  ])
    assert.equal(tapOutcome(output, code, terminated).outcome, 'FAIL');
});

test('campaign executes real child tests and records failure and skip rather than success', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-campaign-runner-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const [name, code, expected] of [
    ['pass', "import test from 'node:test'; test('synthetic positive control', () => {});", 'PASS'],
    [
      'fail',
      "import test from 'node:test'; test('synthetic negative control', () => { throw new Error('EXPECTED_FAILURE'); });",
      'FAIL',
    ],
    [
      'skip',
      "import test from 'node:test'; test.skip('synthetic skip control', () => {});",
      'FAIL',
    ],
  ]) {
    writeFileSync(join(root, name + '.test.mjs'), code);
    const result = await executeFamily(root, [name + '.test.mjs']);
    assert.equal(result.outcome, expected, result.log);
    assert.equal(result.counts.tests, 1);
  }
  assert.equal(
    redact('password=synthetic-private-value Bearer synthetic-session').includes(
      'synthetic-private-value',
    ),
    false,
  );
});
