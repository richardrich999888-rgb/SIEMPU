import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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

function extensionReport(score) {
  const value = report(score);
  const run = value.runs[0];
  const rules = run.tool.driver.rules;
  // Current CodeQL can group rules by query pack; the driver index is unrelated.
  run.tool.driver.rules = [{ id: 'driver-rule', properties: { 'security-severity': '0' } }];
  run.tool.extensions = [{ name: 'codeql/javascript-queries', rules }];
  run.results[0] = {
    ruleId: rules[0].id,
    rule: { id: rules[0].id, index: 0, toolComponent: { index: 0 } },
    level: 'warning',
  };
  return value;
}

test('SAST resolves query-pack rules without using driver severity or waiving suppressions', () => {
  const high = extensionReport('9.8');
  high.runs[0].results[0].suppressions = [{ kind: 'external', status: 'accepted' }];
  assert.equal(evaluateSarif(high).status, 'FAIL');
  assert.equal(evaluateSarif(extensionReport('6.9')).status, 'PASS');
  assert.equal(evaluateSarif(extensionReport(undefined)).status, 'FAIL');
  const noDriverRules = extensionReport('8');
  delete noDriverRules.runs[0].tool.driver.rules;
  assert.equal(evaluateSarif(noDriverRules).status, 'FAIL');
});

test('SAST resolves named or GUID-referenced components and ID-only driver rules', () => {
  for (const ref of [{ name: 'codeql/javascript-queries' }, { guid: 'synthetic-component' }]) {
    const value = extensionReport('9');
    value.runs[0].tool.extensions[0].guid = 'synthetic-component';
    value.runs[0].results[0].rule.toolComponent = ref;
    assert.equal(evaluateSarif(value).status, 'FAIL');
  }
  const legacy = report('8');
  delete legacy.runs[0].results[0].ruleIndex;
  assert.equal(evaluateSarif(legacy).status, 'FAIL');
  const modernDriver = report('6');
  modernDriver.runs[0].results[0].rule = { id: 'synthetic/security-rule', index: 0 };
  assert.equal(evaluateSarif(modernDriver).status, 'PASS');
});

test('SAST rejects ambiguous, conflicting, missing or malformed rule/component references', () => {
  const mutations = [
    (run) => {
      run.results[0].rule.toolComponent.index = 4;
    },
    (run) => {
      run.results[0].rule.toolComponent.index = -1;
    },
    (run) => {
      run.results[0].rule.toolComponent.index = '0';
    },
    (run) => {
      run.results[0].rule.toolComponent.name = 'wrong';
    },
    (run) => {
      run.results[0].rule.toolComponent = {};
    },
    (run) => {
      run.results[0].rule.toolComponent = [];
    },
    (run) => {
      run.results[0].rule = null;
    },
    (run) => {
      run.results[0].rule.index = '0';
    },
    (run) => {
      run.results[0].rule.index = -1;
    },
    (run) => {
      run.results[0].rule.index = 99;
    },
    (run) => {
      run.results[0].ruleIndex = 1;
    },
    (run) => {
      run.results[0].rule.id = 'wrong';
    },
    (run) => {
      run.results[0].rule.guid = 'wrong';
    },
    (run) => {
      run.results[0].rule.toolComponent = { name: 'codeql/javascript-queries' };
      run.tool.extensions.push(structuredClone(run.tool.extensions[0]));
    },
    (run) => {
      delete run.results[0].rule.index;
      run.tool.extensions[0].rules.push(structuredClone(run.tool.extensions[0].rules[0]));
    },
    (run) => {
      run.tool.extensions[0].rules = {};
    },
    (run) => {
      run.tool.extensions = {};
    },
  ];
  for (const mutate of mutations) {
    const value = extensionReport('1');
    mutate(value.runs[0]);
    assert.throws(() => evaluateSarif(value));
  }
});

test('SAST rejects unsuccessful analysis and records parser failures as blocking evidence', async (t) => {
  const failed = report('1');
  failed.runs[0].invocations = [{ executionSuccessful: false }];
  assert.throws(() => evaluateSarif(failed), /unsuccessful invocation/);
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-sarif-parse-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, 'javascript.sarif'), '{broken');
  const summary = await gateDirectory(dir);
  assert.equal(summary.status, 'FAIL');
  assert.equal(summary.reports[0].status, 'FAIL');
  assert.ok(summary.reports[0].error);
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'gate.json'), 'utf8')), summary);
});
