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

function extensionReport(score = '8.1') {
  const document = report(score);
  const run = document.runs[0];
  const rules = run.tool.driver.rules;
  run.tool.driver.rules = [];
  run.tool.driver.guid = '11111111-1111-1111-1111-111111111111';
  run.tool.extensions = [
    { name: 'codeql/javascript-queries', guid: '22222222-2222-2222-2222-222222222222', rules },
  ];
  rules[0].guid = '33333333-3333-3333-3333-333333333333';
  run.results[0].rule = {
    id: rules[0].id,
    index: 0,
    toolComponent: { name: 'codeql/javascript-queries', index: 0 },
  };
  run.results[0].locations = [
    {
      physicalLocation: {
        artifactLocation: { uri: 'services/control/core.mjs', index: 0 },
        region: { startLine: 42 },
      },
    },
  ];
  run.artifacts = [{ location: { uri: 'services/control/core.mjs' } }];
  return document;
}

test('CodeQL extension rule metadata controls severity and exposes source path/line', () => {
  const document = extensionReport();
  // A low severity rule with the same index/id in the driver must not override the extension.
  document.runs[0].tool.driver.rules = report('1.0').runs[0].tool.driver.rules;
  const evaluated = evaluateSarif(document);
  assert.equal(evaluated.status, 'FAIL');
  assert.deepEqual(evaluated.blocked[0], {
    ruleId: 'synthetic/security-rule',
    toolComponent: 'codeql/javascript-queries',
    path: 'services/control/core.mjs',
    line: 42,
    locations: [{ path: 'services/control/core.mjs', line: 42 }],
    securitySeverity: 8.1,
    level: 'warning',
    reason: 'HIGH_OR_CRITICAL_SECURITY',
  });
  assert.equal(evaluateSarif(extensionReport('6.9')).status, 'PASS');
});

test('nested references work without legacy fields, empty driver metadata, or inline artifact URI', () => {
  const document = extensionReport(),
    run = document.runs[0];
  delete run.tool.driver.rules;
  delete run.results[0].ruleId;
  delete run.results[0].ruleIndex;
  delete run.results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(evaluateSarif(document).blocked[0].path, 'services/control/core.mjs');
});

test('component and descriptor GUIDs resolve uniquely and must agree with indexes', () => {
  const document = extensionReport(),
    run = document.runs[0],
    result = run.results[0];
  result.rule.toolComponent = { guid: run.tool.extensions[0].guid };
  result.rule.guid = run.tool.extensions[0].rules[0].guid;
  delete result.rule.index;
  delete result.ruleIndex;
  assert.equal(evaluateSarif(document).status, 'FAIL');
  result.rule.id += '/subkind';
  result.ruleId = result.rule.id;
  assert.equal(evaluateSarif(document).status, 'FAIL');
  result.rule.id += '/too-deep';
  result.ruleId = result.rule.id;
  assert.throws(() => evaluateSarif(document), /identifier/);
});

test('unresolved, ambiguous and contradictory component/rule references fail closed', () => {
  const mutations = [
    (run) => {
      run.results[0].rule.toolComponent.index = 9;
    },
    (run) => {
      run.results[0].rule.toolComponent.index = -1;
    },
    (run) => {
      run.results[0].rule.toolComponent.index = '0';
    },
    (run) => {
      run.results[0].rule.toolComponent.name = 'different';
    },
    (run) => {
      run.results[0].rule.toolComponent = { name: 'codeql/javascript-queries' };
    },
    (run) => {
      run.results[0].rule.toolComponent.guid = run.tool.driver.guid;
    },
    (run) => {
      run.results[0].rule.toolComponent = { guid: 'missing' };
    },
    (run) => {
      run.tool.extensions.push(structuredClone(run.tool.extensions[0]));
      run.results[0].rule.toolComponent = { guid: run.tool.extensions[0].guid };
    },
    (run) => {
      run.results[0].rule.index = 1;
    },
    (run) => {
      run.results[0].rule.id = 'conflicting';
    },
    (run) => {
      run.results[0].ruleIndex = -1;
      run.results[0].rule.index = -1;
    },
    (run) => {
      delete run.results[0].ruleIndex;
      delete run.results[0].rule.index;
    },
    (run) => {
      run.results[0].rule.guid = 'missing';
    },
    (run) => {
      run.tool.extensions[0].rules.push(structuredClone(run.tool.extensions[0].rules[0]));
      run.results[0].rule.guid = run.tool.extensions[0].rules[0].guid;
    },
    (run) => {
      run.results[0].rule.toolComponent = null;
    },
    (run) => {
      run.tool.extensions = {};
    },
  ];
  for (const mutate of mutations) {
    const document = extensionReport();
    mutate(document.runs[0]);
    assert.throws(() => evaluateSarif(document));
  }
});

test('duplicate rule IDs require explicit resolving index and cannot select lower severity by guessing', () => {
  const document = report('9'),
    run = document.runs[0];
  run.tool.driver.rules.push(...report('1').runs[0].tool.driver.rules);
  assert.equal(evaluateSarif(document).status, 'FAIL');
  delete run.results[0].ruleIndex;
  assert.throws(() => evaluateSarif(document), /unambiguous/);
});

test('malformed levels, tags and location references cannot turn findings into passes', () => {
  const mutations = [
    (run) => {
      run.results[0].level = 'unknown';
    },
    (run) => {
      run.tool.extensions[0].rules[0].properties.tags = 'security';
    },
    (run) => {
      run.results[0].locations = {};
    },
    (run) => {
      run.results[0].locations[0].physicalLocation.artifactLocation.index = 9;
    },
    (run) => {
      run.results[0].locations[0].physicalLocation.artifactLocation.uri = 'different.mjs';
    },
    (run) => {
      run.results[0].locations[0].physicalLocation.region.startLine = 0;
    },
  ];
  for (const mutate of mutations) {
    const document = extensionReport('1');
    mutate(document.runs[0]);
    assert.throws(() => evaluateSarif(document));
  }
});
