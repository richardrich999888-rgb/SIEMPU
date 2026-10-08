// Guards the TRL self-assessment against drift and overstatement.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';

const matrix = JSON.parse(readFileSync('docs/trl/cte-trl-matrix.json', 'utf8'));
const EXTERNAL_AXES = [
  'relevant-environment-validation',
  'independent-assessment',
  'sponsor-acceptance',
  'operational-qualification',
];
/** Values an internal assessment may record for axes that only outside parties can complete. */
const EXTERNAL_ALLOWED = new Set(['NOT_STARTED', 'NOT_ENGAGED', 'BLOCKED_EXTERNAL']);

test('every referenced source file and test exists', () => {
  for (const element of matrix.elements)
    for (const path of [...element.sourceFiles, ...element.tests])
      assert.ok(existsSync(path), `${element.id}: missing ${path}`);
});

test('ten uniquely identified elements with the full axis set', () => {
  const ids = matrix.elements.map((e) => e.id);
  assert.equal(ids.length, 10);
  assert.equal(new Set(ids).size, 10);
  for (const element of matrix.elements)
    assert.deepEqual(Object.keys(element.axes).sort(), [...matrix.statusAxes].sort(), element.id);
});

test('no element or system level exceeds what an undefined relevant environment allows', () => {
  assert.match(matrix.scale.relevantEnvironmentStatus, /^NOT DEFINED/);
  for (const element of matrix.elements) {
    assert.ok(Number.isInteger(element.provisionalTrl), element.id);
    assert.ok(element.provisionalTrl >= 1 && element.provisionalTrl <= 4, element.id);
    for (const axis of EXTERNAL_AXES)
      assert.ok(EXTERNAL_ALLOWED.has(element.axes[axis]), `${element.id} ${axis}`);
  }
  // The system level never exceeds its highest element, nor 4 without a relevant environment.
  const highest = Math.max(...matrix.elements.map((e) => e.provisionalTrl));
  assert.ok(matrix.systemAssessment.provisionalTrl <= Math.min(highest, 4));
  for (const phrase of ['TRL 5 or 6', 'IAF approval', 'SAG grading'])
    assert.ok(matrix.systemAssessment.notClaimed.includes(phrase), phrase);
});

test('TRL 5 advancement tests are recorded without raising any level', () => {
  const advancement = matrix.systemAssessment.advancementTests;
  assert.equal(
    advancement.decision,
    'TRL 4 validated laboratory prototype with completed TRL 5 advancement tests and outstanding gates',
  );
  for (const path of [advancement.matrix, advancement.decisionRecord, advancement.evidence])
    assert.ok(existsSync(path), path);
  const results = JSON.parse(readFileSync(advancement.evidence, 'utf8'));
  // The recorded evidence must be from a clean tree at the stated revision.
  assert.equal(results.source.commit, advancement.revision);
  assert.equal(results.source.dirty, false);
  assert.equal(results.outcome, 'PASS');
  assert.ok(advancement.openGates.length > 0, 'gates remain open until externally closed');
  assert.equal(matrix.systemAssessment.provisionalTrl, 4);
});

test('frozen TRL 5 advancement evidence matches its manifest byte for byte', () => {
  const dir = dirname(matrix.systemAssessment.advancementTests.evidence);
  const manifest = JSON.parse(readFileSync(join(dir, 'evidence-manifest.json'), 'utf8'));
  assert.ok(Object.keys(manifest.files).length > 0);
  for (const [file, digest] of Object.entries(manifest.files))
    assert.equal(
      createHash('sha256')
        .update(readFileSync(join(dir, file)))
        .digest('hex'),
      digest,
      file,
    );
});
