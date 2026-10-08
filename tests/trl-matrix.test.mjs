// Guards the TRL self-assessment against drift and overstatement.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

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
