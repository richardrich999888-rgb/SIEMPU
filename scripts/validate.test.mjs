import test from 'node:test';
import assert from 'node:assert/strict';
import { failureExcerpt } from './validate.mjs';

test('failure excerpt returns the failing-tests section without stack frames', () => {
  const log = [
    'ok 1 - passing',
    '✖ failing tests:',
    '',
    'test at tests/x.test.mjs:3:1',
    '✖ broken case (5ms)',
    '  AssertionError [ERR_ASSERTION]: 1 !== 2',
    '      at TestContext.<anonymous> (file:///x.test.mjs:4:10)',
  ].join('\n');
  const excerpt = failureExcerpt(log);
  assert.match(excerpt, /failing tests:/);
  assert.match(excerpt, /broken case/);
  assert.match(excerpt, /AssertionError/);
  assert.doesNotMatch(excerpt, /^\s+at /m);
  assert.doesNotMatch(excerpt, /ok 1 - passing/);
});

test('failure excerpt falls back to a bounded tail when no test section exists', () => {
  const log = Array.from({ length: 500 }, (_, i) => `line ${i}`).join('\n');
  const excerpt = failureExcerpt(log);
  assert.equal(excerpt.split('\n').length, 120);
  assert.match(excerpt, /line 499$/);
  assert.doesNotMatch(excerpt, /line 379\n/);
});

test('failure excerpt is size bounded', () => {
  const excerpt = failureExcerpt('x'.repeat(100000));
  assert.ok(excerpt.length <= 16 * 1024 + '\n[truncated]'.length);
  assert.match(excerpt, /\[truncated\]$/);
});
