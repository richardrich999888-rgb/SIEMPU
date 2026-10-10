import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import {
  classify,
  findHits,
  trackedFiles,
  render,
  MANUAL_VERDICTS,
  TERMS,
} from '../scripts/claims-audit.mjs';

test('classify: negation, standard citation, application sense, test text, review', () => {
  const c = (file, text, term) => classify({ file, text, term }).category;
  assert.equal(c('x.md', 'This is not SAG graded.', 'SAG'), 'NEGATED');
  assert.equal(c('x.md', 'ML-KEM is specified in FIPS 203.', 'FIPS'), 'STANDARD');
  assert.equal(c('x.md', 'The device was approved by the admin.', 'approved'), 'DOMAIN');
  assert.equal(c('tests/x.test.mjs', "assert.equal(r, 'SAG')", 'SAG'), 'TEST');
  assert.equal(c('x.md', 'The platform is SAG graded.', 'SAG'), 'REVIEW');
  assert.equal(c('x.md', 'We are quantum-safe.', 'quantum-safe'), 'REVIEW');
});

test('every term pattern is word-bounded (no "message" or "usage" false hits for SAG)', () => {
  const sag = TERMS.find((t) => t.term === 'SAG').re;
  assert.equal(sag.test('message usage'), false);
  assert.equal(sag.test('SAG grading'), true);
});

test('repository audit: every hit has a verdict and no manual verdict is stale', () => {
  const root = resolve('.');
  const hits = findHits(root, trackedFiles(root));
  const { unresolved } = render({ commit: 'test', hits });
  assert.deepEqual(
    unresolved.map((u) => `${u.file}:${u.line}`),
    [],
  );
  for (const key of MANUAL_VERDICTS.keys()) {
    const [file, fragment] = key.split('::');
    assert.ok(
      hits.some((h) => h.file === file && h.text.includes(fragment)),
      `stale: ${key}`,
    );
  }
});

test('manual verdicts marked inaccurate always carry proposed wording', () => {
  for (const [key, [verdict, proposed]] of MANUAL_VERDICTS)
    if (verdict !== 'accurate') assert.ok(proposed && proposed.length > 0, key);
});
