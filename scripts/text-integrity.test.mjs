import test from 'node:test';
import assert from 'node:assert/strict';
import { isTextPath, textIntegrityViolation } from './text-integrity.mjs';

const utf8 = (text) => new TextEncoder().encode(text);

test('clean UTF-8 source, including tabs, CRLF and non-ASCII text, passes', () => {
  assert.equal(textIntegrityViolation(utf8('')), null);
  assert.equal(textIntegrityViolation(utf8('const a = 1;\r\n\tfoo();\n')), null);
  assert.equal(textIntegrityViolation(utf8('AIRON–SIEPMU §5 — synthetic')), null);
});

test('invalid UTF-8 from a corrupted publication is rejected', () => {
  // Bytes taken from the shape of the a4abc80 damage: text followed by 0xDE 0xAD 0xBE.
  const damaged = Uint8Array.from([...utf8('locations-x'), 0xde, 0xad, 0xbe, 0x47]);
  assert.equal(textIntegrityViolation(damaged), 'INVALID_UTF8');
  assert.equal(textIntegrityViolation(Uint8Array.from([0xc3])), 'INVALID_UTF8');
});

test('control characters and lossy replacement characters are rejected', () => {
  assert.equal(textIntegrityViolation(utf8('a\u0000b')), 'CONTROL_CHARACTER');
  assert.equal(textIntegrityViolation(utf8('a\u001bb')), 'CONTROL_CHARACTER');
  assert.equal(textIntegrityViolation(utf8('a\u007fb')), 'CONTROL_CHARACTER');
  assert.equal(
    textIntegrityViolation(utf8('plaintext = utf\uFFFD\uFFFD')),
    'REPLACEMENT_CHARACTER',
  );
});

test('only declared text extensions are inspected', () => {
  assert.equal(isTextPath('packages/pqc-lab/envelope.mjs'), true);
  assert.equal(isTextPath('research/defence-comparison/sources.json'), true);
  assert.equal(isTextPath('docs/deployment.md'), true);
  assert.equal(isTextPath('artifacts/browser/authority.png'), false);
  assert.equal(isTextPath('Dockerfile'), false);
});
