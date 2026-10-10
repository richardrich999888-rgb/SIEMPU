// Regression tests for the KAT vector reader (CodeQL js/file-system-race, CWE-367).
// The size check and the read must use one descriptor; non-regular and oversized files fail closed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readVectorFile, listVectorFiles } from '../assurance/kat/io/sources.mjs';

/** Size limit duplicated from sources.mjs on purpose: a silent change must fail this test. */
const MAX_VECTOR_BYTES = 64 * 1024 * 1024;

function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-kat-io-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('readVectorFile returns exact bytes and SHA-256 of a regular file', (t) => {
  const root = scratch(t);
  const text = '# synthetic vector\nCOUNT = 0\n';
  writeFileSync(join(root, 'v.rsp'), text);
  const result = readVectorFile(root, 'v.rsp');
  assert.equal(result.path, 'v.rsp');
  assert.equal(result.text, text);
  assert.equal(result.sha256, createHash('sha256').update(text).digest('hex'));
});

test('readVectorFile reads an empty file', (t) => {
  const root = scratch(t);
  writeFileSync(join(root, 'empty.rsp'), '');
  assert.equal(readVectorFile(root, 'empty.rsp').text, '');
});

test('readVectorFile rejects a directory and a missing path', (t) => {
  const root = scratch(t);
  mkdirSync(join(root, 'dir.rsp'));
  assert.throws(() => readVectorFile(root, 'dir.rsp'), /not a regular file|EISDIR/i);
  assert.throws(() => readVectorFile(root, 'absent.rsp'), /ENOENT/);
});

test('readVectorFile rejects a file one byte over the limit', (t) => {
  const root = scratch(t);
  const path = join(root, 'big.rsp');
  writeFileSync(path, '');
  truncateSync(path, MAX_VECTOR_BYTES + 1); // sparse: no 64 MiB write
  assert.throws(() => readVectorFile(root, 'big.rsp'), /too large|exceeds/);
});

test('listVectorFiles: missing directory is empty; filter and order are deterministic', (t) => {
  const root = scratch(t);
  assert.deepEqual(listVectorFiles(root, 'none', /\.rsp$/), []);
  mkdirSync(join(root, 'vectors'));
  writeFileSync(join(root, 'vectors', 'b.rsp'), 'b');
  writeFileSync(join(root, 'vectors', 'a.rsp'), 'a');
  writeFileSync(join(root, 'vectors', 'c.txt'), 'c');
  assert.deepEqual(
    listVectorFiles(root, 'vectors', /\.rsp$/).map((f) => f.text),
    ['a', 'b'],
  );
});
