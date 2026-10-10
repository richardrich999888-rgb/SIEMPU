// IO layer: reads vendored and operator-supplied vector files, the git revision and the
// optional laboratory dependency. Everything here touches the file system or a subprocess;
// nothing here decides PASS/FAIL.

import { createHash } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Maximum vector file size accepted (fail closed on anything larger). */
const MAX_VECTOR_BYTES = 64 * 1024 * 1024;

/**
 * Reads one regular file with its SHA-256, bounded by MAX_VECTOR_BYTES.
 *
 * The size check and the read use the same open descriptor, so the file cannot be replaced or
 * swapped between them (CWE-367). The read is bounded by the checked size: a file that grows or
 * shrinks while being read is rejected instead of being hashed in an inconsistent state.
 * @param {string} root repository root
 * @param {string} path repository-relative path
 */
export function readVectorFile(root, path) {
  const fd = openSync(join(root, path), 'r');
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new Error(`Vector path is not a regular file: ${path}`);
    if (info.size > MAX_VECTOR_BYTES) throw new Error(`Vector file too large: ${path}`);
    // One spare byte detects growth after fstat; the read never exceeds the checked size + 1.
    const buffer = Buffer.alloc(info.size + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > info.size) throw new Error(`Vector file changed while reading: ${path}`);
    }
    if (length !== info.size) throw new Error(`Vector file changed while reading: ${path}`);
    const bytes = buffer.subarray(0, length);
    return {
      path,
      text: bytes.toString('utf8'),
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  } finally {
    closeSync(fd);
  }
}

/**
 * Lists operator-supplied vector files in a directory, sorted by name. Missing directory → [].
 * @param {string} root
 * @param {string} dir repository-relative directory
 * @param {RegExp} pattern file-name filter
 */
export function listVectorFiles(root, dir, pattern) {
  const full = join(root, dir);
  if (!existsSync(full)) return [];
  return readdirSync(full)
    .filter((name) => pattern.test(name))
    .sort()
    .map((name) => readVectorFile(root, join(dir, name)));
}

/** Commit and cleanliness of the working tree at `root`. */
export function gitRevision(root) {
  const run = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  try {
    return { commit: run(['rev-parse', 'HEAD']), dirty: run(['status', '--porcelain']) !== '' };
  } catch {
    return { commit: 'unknown (not a git checkout)', dirty: true };
  }
}

/**
 * Loads the laboratory hybrid KEM implementation if its pinned dependency is installed
 * (npm ci --prefix packages/pqc-lab). Returns {module:null, reason} otherwise.
 * @param {string} root
 */
export async function loadLabHybrid(root) {
  const entry = join(root, 'packages/pqc-lab/node_modules/@noble/post-quantum/hybrid.js');
  const pkg = join(root, 'packages/pqc-lab/node_modules/@noble/post-quantum/package.json');
  if (!existsSync(entry))
    return {
      module: null,
      version: null,
      reason:
        'packages/pqc-lab dependencies not installed (run: npm ci --prefix packages/pqc-lab --ignore-scripts)',
    };
  const version = JSON.parse(readFileSync(pkg, 'utf8')).version;
  return { module: await import(pathToFileURL(entry).href), version, reason: null };
}
