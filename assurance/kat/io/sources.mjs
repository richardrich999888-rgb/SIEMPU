// IO layer: reads vendored and operator-supplied vector files, the git revision and the
// optional laboratory dependency. Everything here touches the file system or a subprocess;
// nothing here decides PASS/FAIL.

import { createHash } from 'node:crypto';
import { closeSync, fstatSync, openSync, readSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Maximum vector file size accepted (fail closed on anything larger). */
const MAX_VECTOR_BYTES = 64 * 1024 * 1024;
/** Maximum size of a dependency package.json read for its version. */
const MANIFEST_MAX_BYTES = 1024 * 1024;

/**
 * Reads at most `limit` bytes from an open descriptor; throws if the file holds more.
 * The descriptor is opened once and never re-resolved by path, so the size check and the read
 * apply to the same file (no check-then-use race on the path).
 * @param {number} fd
 * @param {number} limit
 */
export function readBounded(fd, limit) {
  if (!fstatSync(fd).isFile()) throw new Error('Not a regular file');
  const chunks = [];
  let total = 0;
  const chunk = Buffer.alloc(64 * 1024);
  for (;;) {
    const n = readSync(fd, chunk, 0, chunk.length, null);
    if (n === 0) break;
    total += n;
    // Bound on bytes actually read, so a file that grows after open still fails closed.
    if (total > limit) throw new Error(`Vector file exceeds ${limit} bytes`);
    chunks.push(Buffer.from(chunk.subarray(0, n)));
  }
  return Buffer.concat(chunks, total);
}

/**
 * Reads one file with its SHA-256 (bounded; fails closed above MAX_VECTOR_BYTES).
 * @param {string} root repository root
 * @param {string} path repository-relative path
 */
export function readVectorFile(root, path) {
  const fd = openSync(join(root, path), 'r');
  let bytes;
  try {
    bytes = readBounded(fd, MAX_VECTOR_BYTES);
  } finally {
    closeSync(fd);
  }
  return {
    path,
    text: bytes.toString('utf8'),
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

/**
 * Lists operator-supplied vector files in a directory, sorted by name. Missing directory → [].
 * @param {string} root
 * @param {string} dir repository-relative directory
 * @param {RegExp} pattern file-name filter
 */
export function listVectorFiles(root, dir, pattern) {
  let names;
  try {
    names = readdirSync(join(root, dir));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  return names
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
  const dir = join(root, 'packages/pqc-lab/node_modules/@noble/post-quantum');
  let manifestFd;
  try {
    manifestFd = openSync(join(dir, 'package.json'), 'r');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return {
      module: null,
      version: null,
      reason:
        'packages/pqc-lab dependencies not installed (run: npm ci --prefix packages/pqc-lab --ignore-scripts)',
    };
  }
  let version;
  try {
    version = JSON.parse(readBounded(manifestFd, MANIFEST_MAX_BYTES).toString('utf8')).version;
  } finally {
    closeSync(manifestFd);
  }
  return {
    module: await import(pathToFileURL(join(dir, 'hybrid.js')).href),
    version,
    reason: null,
  };
}
