// IO layer: reads vendored and operator-supplied vector files, the git revision and the
// optional laboratory dependency. Everything here touches the file system or a subprocess;
// nothing here decides PASS/FAIL.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Maximum vector file size accepted (fail closed on anything larger). */
const MAX_VECTOR_BYTES = 64 * 1024 * 1024;

/**
 * Reads one file with its SHA-256.
 * @param {string} root repository root
 * @param {string} path repository-relative path
 */
export function readVectorFile(root, path) {
  const full = join(root, path);
  if (statSync(full).size > MAX_VECTOR_BYTES) throw new Error(`Vector file too large: ${path}`);
  const bytes = readFileSync(full);
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
