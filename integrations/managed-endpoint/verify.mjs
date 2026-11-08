import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const hash = (b) => createHash('sha256').update(b).digest('hex');
const insist = (ok) => {
  if (!ok) throw new Error('MANAGED_PACKAGE_INTEGRITY');
};
const safe = (p) =>
  typeof p === 'string' &&
  /^[a-zA-Z0-9_.\/-]+$/.test(p) &&
  p.split('/').every((s) => s && s !== '.' && s !== '..');
const members = (o, fields) => o && Object.keys(o).sort().join() === [...fields].sort().join();

export function verifyCompanion(directory, expectedManifestSha256) {
  insist(/^[a-f0-9]{64}$/.test(expectedManifestSha256 ?? ''));
  directory = resolve(directory);
  const names = [];
  let total = 0;
  function walk(path, relative = '') {
    const stat = lstatSync(path);
    insist(!stat.isSymbolicLink());
    if (stat.isDirectory()) {
      for (const name of readdirSync(path))
        walk(join(path, name), relative ? relative + '/' + name : name);
    } else {
      insist(stat.isFile() && stat.size <= 4 * 1024 * 1024 && safe(relative));
      total += stat.size;
      names.push(relative);
      insist(total <= 16 * 1024 * 1024 && names.length <= 100);
    }
  }
  walk(directory);
  const bytes = readFileSync(join(directory, 'manifest.json'));
  insist(hash(bytes) === expectedManifestSha256);
  const m = JSON.parse(bytes);
  insist(
    members(m, ['schemaVersion', 'component', 'gitCommit', 'gitTree', 'sagGrading', 'files']) &&
      m.schemaVersion === 1 &&
      m.component === 'airon-managed-endpoint' &&
      /^[a-f0-9]{40}$/.test(m.gitCommit) &&
      /^[a-f0-9]{40}$/.test(m.gitTree) &&
      m.sagGrading === 'NOT_ESTABLISHED' &&
      Array.isArray(m.files) &&
      m.files.length > 0 &&
      m.files.length < 100,
  );
  const expected = [];
  for (const f of m.files) {
    insist(
      members(f, ['path', 'bytes', 'sha256']) &&
        safe(f.path) &&
        f.path !== 'manifest.json' &&
        !expected.includes(f.path) &&
        Number.isSafeInteger(f.bytes) &&
        f.bytes > 0 &&
        /^[a-f0-9]{64}$/.test(f.sha256),
    );
    const data = readFileSync(join(directory, f.path));
    insist(data.length === f.bytes && hash(data) === f.sha256);
    expected.push(f.path);
  }
  insist(names.sort().join('\0') === [...expected, 'manifest.json'].sort().join('\0'));
  return {
    component: m.component,
    gitCommit: m.gitCommit,
    files: m.files.length,
    integrity: 'MATCHES_EXPECTED_DIGEST',
    sagGrading: 'NOT_ESTABLISHED',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(verifyCompanion(process.argv[2] ?? '.', process.argv[3]), null, 2));
}
