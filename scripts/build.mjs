import { mkdir, readFile, readdir, writeFile, copyFile, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
// Native JavaScript has no transpilation step. This packages only an explicit source allowlist.
const roots = ['apps', 'services', 'packages', 'scripts', 'database'];
const excludedScripts = new Set([
  'scripts/demo.mjs',
  'scripts/benchmark.mjs',
  'scripts/release.mjs',
  'scripts/sarif-gate.mjs',
  'scripts/audit-claims.mjs',
  'scripts/validate.mjs',
  'scripts/browser-e2e.mjs',
  'apps/unit-client/browser-check.mjs',
]);
const files = ['package.json', 'package-lock.json', 'LICENSE', 'README.md'];
async function collect(dir) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) await collect(p);
    else if (
      e.isFile() &&
      /\.(mjs|js|css|html|svg|sql|json)$/.test(p) &&
      !p.endsWith('.test.mjs') &&
      !excludedScripts.has(p)
    )
      files.push(p);
  }
}
for (const dir of roots) await collect(dir);
await rm('dist', { recursive: true, force: true });
const manifest = [];
for (const file of files.sort()) {
  const bytes = await readFile(file);
  const dest = join('dist', file);
  await mkdir(dirname(dest), { recursive: true });
  await copyFile(file, dest);
  manifest.push({
    file,
    bytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
}
await writeFile(
  'dist/manifest.json',
  JSON.stringify({ schemaVersion: 1, files: manifest }, null, 2) + '\n',
);
console.log(
  `Packaged ${manifest.length} allowlisted files in dist; no credentials, database or provisioned profiles included.`,
);
