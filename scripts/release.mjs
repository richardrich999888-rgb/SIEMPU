import { readFile, mkdir, readdir, writeFile, copyFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';

const pkg = JSON.parse(await readFile('package.json', 'utf8'));
const version = process.argv[2] || pkg.version;
if (!/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version) || version !== pkg.version)
  throw new Error('Release version must exactly match package.json');
const revision = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (
  execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
    encoding: 'utf8',
  }).trim()
)
  throw new Error('Release requires a clean committed source tree');
const out = resolve('artifacts/release');
await mkdir(out, { recursive: true });
// Quality workflow must supply the real image inventory before a release bundle can be made.
const image = JSON.parse(await readFile(join(out, 'image.cdx.json'), 'utf8'));
if (image.bomFormat !== 'CycloneDX')
  throw new Error('Verified quality workflow image SBOM is required');
await readFile('dist/manifest.json');
await copyFile('artifacts/application.cdx.json', join(out, 'application.cdx.json'));
execFileSync('git', [
  'archive',
  '--format=tar.gz',
  `--prefix=syntriass-siepmu-${version}/`,
  `--output=${join(out, `source-${version}.tar.gz`)}`,
  revision,
]);
execFileSync('tar', ['-czf', join(out, `runtime-${version}.tar.gz`), '-C', resolve('dist'), '.']);
await writeFile(
  join(out, 'release.json'),
  JSON.stringify(
    {
      schemaVersion: 1,
      version,
      revision,
      node: process.version,
      createdAt: new Date().toISOString(),
      status: 'synthetic-demonstrator',
      publication: 'workflow-artifact-only',
      approval: 'No operational approval or certificate claimed',
      artifacts: {
        source: 'Committed source including tests, deployment manifests and documentation',
        runtime:
          'Native JavaScript package; excludes repository-only acceptance and benchmark runners',
        inventory: 'Application and scanned image CycloneDX inventories',
        integrity: 'SHA256SUMS is an unsigned integrity inventory, not a release signature',
      },
    },
    null,
    2,
  ) + '\n',
);
async function collect(dir, prefix = '') {
  const rows = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const name = prefix + entry.name;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) rows.push(...(await collect(path, name + '/')));
    else if (entry.isFile() && name !== 'SHA256SUMS')
      rows.push(
        `${createHash('sha256')
          .update(await readFile(path))
          .digest('hex')}  ${name}`,
      );
  }
  return rows;
}
await writeFile(join(out, 'SHA256SUMS'), (await collect(out)).sort().join('\n') + '\n');
console.log(
  JSON.stringify({
    status: 'PACKAGED',
    version,
    revision,
    destination: 'artifacts/release',
    unsigned: true,
  }),
);
