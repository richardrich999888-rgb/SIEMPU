import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
const pkg = JSON.parse(await readFile('package.json', 'utf8'));
const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
const entries = Object.entries(lock.packages || {}).filter(([path]) => path);
const components = entries.map(([path, item]) => ({
  type: 'library',
  name: item.name || path.replace(/^node_modules\//, ''),
  version: item.version,
  properties: [{ name: 'siepmu:dependency-kind', value: item.dev ? 'development' : 'runtime' }],
  ...(item.license ? { licenses: [{ expression: item.license }] } : {}),
}));
components.push({
  type: 'application',
  name: 'Node.js',
  version: process.version.slice(1),
  purl: `pkg:generic/nodejs@${process.version.slice(1)}`,
});
const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: { type: 'application', name: pkg.name, version: pkg.version },
    properties: [
      {
        name: 'siepmu:scope',
        value:
          'Application lockfile and Node runtime only. Not a complete container/OS SBOM; CI Trivy generates the image SBOM.',
      },
    ],
  },
  components,
};
await mkdir('artifacts', { recursive: true });
await writeFile('artifacts/application.cdx.json', JSON.stringify(bom, null, 2) + '\n');
console.log(
  `Application SBOM: ${entries.length} npm lockfile dependencies (including development tools) plus Node runtime; OS and Node bundled libraries require image scanning.`,
);
