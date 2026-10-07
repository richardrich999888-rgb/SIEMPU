import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
const pkg = JSON.parse(await readFile('package.json', 'utf8'));
const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
const entries = Object.entries(lock.packages || {}).filter(([path]) => path);
const nodeVersion = process.version.slice(1);
const nodeRef = `runtime:nodejs:${nodeVersion}`;
const componentName = (path, item) =>
  item.name || path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
const components = entries.map(([path, item]) => {
  const name = componentName(path, item);
  return {
    type: 'library',
    'bom-ref': `npm:${path}@${item.version}`,
    name,
    version: item.version,
    purl: `pkg:npm/${name.replace('@', '%40')}@${item.version}`,
    properties: [
      { name: 'siepmu:dependency-kind', value: item.dev ? 'development' : 'runtime' },
      {
        name: 'siepmu:inventory-source',
        value: 'package-lock.json; includes direct and transitive locked packages',
      },
      {
        name: 'siepmu:license-status',
        value: item.license
          ? 'Upstream lockfile declaration; not an independent license review'
          : 'Unknown; requires review',
      },
    ],
    ...(item.license ? { licenses: [{ expression: item.license }] } : {}),
  };
});
// ABI levels and Unicode/time-zone data are runtime metadata, not invented standalone libraries.
const metadataVersions = new Set(['modules', 'napi', 'unicode', 'cldr', 'tz']);
const names = { ares: 'c-ares', uv: 'libuv' };
const bundled = Object.entries(process.versions).filter(
  ([name, version]) => name !== 'node' && version && !metadataVersions.has(name),
);
for (const [reportedName, version] of bundled) {
  const name = names[reportedName] || reportedName;
  components.push({
    type: 'library',
    'bom-ref': `runtime:nodejs:${nodeVersion}:${reportedName}:${version}`,
    name,
    version,
    properties: [
      { name: 'siepmu:dependency-kind', value: 'Node runtime bundled or linked component' },
      {
        name: 'siepmu:inventory-source',
        value: `process.versions.${reportedName} on the executing build runtime`,
      },
      {
        name: 'siepmu:license-status',
        value:
          'Unknown; not inferred from Node licensing. Review this exact Node distribution and component notices.',
      },
      {
        name: 'siepmu:identification-status',
        value:
          'Runtime-reported name/version; packaging, patches and full transitive closure not independently resolved',
      },
    ],
    externalReferences: [
      { type: 'license', url: `https://github.com/nodejs/node/blob/v${nodeVersion}/LICENSE` },
    ],
  });
}
components.push({
  type: 'application',
  'bom-ref': nodeRef,
  name: 'Node.js',
  version: nodeVersion,
  purl: `pkg:generic/nodejs@${nodeVersion}`,
  properties: [
    {
      name: 'siepmu:license-status',
      value:
        'Distribution includes multiple upstream licenses; inspect exact distribution license notices',
    },
    ...Object.entries(process.versions)
      .filter(([name]) => metadataVersions.has(name))
      .map(([name, value]) => ({ name: `siepmu:node-metadata:${name}`, value })),
  ],
  externalReferences: [
    { type: 'license', url: `https://github.com/nodejs/node/blob/v${nodeVersion}/LICENSE` },
  ],
});
const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: {
      type: 'application',
      'bom-ref': 'application:siepmu',
      name: pkg.name,
      version: pkg.version,
    },
    properties: [
      {
        name: 'siepmu:scope',
        value:
          'Direct/transitive npm lockfile inventory (including development tools), executing Node version and nonempty component versions reported by process.versions, including OpenSSL and SQLite. Runtime metadata versions are not standalone libraries. Node component licenses remain unreviewed. Not a complete container/OS or vendored-component dependency closure; CI image inventory and exact distribution/license review are required.',
      },
    ],
  },
  components,
  dependencies: [
    {
      ref: 'application:siepmu',
      dependsOn: [
        nodeRef,
        ...entries
          .filter(([, item]) => !item.dev)
          .map(([path, item]) => `npm:${path}@${item.version}`),
      ],
    },
    {
      ref: nodeRef,
      dependsOn: bundled.map(
        ([name, version]) => `runtime:nodejs:${nodeVersion}:${name}:${version}`,
      ),
    },
  ],
};
await mkdir('artifacts', { recursive: true });
await writeFile('artifacts/application.cdx.json', JSON.stringify(bom, null, 2) + '\n');
console.log(
  `Application SBOM: ${entries.length} direct/transitive npm lockfile packages; Node ${nodeVersion}; ${bundled.length} runtime-reported components including OpenSSL ${process.versions.openssl} and SQLite ${process.versions.sqlite}. Bundled-component license review and full OS inventory remain separate.`,
);
