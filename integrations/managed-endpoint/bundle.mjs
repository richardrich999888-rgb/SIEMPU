import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyCompanion } from './verify.mjs';

export const sourceFiles = Object.freeze([
  'integrations/managed-endpoint/index.mjs',
  'integrations/managed-endpoint/outbox.mjs',
  'packages/storage/private-sqlite.mjs',
  'integrations/pkcs11/provider.mjs',
  'integrations/pkcs11/worker.py',
  'integrations/pkcs11/requirements.txt',
  'integrations/pkcs11/README.md',
  'integrations/pkcs11/notices/SoftHSM-LICENSE.txt',
  'integrations/pkcs11/notices/python-pkcs11-LICENSE.txt',
  'integrations/pkcs11/notices/asn1crypto-LICENSE.txt',
  'integrations/endpoint-inspection/README.md',
  'integrations/endpoint-inspection/prepare-runtime.py',
  'integrations/endpoint-inspection/siepmu-bwrap.apparmor',
  'packages/file-inspection/clamav.mjs',
  'packages/file-inspection/sandbox.mjs',
  'packages/integration/client.mjs',
  'packages/transport/tls.mjs',
  'packages/crypto/crypto.mjs',
  'packages/protocol/canonical.mjs',
  'services/control/primitives.mjs',
  'apps/unit-client/challenge.mjs',
]);

/** Package only reviewed source; never auto-install binaries or change host policy. */
export function buildCompanion(root, destination) {
  root = resolve(root);
  destination = resolve(root, destination);
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  if (git('status', '--porcelain', '--untracked-files=all'))
    throw new Error('CLEAN_COMMITTED_TREE_REQUIRED');
  const rel = relative(root, destination);
  if (!/^artifacts\/[a-zA-Z0-9_-]+$/.test(rel) || existsSync(destination))
    throw new Error('NEW_ARTIFACT_DESTINATION_REQUIRED');
  if (
    existsSync(join(root, 'artifacts')) &&
    (!lstatSync(join(root, 'artifacts')).isDirectory() ||
      lstatSync(join(root, 'artifacts')).isSymbolicLink())
  )
    throw new Error('UNSAFE_OUTPUT_DIRECTORY');
  const mapping = [
    ...sourceFiles.map((p) => [p, 'lib/' + p]),
    ...['package.json', 'README.md', 'verify.mjs', 'self-test.mjs'].map((p) => [
      'integrations/managed-endpoint/' + p,
      p,
    ]),
    ['LICENSE', 'LICENSE'],
  ];
  const payload = new Map();
  for (const [source, target] of mapping) {
    const stat = lstatSync(join(root, source));
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('UNSAFE_SOURCE');
    const committed = execFileSync('git', ['show', 'HEAD:' + source], {
      cwd: root,
      maxBuffer: 4 * 1024 * 1024,
    });
    if (!committed.equals(readFileSync(join(root, source))))
      throw new Error('SOURCE_DIFFERS_FROM_COMMIT');
    payload.set(target, committed);
  }
  payload.set(
    'index.mjs',
    Buffer.from(
      "export { openManagedEndpoint, validateConfiguration } from './lib/integrations/managed-endpoint/index.mjs';\n",
    ),
  );
  const sha = (data) => createHash('sha256').update(data).digest('hex');
  const files = [...payload]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([path, data]) => ({ path, bytes: data.length, sha256: sha(data) }));
  const manifest = Buffer.from(
    JSON.stringify(
      {
        schemaVersion: 1,
        component: 'airon-managed-endpoint',
        gitCommit: git('rev-parse', 'HEAD'),
        gitTree: git('rev-parse', 'HEAD^{tree}'),
        sagGrading: 'NOT_ESTABLISHED',
        files,
      },
      null,
      2,
    ) + '\n',
  );
  mkdirSync(destination, { recursive: true, mode: 0o700 });
  for (const [path, data] of payload) {
    mkdirSync(dirname(join(destination, path)), { recursive: true, mode: 0o700 });
    writeFileSync(join(destination, path), data, { flag: 'wx', mode: 0o600 });
  }
  writeFileSync(join(destination, 'manifest.json'), manifest, { flag: 'wx', mode: 0o600 });
  const manifestSha256 = sha(manifest);
  return { package: destination, manifestSha256, ...verifyCompanion(destination, manifestSha256) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = fileURLToPath(new URL('../..', import.meta.url));
  console.log(
    JSON.stringify(
      buildCompanion(root, process.argv[2] ?? 'artifacts/managed-endpoint-pack'),
      null,
      2,
    ),
  );
}
