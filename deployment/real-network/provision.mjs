// Synthetic fixture provisioner. Private node bundles are never evaluation evidence.
import { execFileSync } from 'node:child_process';
import {
  cpSync,
  chmodSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
  existsSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { reservePort } from '../secure/ports.mjs';
import { snapshot } from '../../assurance/sag/package.mjs';

export const placement = Object.freeze({
  A: ['unit-a'],
  B: ['web', 'control', 'unit-admin'],
  C: ['relay'],
  D: ['checkpoint', 'collector'],
  E: ['unit-b', 'unit-denied'],
  F: [],
});
const write = (p, value) =>
  writeFileSync(p, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });

export async function provision(directory, { mode = 'multi-host', root = resolve('.') } = {}) {
  if (!['multi-host', 'local-process'].includes(mode)) throw new Error('TESTBED_MODE');
  const source = snapshot(root),
    out = resolve(directory);
  if (existsSync(out)) throw new Error('NEW_PRIVATE_DIRECTORY_REQUIRED');
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const staging = join(out, 'provisioning-only');
  execFileSync(
    process.execPath,
    ['deployment/testbed/provision.mjs', staging, join(out, 'generated')],
    { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], timeout: 60000 },
  );
  const compose = JSON.parse(readFileSync(join(out, 'generated/compose.json')));
  const ports = { web: 8080, control: 8081, relay: 8082, checkpoint: 8444, collector: 8445 };
  if (mode === 'local-process')
    for (const role of Object.keys(ports)) ports[role] = await reservePort();
  const urls = Object.fromEntries(
    Object.entries(ports).map(([role, port]) => [
      role,
      `https://${mode === 'local-process' ? '127.0.0.1' : role}:${port}`,
    ]),
  );
  const originalUrls = { web: 8080, control: 8081, relay: 8082, checkpoint: 8444, collector: 8445 };
  for (const [node, roles] of Object.entries(placement)) {
    const nodeDir = join(out, node);
    mkdirSync(nodeDir, { mode: 0o700 });
    const manifests = [];
    for (const role of roles) {
      const service = compose.services[role],
        roleDir = join(nodeDir, role);
      mkdirSync(roleDir, { mode: 0o700 });
      cpSync(service.volumes[0].split(':/state')[0], join(roleDir, 'state'), { recursive: true });
      cpSync(join(staging, 'keys', role), join(roleDir, 'keys'), { recursive: true });
      chmodSync(join(roleDir, 'state'), 0o700);
      chmodSync(join(roleDir, 'keys'), 0o700);
      const env = {};
      for (const [key, value] of Object.entries(service.environment)) {
        let s = value
          .replaceAll('/state', '@NODE@/' + role + '/state')
          .replaceAll('/keys', '@NODE@/' + role + '/keys');
        for (const [name, port] of Object.entries(originalUrls))
          s = s.replaceAll(`https://${name}:${port}`, urls[name]);
        env[key] = s;
      }
      if (ports[role]) {
        const prefix = role === 'checkpoint' ? 'CUSTODY' : role.toUpperCase();
        env['SIEPMU_' + prefix + '_PORT'] = String(ports[role]);
        env['SIEPMU_' + prefix + '_HOST'] = mode === 'local-process' ? '127.0.0.1' : '0.0.0.0';
        manifests.push({ role, command: service.command.slice(1), env });
      } else {
        write(join(roleDir, 'endpoint.json'), {
          mode: 'software-sdk',
          url: urls.web,
          sourceCommit: source.commit,
          limitations: ['No PKCS11 hardware or ClamAV sandbox in software-sdk profile'],
        });
        writeFileSync(join(roleDir, 'outbox-secret'), randomBytes(32), { mode: 0o600, flag: 'wx' });
      }
    }
    write(join(nodeDir, 'node.json'), {
      schemaVersion: 1,
      node,
      mode,
      source: { commit: source.commit, tree: source.tree },
      roles: manifests,
      standby: node === 'F' ? 'QUARANTINED_NO_WRITER_CREDENTIAL' : null,
      custody: 'COMMON_PROVISIONER_NOT_INDEPENDENT_ADMINISTRATION',
    });
  }
  write(join(out, 'deployment.json'), {
    mode,
    source: { commit: source.commit, tree: source.tree },
    placement,
    urls,
    ports,
  });
  writeFileSync(
    join(out, 'hosts.example'),
    '127.0.0.1 localhost\n10.77.0.2 web control\n10.77.0.3 relay\n10.77.0.4 checkpoint collector\n',
    { mode: 0o600 },
  );
  // Discard aggregate CA/key copies after role separation. This is not a secure-erasure claim.
  rmSync(staging, { recursive: true });
  rmSync(join(out, 'generated'), { recursive: true });
  return { out, mode, source: { commit: source.commit, tree: source.tree }, urls, ports };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  console.log(
    JSON.stringify(await provision(process.argv[2], { mode: process.argv[3] ?? 'multi-host' })),
  );
