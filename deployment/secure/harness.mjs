import { Authority } from '../../services/control/core.mjs';
import {
  CheckpointCustodian,
  authoritySnapshot,
  authorizationDigest,
} from '../../services/evidence/custody.mjs';
import { packet } from '../../services/control/primitives.mjs';
import { spawn } from 'node:child_process';
import { reservePort } from './ports.mjs';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { generateLabPKI } from './lab-pki.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';

export async function seedLabCustodian(authorityDir, custodyDir) {
  const authorityKey = JSON.parse(readFileSync(join(authorityDir, 'public-key.json')));
  const authority = new Authority({
    dbPath: join(authorityDir, 'control.sqlite'),
    signingKey: JSON.parse(readFileSync(join(authorityDir, 'server-key.json'))),
    masterKey: readFileSync(join(authorityDir, 'master.key')),
  });
  const custody = new CheckpointCustodian({
    database: join(custodyDir, 'checkpoints.sqlite'),
    authorityKey,
    signingKey: JSON.parse(readFileSync(join(custodyDir, 'signing-key.json'))),
    allowBootstrap: true,
  });
  try {
    await custody.accept(
      packet(authority.key, {
        version: 1,
        nonce: crypto.randomUUID(),
        issuedAt: Date.now(),
        stateDigest: authorizationDigest(authority),
        evidence: authoritySnapshot(authority),
      }),
    );
  } finally {
    authority.close();
    custody.close();
  }
}
// Child processes receive ports reserved outside the ephemeral range (see ports.mjs).
export const freePort = reservePort;
export function prepareSecureLab(dir) {
  const pki = generateLabPKI(join(dir, 'pki'));
  for (const name of [
    'web',
    'control',
    'relay',
    'checkpoint',
    'collector',
    'adapter',
    'web-client',
    'control-client',
    'observer-client',
    'operator-client',
    'adapter-client',
    'unit-a',
    'unit-b',
    'unit-denied',
  ])
    pki.issue(name);
  const independent = join(dir, 'custody');
  mkdirSync(independent, { mode: 0o700 });
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  writeFileSync(
    join(independent, 'signing-key.json'),
    JSON.stringify(keys.privateKey.export({ format: 'jwk' })),
    { mode: 0o600, flag: 'wx' },
  );
  writeFileSync(
    join(independent, 'public-key.json'),
    JSON.stringify(keys.publicKey.export({ format: 'jwk' })),
    { mode: 0o600, flag: 'wx' },
  );
  const monitor = join(dir, 'monitor');
  mkdirSync(monitor, { mode: 0o700 });
  const monitorKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  for (const [name, key] of [
    ['signing-key', monitorKeys.privateKey],
    ['public-key', monitorKeys.publicKey],
  ])
    writeFileSync(join(monitor, name + '.json'), JSON.stringify(key.export({ format: 'jwk' })), {
      mode: 0o600,
      flag: 'wx',
    });
  return { pki, independent };
}
export function labEnvironment(
  dir,
  pki,
  ports,
  hosts = { web: '127.0.0.1', control: '127.0.0.1', relay: '127.0.0.1', checkpoint: '127.0.0.1' },
) {
  const env = {
    SIEPMU_PROFILE: 'isolated',
    SIEPMU_DATA_DIR: dir,
    SIEPMU_TLS_CA: join(pki.dir, 'ca.crt'),
    SIEPMU_PUBLIC_ORIGIN: `https://${hosts.web}:${ports.web}`,
    SIEPMU_CONTROL_URL: `https://${hosts.control}:${ports.control}`,
    SIEPMU_RELAY_URL: `https://${hosts.relay}:${ports.relay}`,
    SIEPMU_CUSTODY_URL: `https://${hosts.checkpoint}:${ports.checkpoint}/v1/checkpoints`,
    SIEPMU_CUSTODIAN_PUBLIC_KEY: join(dir, 'custody', 'public-key.json'),
    SIEPMU_AUTHORITY_PUBLIC_KEY: join(dir, 'public-key.json'),
    SIEPMU_CUSTODY_SIGNING_KEY: join(dir, 'custody', 'signing-key.json'),
    SIEPMU_CUSTODY_DB: join(dir, 'custody', 'checkpoints.sqlite'),
    SIEPMU_CUSTODY_PORT: String(ports.checkpoint),
  };
  for (const role of ['web', 'control', 'relay', 'checkpoint']) {
    const prefix = 'SIEPMU_' + role.toUpperCase();
    env[prefix + '_PORT'] = String(ports[role]);
    env[prefix + '_TLS_CERT'] = join(pki.dir, role + '.crt');
    env[prefix + '_TLS_KEY'] = join(pki.dir, role + '.key');
    if (role !== 'web')
      env[prefix + '_TLS_CLIENT_PINS'] = pki.pin(
        role === 'control' ? 'web-client' : 'control-client',
      );
  }
  for (const role of ['web', 'control']) {
    const prefix = 'SIEPMU_' + role.toUpperCase() + '_CLIENT_TLS_';
    env[prefix + 'CERT'] = join(pki.dir, role + '-client.crt');
    env[prefix + 'KEY'] = join(pki.dir, role + '-client.key');
  }
  if (ports.collector)
    Object.assign(env, {
      SIEPMU_COLLECTOR_PORT: String(ports.collector),
      SIEPMU_COLLECTOR_DB: join(dir, 'monitor', 'collector.sqlite'),
      SIEPMU_COLLECTOR_SIGNING_KEY: join(dir, 'monitor', 'signing-key.json'),
      SIEPMU_COLLECTOR_PUBLIC_KEY: join(dir, 'monitor', 'public-key.json'),
      SIEPMU_COLLECTOR_SOURCE_PIN: pki.pin('control-client'),
      SIEPMU_COLLECTOR_OPERATOR_PIN: pki.pin('operator-client'),
      SIEPMU_COLLECTOR_TLS_CERT: join(pki.dir, 'collector.crt'),
      SIEPMU_COLLECTOR_TLS_KEY: join(pki.dir, 'collector.key'),
      SIEPMU_COLLECTOR_TLS_CLIENT_PINS:
        pki.pin('control-client') + ',' + pki.pin('operator-client'),
      SIEPMU_COLLECTOR_URL: `https://${hosts.collector ?? '127.0.0.1'}:${ports.collector}/v1/events`,
    });
  return env;
}
export async function startSecureStack(
  dir,
  { root = resolve('.'), lab = prepareSecureLab(dir) } = {},
) {
  await seedLabCustodian(dir, lab.independent);
  const ports = {};
  for (const n of ['web', 'control', 'relay', 'checkpoint', 'collector'])
    ports[n] = await reservePort();
  const env = { ...process.env, ...labEnvironment(dir, lab.pki, ports) };
  delete env.SIEPMU_ALLOW_REMOTE_HTTP;
  const children = new Map(),
    logs = [];
  const files = {
    collector: 'services/monitoring/server.mjs',
    checkpoint: 'services/evidence/server.mjs',
    relay: 'services/relay/server.mjs',
    control: 'services/control/server.mjs',
    web: 'services/web/server.mjs',
  };
  const start = (role) => {
    const child = spawn(process.execPath, [files[role]], {
      cwd: root,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.set(role, child);
    child.stdout.on('data', (b) => logs.push(String(b)));
    child.stderr.on('data', (b) => logs.push(String(b)));
    return child;
  };
  const stopRole = async (role) => {
    const child = children.get(role);
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const done = new Promise((r) => child.once('exit', r));
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    await done;
    clearTimeout(timer);
  };
  const stop = async () => {
    for (const role of ['web', 'control', 'relay', 'checkpoint', 'collector']) await stopRole(role);
  };
  const baseUrl = env.SIEPMU_PUBLIC_ORIGIN,
    tls = { ca: readFileSync(join(lab.pki.dir, 'ca.crt')) };
  try {
    for (const role of Object.keys(files)) start(role);
    let ready = false;
    for (let i = 0; i < 120; i++) {
      if ([...children.values()].some((c) => c.exitCode !== null))
        throw new Error('Secure service exited: ' + logs.join(''));
      try {
        if (
          (await requestBytes(baseUrl + '/health/ready', { tls, timeoutMs: 500 })).status === 200
        ) {
          ready = true;
          break;
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 50));
    }
    if (!ready) throw new Error('Secure lab readiness failed: ' + logs.join(''));
  } catch (error) {
    await stop();
    throw error;
  }
  return {
    ...lab,
    ports,
    env,
    baseUrl,
    tls,
    children,
    stop,
    stopRole,
    start,
    logs: () => logs.join(''),
  };
}
export function secureApiTransport(baseUrl, tls, timeoutMs = 10000) {
  return async (method, path, body, token) => {
    const result = await requestBytes(baseUrl + path, {
      method,
      tls,
      timeoutMs,
      headers: {
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(token ? { authorization: 'Bearer ' + token } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: result.status, body: JSON.parse(result.body), headers: result.headers };
  };
}
