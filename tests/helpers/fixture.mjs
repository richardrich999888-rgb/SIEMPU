import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { ApiClient, coreTransport, httpTransport } from './client.mjs';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const relayStores = new Map();
export async function provision() {
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-test-'));
  const { initDemo } = await import('../../scripts/bootstrap.mjs');
  const provisioned = await initDemo(dir);
  const profiles = Object.fromEntries(
    provisioned.profiles.map((profile) => [profile.username, profile]),
  );
  return { dir, provisioned, profiles };
}
export async function openAuthority(dir, hooks = {}) {
  const { Authority } = await import('../../services/control/core.mjs');
  const signingKey = JSON.parse(await readFile(join(dir, 'server-key.json'), 'utf8'));
  const masterKey = await readFile(join(dir, 'master.key'));
  if (!relayStores.has(dir)) relayStores.set(dir, new Map());
  const blobs = relayStores.get(dir);
  const relay = {
    putBlob: async (hash, bytes) => {
      blobs.set(hash, Buffer.from(bytes));
    },
    getBlob: async (hash) => {
      const bytes = blobs.get(hash);
      if (!bytes) throw new Error('Test relay blob unavailable');
      return Buffer.from(bytes);
    },
  };
  return new Authority({
    dbPath: join(dir, 'control.sqlite'),
    signingKey,
    masterKey,
    hooks,
    relay,
  });
}
export async function coreFixture(t, hooks = {}) {
  const fixture = await provision();
  const authority = await openAuthority(fixture.dir, hooks);
  const transport = coreTransport(authority);
  const clients = Object.fromEntries(
    Object.entries(fixture.profiles).map(([name, profile]) => [
      name,
      new ApiClient(transport, profile),
    ]),
  );
  t?.after(async () => {
    authority.close();
    relayStores.delete(fixture.dir);
    await rm(fixture.dir, { recursive: true, force: true });
  });
  return { ...fixture, authority, transport, clients };
}
async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
export async function startStack(dir) {
  const [web, control, relay] = await Promise.all([freePort(), freePort(), freePort()]);
  const env = {
    ...process.env,
    SIEPMU_DATA_DIR: dir,
    SIEPMU_WEB_PORT: String(web),
    SIEPMU_CONTROL_PORT: String(control),
    SIEPMU_RELAY_PORT: String(relay),
    SIEPMU_CONTROL_URL: `http://127.0.0.1:${control}`,
    SIEPMU_RELAY_URL: `http://127.0.0.1:${relay}`,
  };
  const child = spawn(process.execPath, ['scripts/start.mjs'], {
    cwd: root,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (data) => {
    output += data;
  });
  child.stderr.on('data', (data) => {
    output += data;
  });
  const baseUrl = `http://127.0.0.1:${web}`;
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error('Stack exited: ' + output);
    try {
      const response = await fetch(baseUrl + '/api/meta', { signal: AbortSignal.timeout(300) });
      if (response.ok) break;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  try {
    const response = await fetch(baseUrl + '/api/meta', { signal: AbortSignal.timeout(1000) });
    if (!response.ok) throw new Error('Not ready');
  } catch (error) {
    child.kill('SIGTERM');
    throw new Error('Stack readiness failed: ' + output, { cause: error });
  }
  const stop = async () => {
    if (child.exitCode !== null) return;
    child.kill('SIGTERM');
    let timer;
    try {
      await Promise.race([
        new Promise((resolve) => child.once('exit', resolve)),
        new Promise((resolve) => {
          timer = setTimeout(() => {
            child.kill('SIGKILL');
            resolve();
          }, 5500);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  return { child, baseUrl, ports: { web, control, relay }, stop, logs: () => output };
}
export async function httpFixture(t) {
  const fixture = await provision(),
    stack = await startStack(fixture.dir);
  const transport = httpTransport(stack.baseUrl);
  const clients = Object.fromEntries(
    Object.entries(fixture.profiles).map(([name, profile]) => [
      name,
      new ApiClient(transport, profile),
    ]),
  );
  t?.after(async () => {
    await stack.stop();
    await rm(fixture.dir, { recursive: true, force: true });
  });
  return { ...fixture, ...stack, clients, transport };
}
