// Laboratory helper: runs services/integration/server.mjs as a separate process on a running
// secure stack (deployment/secure/harness.mjs), with its own mTLS server identity, a pinned
// source-system client identity, and a managed SIEPMU endpoint profile. Synthetic data only.

import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { requestBytes } from '../../packages/transport/tls.mjs';
import { reservePort } from './ports.mjs';

/** Bounded wait for the adapter to accept TLS connections (100 x 50 ms). */
const READY_ATTEMPTS = 100;
const READY_INTERVAL_MS = 50;

/**
 * @param {{stack: any, dir: string, profile: object, destinations: object[],
 *   sourceIdentity?: string}} options sourceIdentity: lab PKI name pinned as the source system
 * @returns {Promise<{url: string, sourceTls: object, logs: () => string, stop: () => Promise<void>}>}
 */
export async function startLabAdapter({
  stack,
  dir,
  profile,
  destinations,
  sourceIdentity = 'adapter-client',
}) {
  const port = await reservePort();
  const profilePath = join(dir, 'adapter-profile.json');
  const destinationsPath = join(dir, 'adapter-destinations.json');
  // Same restrictive mode the adapter enforces on start.
  writeFileSync(profilePath, JSON.stringify(profile), { mode: 0o600 });
  writeFileSync(destinationsPath, JSON.stringify(destinations), { mode: 0o600 });
  const env = {
    ...stack.env,
    SIEPMU_ADAPTER_PORT: String(port),
    SIEPMU_ADAPTER_PROFILE: profilePath,
    SIEPMU_ADAPTER_DESTINATIONS: destinationsPath,
    SIEPMU_ADAPTER_DB: join(dir, 'adapter.sqlite'),
    SIEPMU_PLATFORM_URL: stack.baseUrl,
    SIEPMU_ADAPTER_TLS_CERT: join(stack.pki.dir, 'adapter.crt'),
    SIEPMU_ADAPTER_TLS_KEY: join(stack.pki.dir, 'adapter.key'),
    SIEPMU_ADAPTER_TLS_CLIENT_PINS: stack.pki.pin(sourceIdentity),
    SIEPMU_ADAPTER_CLIENT_TLS_CERT: join(stack.pki.dir, 'unit-a.crt'),
    SIEPMU_ADAPTER_CLIENT_TLS_KEY: join(stack.pki.dir, 'unit-a.key'),
  };
  const child = spawn(process.execPath, ['services/integration/server.mjs'], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (b) => (logs += b));
  child.stderr.on('data', (b) => (logs += b));
  const url = `https://127.0.0.1:${port}`;
  const sourceTls = stack.pki.material(sourceIdentity);
  let ready = false;
  for (let i = 0; i < READY_ATTEMPTS && !ready; i++) {
    if (child.exitCode !== null) throw new Error('ADAPTER_EXITED');
    try {
      await requestBytes(url + '/v1/messages', { tls: sourceTls });
      ready = true;
    } catch {
      await new Promise((r) => setTimeout(r, READY_INTERVAL_MS));
    }
  }
  if (!ready) {
    child.kill('SIGKILL');
    throw new Error('ADAPTER_NOT_READY');
  }
  return {
    url,
    sourceTls,
    logs: () => logs,
    async stop() {
      if (child.exitCode !== null) return;
      const exited = new Promise((r) => child.once('exit', r));
      child.kill('SIGTERM');
      await exited;
    },
  };
}
