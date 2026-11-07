// Laboratory helper: runs services/integration/server.mjs as a separate process on a running
// secure stack (deployment/secure/harness.mjs), with its own mTLS server identity, a pinned
// source-system client identity, and a managed SIEPMU endpoint profile. Synthetic data only.

import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startupDiagnostic, isAdapterReady } from '../../services/integration/lifecycle.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import { reservePort } from './ports.mjs';

/** Bounded readiness deadline including each network probe. */
const READY_TIMEOUT_MS = 15000;
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
    SIEPMU_ENABLE_LEGACY_PLAINTEXT_ADAPTER: '1',
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
    cwd: resolve(fileURLToPath(new URL('../..', import.meta.url))),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '',
    spawnError = false;
  child.on('error', () => {
    spawnError = true;
  });
  const capture = (b) => {
    logs = (logs + b.toString()).slice(-32768);
  };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);
  const ended = () => child.exitCode !== null || child.signalCode !== null || spawnError;
  const stop = async () => {
    if (ended()) return;
    const exited = new Promise((r) => child.once('exit', r));
    const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
    child.kill('SIGTERM');
    try {
      await exited;
    } finally {
      clearTimeout(timer);
    }
  };
  const failure = (code) => {
    let diagnostic = startupDiagnostic(null);
    for (const line of logs.split('\n')) {
      try {
        const record = JSON.parse(line);
        if (record.event === 'ADAPTER_STARTUP_FAILED')
          diagnostic = startupDiagnostic({ ...record, adapterStage: record.stage });
      } catch {}
    }
    return Object.assign(new Error(code), { diagnostic });
  };
  const url = `https://127.0.0.1:${port}`;
  const sourceTls = stack.pki.material(sourceIdentity);
  const deadline = Date.now() + READY_TIMEOUT_MS;
  try {
    while (Date.now() < deadline) {
      if (ended()) throw failure('ADAPTER_EXITED');
      try {
        const response = await requestBytes(url + '/ready', {
          tls: sourceTls,
          timeoutMs: Math.min(1000, Math.max(1, deadline - Date.now())),
          maxBytes: 4096,
        });
        if (isAdapterReady(response)) return { url, sourceTls, logs: () => logs, stop };
      } catch {}
      await new Promise((r) => setTimeout(r, READY_INTERVAL_MS));
    }
    throw failure('ADAPTER_NOT_READY');
  } catch (error) {
    await stop();
    throw error;
  }
}
