// Synthetic process harness. Only public endpoint pins and data-plane relay credentials
// enter the adapter's configuration. Host/kernel independence is a separate test axis.
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { publicJwk } from '../../services/control/primitives.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import { reservePort } from './ports.mjs';

export async function startLabSealedAdapter({ stack, dir, source, destinations }) {
  const port = await reservePort();
  const sourcePath = join(dir, 'source-public.json'),
    destinationPath = join(dir, 'destinations-public.json');
  writeFileSync(
    sourcePath,
    JSON.stringify({
      userId: source.userId,
      deviceId: source.deviceId,
      signingPublicKey: publicJwk(source.keys.signing.publicKey),
    }),
    { mode: 0o600 },
  );
  writeFileSync(destinationPath, JSON.stringify(destinations.map((d) => d.userId)), {
    mode: 0o600,
  });
  const env = {
    PATH: process.env.PATH,
    SIEPMU_PROFILE: 'isolated',
    SIEPMU_ADAPTER_PORT: String(port),
    SIEPMU_ADAPTER_DB: join(dir, 'sealed-adapter.sqlite'),
    SIEPMU_SEALED_SOURCE: sourcePath,
    SIEPMU_SEALED_DESTINATIONS: destinationPath,
    SIEPMU_TLS_CA: join(stack.pki.dir, 'ca.crt'),
    SIEPMU_ADAPTER_TLS_CERT: join(stack.pki.dir, 'adapter.crt'),
    SIEPMU_ADAPTER_TLS_KEY: join(stack.pki.dir, 'adapter.key'),
    SIEPMU_ADAPTER_TLS_CLIENT_PINS: stack.pki.pin('adapter-client'),
    SIEPMU_RELAY_URL: stack.env.SIEPMU_RELAY_URL,
    SIEPMU_RELAY_SECRET_FILE: join(stack.env.SIEPMU_DATA_DIR, 'relay.secret'),
    SIEPMU_SEALED_CLIENT_TLS_CERT: join(stack.pki.dir, 'sealed-relay-client.crt'),
    SIEPMU_SEALED_CLIENT_TLS_KEY: join(stack.pki.dir, 'sealed-relay-client.key'),
  };
  const child = spawn(
    process.execPath,
    [new URL('../../services/integration/sealed-server.mjs', import.meta.url).pathname],
    { env, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let logs = '',
    failed = false;
  child.on('error', () => {
    failed = true;
  });
  for (const stream of [child.stdout, child.stderr])
    stream.on('data', (b) => {
      logs = (logs + b).slice(-32768);
    });
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null || failed) return;
    const closed = new Promise((r) => child.once('close', r));
    const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
    child.kill('SIGTERM');
    try {
      await closed;
    } finally {
      clearTimeout(timer);
    }
  };
  const url = `https://127.0.0.1:${port}`,
    sourceTls = stack.pki.material('adapter-client');
  const deadline = Date.now() + 15000;
  try {
    while (Date.now() < deadline) {
      if (failed || child.exitCode !== null || child.signalCode !== null)
        throw new Error('SEALED_ADAPTER_EXITED');
      try {
        const r = await requestBytes(url + '/ready', {
          tls: sourceTls,
          timeoutMs: Math.min(1000, Math.max(1, deadline - Date.now())),
          maxBytes: 4096,
        });
        const p = JSON.parse(r.body);
        if (
          r.status === 200 &&
          p.service === 'sealed-ciphertext-adapter' &&
          p.ready === true &&
          p.checks?.relay === true &&
          p.checks.database === true &&
          p.checks.capacity === true
        )
          return { url, sourceTls, stop, logs: () => logs, env };
      } catch {}
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error('SEALED_ADAPTER_NOT_READY');
  } catch (error) {
    await stop();
    throw error;
  }
}
