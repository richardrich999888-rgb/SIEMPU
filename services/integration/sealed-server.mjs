import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { serverTLS, clientTLS } from '../../packages/transport/tls.mjs';
import { createRelayClient } from '../relay/client.mjs';
import { SealedAdapter, createSealedAdapterServer } from './sealed-adapter.mjs';

export async function startSealedAdapter(env = process.env) {
  // Reject accidental reuse of the old managed-endpoint deployment configuration.
  if (env.SIEPMU_ADAPTER_PROFILE || env.SIEPMU_PLATFORM_URL)
    throw new Error('SEALED_ADAPTER_CONFIG');
  if (!env.SIEPMU_RELAY_URL?.startsWith('https:')) throw new Error('SEALED_ADAPTER_TLS');
  let adapter, server;
  try {
    adapter = new SealedAdapter({
      database: env.SIEPMU_ADAPTER_DB,
      source: JSON.parse(readFileSync(env.SIEPMU_SEALED_SOURCE)),
      destinations: JSON.parse(readFileSync(env.SIEPMU_SEALED_DESTINATIONS)),
      relay: createRelayClient({
        baseUrl: env.SIEPMU_RELAY_URL,
        secretFile: env.SIEPMU_RELAY_SECRET_FILE,
        tls: clientTLS('sealed', env),
      }),
    });
    server = createSealedAdapterServer({ adapter, tls: serverTLS('adapter', env) });
    await new Promise((resolveListening, reject) => {
      server.once('error', reject);
      server.listen(
        Number(env.SIEPMU_ADAPTER_PORT ?? 8446),
        env.SIEPMU_ADAPTER_HOST ?? '127.0.0.1',
        () => {
          server.removeListener('error', reject);
          resolveListening();
        },
      );
    });
    return { server, adapter };
  } catch (error) {
    server?.close();
    adapter?.close();
    throw error;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { server, adapter } = await startSealedAdapter();
    process.once('SIGTERM', () => {
      const deadline = setTimeout(() => process.exit(1), 5000);
      deadline.unref();
      server.close(() => {
        adapter.close();
        process.exit(0);
      });
    });
  } catch {
    console.error('{"event":"SEALED_ADAPTER_STARTUP_FAILED"}');
    process.exitCode = 1;
  }
}
