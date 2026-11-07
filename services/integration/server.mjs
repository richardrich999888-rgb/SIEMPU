import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { IntegrationEndpoint } from '../../packages/integration/client.mjs';
import { serverTLS, clientTLS } from '../../packages/transport/tls.mjs';
import { SyntheticAdapter, createAdapterServer } from './adapter.mjs';
import { startupDiagnostic } from './lifecycle.mjs';

export async function startAdapter(env = process.env) {
  let stage = 'CONFIGURE',
    adapter,
    server;
  try {
    const read = (p) => JSON.parse(readFileSync(p));
    if (statSync(env.SIEPMU_ADAPTER_PROFILE).mode & 0o077)
      throw new Error('Adapter profile permissions');
    const endpoint = new IntegrationEndpoint({
      url: env.SIEPMU_PLATFORM_URL,
      tls: clientTLS('adapter', env),
      profile: read(env.SIEPMU_ADAPTER_PROFILE),
      authorityKey: read(env.SIEPMU_AUTHORITY_PUBLIC_KEY),
    });
    stage = 'AUTHENTICATE';
    await endpoint.authenticate();
    stage = 'DATABASE';
    adapter = new SyntheticAdapter({
      database: env.SIEPMU_ADAPTER_DB,
      endpoint,
      destinations: read(env.SIEPMU_ADAPTER_DESTINATIONS),
      ...(env.SIEPMU_ADAPTER_MAX_PENDING !== undefined
        ? { maxPending: Number(env.SIEPMU_ADAPTER_MAX_PENDING) }
        : {}),
    });
    stage = 'LISTEN';
    server = createAdapterServer({ adapter, tls: serverTLS('adapter', env) });
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
    process.once('SIGTERM', () => {
      const timer = setTimeout(() => process.exit(1), 5000);
      timer.unref();
      server.close(() => {
        adapter.close();
        process.exit(0);
      });
    });
    return { server, adapter };
  } catch (error) {
    server?.close();
    adapter?.close();
    error.adapterStage = stage;
    throw error;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await startAdapter();
  } catch (error) {
    console.error(JSON.stringify(startupDiagnostic(error)));
    process.exitCode = 1;
  }
}
