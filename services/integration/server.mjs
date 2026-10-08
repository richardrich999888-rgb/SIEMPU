import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { IntegrationEndpoint } from '../../packages/integration/client.mjs';
import { serverTLS, clientTLS } from '../../packages/transport/tls.mjs';
import { SyntheticAdapter, createAdapterServer } from './adapter.mjs';
export async function startAdapter(env = process.env) {
  const read = (p) => JSON.parse(readFileSync(p));
  if (statSync(env.SIEPMU_ADAPTER_PROFILE).mode & 0o077)
    throw new Error('Adapter profile permissions');
  const endpoint = new IntegrationEndpoint({
    url: env.SIEPMU_PLATFORM_URL,
    tls: clientTLS('adapter', env),
    profile: read(env.SIEPMU_ADAPTER_PROFILE),
    authorityKey: read(env.SIEPMU_AUTHORITY_PUBLIC_KEY),
  });
  await endpoint.authenticate();
  const adapter = new SyntheticAdapter({
    database: env.SIEPMU_ADAPTER_DB,
    endpoint,
    destinations: read(env.SIEPMU_ADAPTER_DESTINATIONS),
  });
  const server = createAdapterServer({ adapter, tls: serverTLS('adapter', env) });
  server.listen(Number(env.SIEPMU_ADAPTER_PORT ?? 8446), env.SIEPMU_ADAPTER_HOST ?? '127.0.0.1');
  process.on('SIGTERM', () =>
    server.close(() => {
      adapter.close();
      process.exit(0);
    }),
  );
  return { server, adapter };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  await startAdapter();
