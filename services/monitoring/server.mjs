import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { serverTLS } from '../../packages/transport/tls.mjs';
import { SecurityCollector, createCollectorServer } from './collector.mjs';
export function startCollector(env = process.env) {
  const read = (p) => JSON.parse(readFileSync(p));
  if (statSync(env.SIEPMU_COLLECTOR_SIGNING_KEY).mode & 0o077)
    throw new Error('Signing key permissions');
  const collector = new SecurityCollector({
    database: env.SIEPMU_COLLECTOR_DB,
    sourceKey: read(env.SIEPMU_AUTHORITY_PUBLIC_KEY),
    signingKey: read(env.SIEPMU_COLLECTOR_SIGNING_KEY),
    retentionMs: Number(env.SIEPMU_COLLECTOR_RETENTION_MS ?? 7 * 86400000),
  });
  const server = createCollectorServer({
    collector,
    tls: serverTLS('collector', env),
    sourcePin: env.SIEPMU_COLLECTOR_SOURCE_PIN,
    operatorPin: env.SIEPMU_COLLECTOR_OPERATOR_PIN,
  });
  server.listen(
    Number(env.SIEPMU_COLLECTOR_PORT ?? 8445),
    env.SIEPMU_COLLECTOR_HOST ?? '127.0.0.1',
  );
  process.on('SIGTERM', () =>
    server.close(() => {
      collector.close();
      process.exit(0);
    }),
  );
  return { server, collector };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  startCollector();
