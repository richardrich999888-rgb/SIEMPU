import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createTransportServer, serverTLS } from '../../packages/transport/tls.mjs';
import { CheckpointCustodian } from './custody.mjs';

export function createCustodyServer({ custodian, tls }) {
  if (!tls?.requestCert) throw new Error('Independent custody requires mTLS');
  const server = createTransportServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    try {
      if (
        req.method !== 'POST' ||
        req.url !== '/v1/checkpoints' ||
        req.headers['content-type'] !== 'application/json'
      ) {
        res.writeHead(404);
        res.end('{}');
        return;
      }
      let size = 0;
      const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 16 * 1024 * 1024) throw new Error('BODY_LIMIT');
        chunks.push(chunk);
      }
      const receipt = await custodian.accept(JSON.parse(Buffer.concat(chunks)));
      res.end(JSON.stringify(receipt));
    } catch {
      res.writeHead(409);
      res.end(JSON.stringify({ code: 'CHECKPOINT_REJECTED' }));
    }
  }, tls);
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const read = (path) => JSON.parse(readFileSync(path));
  const custodian = new CheckpointCustodian({
    database: process.env.SIEPMU_CUSTODY_DB,
    authorityKey: read(process.env.SIEPMU_AUTHORITY_PUBLIC_KEY),
    signingKey: read(process.env.SIEPMU_CUSTODY_SIGNING_KEY),
  });
  const server = createCustodyServer({ custodian, tls: serverTLS('checkpoint') });
  server.listen(
    Number(process.env.SIEPMU_CUSTODY_PORT ?? 8444),
    process.env.SIEPMU_CUSTODY_HOST ?? '127.0.0.1',
  );
  process.on('SIGTERM', () =>
    server.close(() => {
      custodian.close();
      process.exit(0);
    }),
  );
}
