import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createTransportServer, serverTLS } from '../../packages/transport/tls.mjs';
import { CheckpointCustodian } from './custody.mjs';

/** Full-chain (version 1) checkpoint requests; a range request is far smaller. */
const CHECKPOINT_MAX_BYTES = 16 * 1024 * 1024;
/** Anchor queries are a fixed, small signed packet. */
const ANCHOR_MAX_BYTES = 4096;

/** Reads a request body, failing closed beyond `maxBytes`. */
async function readBody(req, maxBytes) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new Error('BODY_LIMIT');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks));
}
export function createCustodyServer({ custodian, tls }) {
  if (!tls?.requestCert) throw new Error('Independent custody requires mTLS');
  const server = createTransportServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    try {
      if (req.method !== 'POST' || req.headers['content-type'] !== 'application/json') {
        res.writeHead(404);
        res.end('{}');
        return;
      }
      // Exact static routing: request values never select a callable or a property name.
      switch (req.url) {
        case '/v1/checkpoints':
          res.end(
            JSON.stringify(await custodian.accept(await readBody(req, CHECKPOINT_MAX_BYTES))),
          );
          return;
        case '/v1/anchor':
          res.end(JSON.stringify(custodian.anchor(await readBody(req, ANCHOR_MAX_BYTES))));
          return;
        default:
          res.writeHead(404);
          res.end('{}');
      }
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
