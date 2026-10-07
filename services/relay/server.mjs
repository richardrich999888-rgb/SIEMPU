import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readRelaySecret, sha256, validateRelayAuthentication } from './auth.mjs';

export function createRelayServer({
  database,
  secret,
  maxBytes = 4 * 1024 * 1024,
  maxStorageBytes = 1024 * 1024 * 1024,
  now = Date.now,
} = {}) {
  mkdirSync(dirname(database), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(database);
  chmodSync(database, 0o600);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS blobs(hash TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS workload_nonces(nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS workload_nonce_expiry ON workload_nonces(expires_at);`);
  let closed = false;
  function json(res, status, value) {
    res.writeHead(status, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    });
    res.end(JSON.stringify(value));
  }
  function healthRoute(_req, res) {
    db.prepare('SELECT 1').get();
    json(res, 200, { status: 'ok', service: 'blind-ciphertext-relay' });
  }
  const publicRoutes = new Map([
    ['GET /health', healthRoute],
    ['GET /health/live', healthRoute],
    ['GET /health/ready', healthRoute],
  ]);
  // Authentication is an unconditional workload boundary. Route, Origin and
  // content checks below cannot select an unauthenticated blob handler.
  async function workloadRoute(req, res) {
    if (Number(req.headers['content-length'] || 0) > maxBytes) {
      json(res, 413, { error: 'BODY_LIMIT' });
      req.resume();
      return;
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > maxBytes) {
        json(res, 413, { error: 'BODY_LIMIT' });
        return;
      }
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);
    const auth = validateRelayAuthentication(secret, req.method, req.url, body, req.headers, now());
    if (!auth) {
      json(res, 401, { error: 'WORKLOAD_AUTHENTICATION' });
      return;
    }
    const match = /^\/blobs\/([a-f0-9]{64})$/.exec(req.url || '');
    if (!match || !['GET', 'PUT'].includes(req.method)) {
      json(res, 404, { error: 'NOT_FOUND' });
      return;
    }
    if (req.headers.origin) {
      json(res, 403, { error: 'WORKLOAD_ONLY' });
      return;
    }
    if (req.method === 'PUT' && req.headers['content-type'] !== 'application/octet-stream') {
      json(res, 415, { error: 'CONTENT_TYPE' });
      return;
    }
    if (req.method === 'GET' && body.length) {
      json(res, 400, { error: 'UNEXPECTED_BODY' });
      return;
    }
    if (req.method === 'PUT' && (body.length < 16 || sha256(body) !== match[1])) {
      json(res, 400, { error: 'CIPHERTEXT_DIGEST' });
      return;
    }
    db.exec('BEGIN IMMEDIATE');
    let blob;
    try {
      db.prepare('DELETE FROM workload_nonces WHERE expires_at < ?').run(now());
      if (db.prepare('SELECT 1 FROM workload_nonces WHERE nonce=?').get(auth.nonce)) {
        db.exec('ROLLBACK');
        json(res, 409, { error: 'WORKLOAD_REPLAY' });
        return;
      }
      db.prepare('INSERT INTO workload_nonces(nonce, expires_at) VALUES (?,?)').run(
        auth.nonce,
        auth.expiresAt,
      );
      blob = db.prepare('SELECT ciphertext,size FROM blobs WHERE hash=?').get(match[1]);
      if (req.method === 'PUT' && !blob) {
        const used = db.prepare('SELECT COALESCE(SUM(size),0) AS bytes FROM blobs').get().bytes;
        if (used + body.length > maxStorageBytes) {
          db.exec('COMMIT');
          json(res, 507, { error: 'RELAY_STORAGE_LIMIT' });
          return;
        }
        db.prepare('INSERT INTO blobs(hash,ciphertext,size,created_at) VALUES (?,?,?,?)').run(
          match[1],
          body,
          body.length,
          now(),
        );
      }
      db.exec('COMMIT');
    } catch (error) {
      try {
        db.exec('ROLLBACK');
      } catch {}
      throw error;
    }
    if (req.method === 'PUT') {
      json(res, blob ? 200 : 201, { hash: match[1], size: body.length });
      return;
    }
    if (!blob) {
      json(res, 404, { error: 'BLOB_NOT_FOUND' });
      return;
    }
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-length': blob.size,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    });
    res.end(Buffer.from(blob.ciphertext));
  }
  const server = createServer(async (req, res) => {
    try {
      const route = publicRoutes.get(`${req.method} ${req.url}`) ?? workloadRoute;
      await route(req, res);
    } catch {
      if (!res.headersSent) json(res, 503, { error: 'RELAY_UNAVAILABLE' });
      else res.destroy();
    }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.maxRequestsPerSocket = 100;
  server.on('close', () => {
    if (!closed) {
      closed = true;
      db.close();
    }
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const data = resolve(process.env.SIEPMU_DATA_DIR || '.data');
  const relayData = resolve(process.env.SIEPMU_RELAY_DATA_DIR || `${data}/relay`);
  const host = process.env.SIEPMU_RELAY_HOST || '127.0.0.1';
  if (
    !['127.0.0.1', '::1', 'localhost'].includes(host) &&
    process.env.SIEPMU_ALLOW_REMOTE_HTTP !== '1'
  )
    throw new Error('Remote HTTP requires explicit internal-network override');
  const server = createRelayServer({
    database: `${relayData}/relay.sqlite`,
    secret: readRelaySecret(process.env.SIEPMU_RELAY_SECRET_FILE || `${data}/relay.secret`),
  });
  server.listen(Number(process.env.SIEPMU_RELAY_PORT || 8082), host, () =>
    console.log(`Ciphertext relay listening at ${host}:${server.address().port}`),
  );
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.on(signal, () => {
      server.close();
      server.closeIdleConnections();
    });
}
