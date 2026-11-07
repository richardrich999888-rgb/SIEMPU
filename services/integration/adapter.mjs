import { DatabaseSync } from 'node:sqlite';
import { canonical, hash } from '../control/primitives.mjs';
import { createTransportServer } from '../../packages/transport/tls.mjs';

/** Default ceiling on durable idempotency records. Records are never evicted (eviction would
 * reopen replay); once full, new request IDs are refused until an operator archives the store. */
export const DEFAULT_MAX_ENTRIES = 100000;
// Local laboratory resource limit, not a sponsor capacity/availability target.
export const DEFAULT_MAX_PENDING = 32;
/** Accepted clock skew between the synthetic source and the adapter, in either direction. */
export const FRESHNESS_WINDOW_MS = 300000;

export class SyntheticAdapter {
  constructor({
    database,
    endpoint,
    destinations,
    maxEntries = DEFAULT_MAX_ENTRIES,
    maxPending = DEFAULT_MAX_PENDING,
  }) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1)
      throw new TypeError('maxEntries must be a positive integer');
    if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 1024)
      throw new TypeError('maxPending must be an integer from 1 to 1024');
    Object.assign(this, { endpoint, destinations, maxEntries, maxPending });
    this.pending = 0;
    this.tail = Promise.resolve();
    this.db = new DatabaseSync(database);
    this.db.exec(
      'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,digest TEXT NOT NULL,sealed TEXT NOT NULL,result TEXT);',
    );
  }
  async submit(request) {
    if (this.pending >= this.maxPending) throw new Error('ADAPTER_BUSY');
    if (
      !request ||
      typeof request !== 'object' ||
      Array.isArray(request) ||
      Object.keys(request).sort().join() !==
        'destinationUserId,issuedAt,payload,requestId,senderUserId,version' ||
      request.version !== 1 ||
      !Number.isSafeInteger(request.issuedAt) ||
      Math.abs(Date.now() - request.issuedAt) > FRESHNESS_WINDOW_MS ||
      !/^[a-f0-9-]{36}$/.test(request.requestId)
    )
      throw new Error('ADAPTER_SCHEMA_OR_REPLAY');
    if (request.senderUserId !== this.endpoint.profile.userId)
      throw new Error('ADAPTER_SENDER_DENIED');
    const destination = this.destinations.find((d) => d.userId === request.destinationUserId);
    if (!destination) throw new Error('ADAPTER_DESTINATION_DENIED');
    this.endpoint.crypto.validatePayload(request.payload);
    // A caller must not change a validated request while it waits behind another request.
    request = JSON.parse(canonical(request));
    const prior = this.tail;
    let unlock;
    this.tail = new Promise((r) => {
      unlock = r;
    });
    this.pending++;
    await prior;
    try {
      if (Math.abs(Date.now() - request.issuedAt) > FRESHNESS_WINDOW_MS)
        throw new Error('ADAPTER_SCHEMA_OR_REPLAY');
      const digest = hash(canonical(request));
      let row = this.db.prepare('SELECT * FROM requests WHERE id=?').get(request.requestId);
      if (row && row.digest !== digest) throw new Error('IDEMPOTENCY_CONFLICT');
      if (row?.result) return JSON.parse(row.result);
      if (!row) {
        const { n } = this.db.prepare('SELECT COUNT(*) AS n FROM requests').get();
        if (n >= this.maxEntries) throw new Error('ADAPTER_CAPACITY');
        const sealed = await this.endpoint.seal(destination, request.payload);
        this.db
          .prepare('INSERT INTO requests VALUES(?,?,?,NULL)')
          .run(request.requestId, digest, canonical(sealed));
        row = { sealed: canonical(sealed) };
      }
      const result = await this.endpoint.submit(JSON.parse(row.sealed));
      const response = {
        version: 1,
        requestId: request.requestId,
        objectId: result.object.id,
        accepted: true,
        receipt: result.receipt,
      };
      this.db
        .prepare('UPDATE requests SET result=? WHERE id=?')
        .run(canonical(response), request.requestId);
      return response;
    } finally {
      this.pending--;
      unlock();
    }
  }
  async readiness() {
    const checks = { database: false, capacity: this.pending < this.maxPending, authority: false };
    try {
      checks.database = this.db.prepare('SELECT 1 AS ok').get().ok === 1;
    } catch {}
    if (checks.database && checks.capacity) {
      try {
        const { payload } = await this.endpoint.signed('/api/control');
        const now = Date.now();
        checks.authority =
          Number.isSafeInteger(payload?.issuedAt) &&
          Number.isSafeInteger(payload?.expiresAt) &&
          payload.issuedAt <= now &&
          payload.expiresAt > now;
      } catch {}
    }
    return { service: 'synthetic-adapter', ready: Object.values(checks).every(Boolean), checks };
  }
  /**
   * Delivery state of a previously accepted request, as currently reported by the authority.
   * The source system holds no platform credential; it learns only state, never content.
   */
  async status(requestId) {
    if (typeof requestId !== 'string' || !/^[a-f0-9-]{36}$/.test(requestId))
      throw new Error('ADAPTER_SCHEMA_OR_REPLAY');
    const row = this.db.prepare('SELECT result FROM requests WHERE id=?').get(requestId);
    if (!row?.result) throw new Error('ADAPTER_UNKNOWN_REQUEST');
    const { objectId } = JSON.parse(row.result);
    const object = (await this.endpoint.listObjects()).find((o) => o.id === objectId);
    if (!object) throw new Error('ADAPTER_UNKNOWN_REQUEST');
    return { version: 1, requestId, objectId, state: object.state };
  }
  close() {
    this.db.close();
  }
}
const STATUS_PATH = /^\/v1\/messages\/([a-f0-9-]{36})$/;
export function createAdapterServer({ adapter, tls }) {
  if (!tls?.requestCert) throw new Error('ADAPTER_MTLS_REQUIRED');
  const server = createTransportServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    try {
      if (req.method === 'GET' && req.url === '/ready') {
        const observation = await adapter.readiness();
        res.writeHead(observation.ready ? 200 : 503);
        res.end(canonical(observation));
        return;
      }
      const status = req.method === 'GET' ? STATUS_PATH.exec(req.url ?? '') : null;
      if (status) {
        try {
          res.end(canonical(await adapter.status(status[1])));
        } catch (error) {
          // Unknown or malformed IDs are 404; a platform failure is reported as such, not hidden.
          const known = ['ADAPTER_UNKNOWN_REQUEST', 'ADAPTER_SCHEMA_OR_REPLAY'].includes(
            /** @type {Error} */ (error).message,
          );
          res.writeHead(known ? 404 : 502);
          res.end(
            known
              ? '{"version":1,"code":"ADAPTER_UNKNOWN_REQUEST"}'
              : '{"version":1,"code":"ADAPTER_UPSTREAM"}',
          );
        }
        return;
      }
      if (
        req.url !== '/v1/messages' ||
        req.method !== 'POST' ||
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
        if (size > 512 * 1024) throw new Error('BODY_LIMIT');
        chunks.push(chunk);
      }
      const response = await adapter.submit(JSON.parse(Buffer.concat(chunks)));
      res.end(canonical(response));
    } catch (error) {
      const busy = error?.message === 'ADAPTER_BUSY';
      if (busy) res.setHeader('retry-after', '1');
      res.writeHead(busy ? 503 : 409);
      res.end(
        busy ? '{"version":1,"code":"ADAPTER_BUSY"}' : '{"version":1,"code":"ADAPTER_REJECTED"}',
      );
    }
  }, tls);
  server.requestTimeout = 15000;
  server.headersTimeout = 5000;
  return server;
}
