import { canonical, hash } from '../control/primitives.mjs';
import { createTransportServer } from '../../packages/transport/tls.mjs';
import {
  bindDatabase,
  privateDatabase,
  validateSource,
  validateDestinations,
  validateTransfer,
  insist,
} from '../../packages/integration/sealed-transfer.mjs';

// Data-plane staging only. No personnel session, content-key wrap or endpoint private key.
export class SealedAdapter {
  constructor({
    database,
    source,
    destinations,
    relay,
    maxEntries = 10000,
    maxPending = 32,
    maxStoredBytes = 16 * 1024 * 1024,
  }) {
    insist(
      Number.isSafeInteger(maxEntries) && maxEntries > 0 && maxEntries <= 100000,
      'TRANSFER_LIMIT',
    );
    insist(
      Number.isSafeInteger(maxPending) && maxPending > 0 && maxPending <= 128,
      'TRANSFER_LIMIT',
    );
    insist(
      Number.isSafeInteger(maxStoredBytes) &&
        maxStoredBytes > 0 &&
        maxStoredBytes <= 1024 * 1024 * 1024,
      'TRANSFER_LIMIT',
    );
    this.source = validateSource(source);
    this.destinations = validateDestinations(destinations);
    Object.assign(this, { relay, maxEntries, maxPending, maxStoredBytes });
    this.pending = 0;
    this.tail = Promise.resolve();
    this.db = privateDatabase(database);
    try {
      this.db.exec(
        'CREATE TABLE IF NOT EXISTS transfers(id TEXT PRIMARY KEY,digest TEXT NOT NULL,request TEXT NOT NULL,response TEXT);',
      );
      bindDatabase(
        this.db,
        { version: 2, source: this.source, destinations: this.destinations },
        'transfers',
      );
    } catch (error) {
      this.db.close();
      throw error;
    }
  }
  async stage(request) {
    insist(this.pending < this.maxPending, 'TRANSFER_BUSY');
    validateTransfer(request, this.source, this.destinations);
    const encoded = canonical(request);
    request = JSON.parse(encoded);
    const prior = this.tail;
    let unlock;
    this.tail = new Promise((r) => {
      unlock = r;
    });
    this.pending++;
    await prior;
    try {
      const bytes = validateTransfer(request, this.source, this.destinations);
      const m = request.manifest,
        digest = hash(encoded);
      const existing = this.db.prepare('SELECT * FROM transfers WHERE id=?').get(m.requestId);
      insist(!existing || existing.digest === digest, 'TRANSFER_IDEMPOTENCY_CONFLICT');
      if (existing?.response) return JSON.parse(existing.response);
      if (!existing) {
        const { n, bytes: stored } = this.db
          .prepare('SELECT COUNT(*) n, COALESCE(SUM(length(request)),0) bytes FROM transfers')
          .get();
        insist(
          n < this.maxEntries && stored + Buffer.byteLength(encoded) <= this.maxStoredBytes,
          'TRANSFER_CAPACITY',
        );
        this.db
          .prepare('INSERT INTO transfers VALUES(?,?,?,NULL)')
          .run(m.requestId, digest, encoded);
      }
      const receipt = await this.relay.putBlob(m.ciphertextHash, bytes);
      insist(
        receipt?.hash === m.ciphertextHash && receipt?.size === bytes.length,
        'TRANSFER_RELAY_RECEIPT',
      );
      const response = {
        version: 2,
        requestId: m.requestId,
        objectId: m.objectId,
        state: 'STAGED_CIPHERTEXT',
        ciphertextHash: receipt.hash,
        bytes: receipt.size,
      };
      this.db
        .prepare('UPDATE transfers SET response=? WHERE id=?')
        .run(canonical(response), m.requestId);
      return response;
    } finally {
      this.pending--;
      unlock();
    }
  }
  async readiness() {
    const checks = { database: false, capacity: this.pending < this.maxPending, relay: false };
    try {
      const { n, bytes } = this.db
        .prepare('SELECT COUNT(*) n, COALESCE(SUM(length(request)),0) bytes FROM transfers')
        .get();
      checks.database = true;
      checks.capacity &&= n < this.maxEntries && bytes < this.maxStoredBytes;
      checks.relay = (await this.relay.health()) === true;
    } catch {}
    return {
      service: 'sealed-ciphertext-adapter',
      ready: Object.values(checks).every(Boolean),
      checks,
    };
  }
  close() {
    this.db.close();
  }
}

export function createSealedAdapterServer({ adapter, tls }) {
  insist(tls?.requestCert, 'TRANSFER_MTLS_REQUIRED');
  const server = createTransportServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    try {
      insist(!req.headers.authorization, 'TRANSFER_CREDENTIAL_FORBIDDEN');
      if (req.method === 'GET' && req.url === '/ready') {
        const state = await adapter.readiness();
        res.writeHead(state.ready ? 200 : 503);
        res.end(canonical(state));
        return;
      }
      if (
        req.method !== 'POST' ||
        req.url !== '/v2/ciphertext' ||
        req.headers['content-type'] !== 'application/json'
      ) {
        res.writeHead(404);
        res.end('{}');
        return;
      }
      const chunks = [];
      let size = 0;
      for await (const b of req) {
        size += b.length;
        insist(size <= 384 * 1024, 'TRANSFER_SIZE');
        chunks.push(b);
      }
      res.end(canonical(await adapter.stage(JSON.parse(Buffer.concat(chunks)))));
    } catch (error) {
      const busy = error?.message === 'TRANSFER_BUSY';
      if (busy) res.setHeader('retry-after', '1');
      res.writeHead(busy ? 503 : 409);
      res.end(canonical({ version: 2, code: busy ? 'TRANSFER_BUSY' : 'TRANSFER_REJECTED' }));
    }
  }, tls);
  server.maxConnections = 32;
  server.requestTimeout = 15000;
  server.headersTimeout = 5000;
  return server;
}
