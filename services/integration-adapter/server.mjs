/** Synthetic ciphertext submission adapter. No key-release/admin route exists here. */
import { createPublicKey, createHash, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonical } from '../../packages/protocol/canonical.mjs';
import { secureServerFactory } from '../../packages/transport/mtls.mjs';

const digest = (value) => createHash('sha256').update(canonical(value)).digest('hex');
const exact = (value, keys) =>
  value &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const uuid = (value) => typeof value === 'string' && /^[a-f0-9-]{36}$/.test(value);
const fields = [
  'protocol',
  'version',
  'sourceId',
  'keyId',
  'nonce',
  'idempotencyKey',
  'issuedAt',
  'expiresAt',
  'submission',
];

export function createIntegrationAdapter({
  database,
  tls,
  sources,
  controlSubmit,
  now = Date.now,
  maxEntries = 10000,
}) {
  if (!Array.isArray(sources) || !sources.length || typeof controlSubmit !== 'function')
    throw new Error('Explicit synthetic sources and public submission transport required');
  const registry = new Map(
    sources.map((source) => [
      source.id,
      { ...source, publicKey: createPublicKey({ key: source.signingPublicKey, format: 'jwk' }) },
    ]),
  );
  if (registry.size !== sources.length) throw new Error('Duplicate source identity');
  mkdirSync(dirname(database), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(database);
  chmodSync(database, 0o600);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS nonces(source TEXT, nonce TEXT, expires INTEGER, PRIMARY KEY(source,nonce));
    CREATE TABLE IF NOT EXISTS requests(source TEXT, id TEXT, digest TEXT, status TEXT, result TEXT, PRIMARY KEY(source,id));
    CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY, time INTEGER, source TEXT, correlation TEXT, outcome TEXT);`);
  const event = (source, correlation, outcome) =>
    db
      .prepare('INSERT INTO audit(time,source,correlation,outcome) VALUES(?,?,?,?)')
      .run(now(), source, correlation, outcome);
  const server = secureServerFactory({
    ...tls,
    allowedClientPins: sources.map((s) => s.certificatePin),
  })(async (req, res) => {
    let sourceId = 'unknown',
      correlation = '';
    const reply = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    const deny = (status, error) => {
      event(sourceId, correlation, error);
      reply(status, { error });
    };
    try {
      if (req.method === 'GET' && req.url === '/integration/versions') {
        reply(200, { protocol: 'SIEPMU-SYNTHETIC-INGRESS', versions: [1], synthetic: true });
        return;
      }
      if (req.method !== 'POST' || req.url !== '/integration/v1/submissions') {
        deny(404, 'NOT_FOUND');
        return;
      }
      if (req.headers['content-type'] !== 'application/json') {
        deny(415, 'JSON_REQUIRED');
        return;
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 1500000) {
          deny(413, 'BODY_LIMIT');
          return;
        }
        chunks.push(chunk);
      }
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        deny(400, 'INVALID_JSON');
        return;
      }
      if (!exact(body, ['context', 'signature']) || !exact(body.context, fields)) {
        deny(400, 'INVALID_SCHEMA');
        return;
      }
      const c = body.context;
      if (c.protocol !== 'SIEPMU-SYNTHETIC-INGRESS' || c.version !== 1) {
        deny(400, 'UNSUPPORTED_PROTOCOL');
        return;
      }
      const source = registry.get(c.sourceId);
      if (
        !source ||
        c.keyId !== digest(source.signingPublicKey) ||
        req.socket.getPeerCertificate().fingerprint256.replaceAll(':', '').toLowerCase() !==
          source.certificatePin.toLowerCase()
      ) {
        deny(403, 'SOURCE_DENIED');
        return;
      }
      sourceId = c.sourceId;
      if (
        !uuid(c.nonce) ||
        !uuid(c.idempotencyKey) ||
        !Number.isSafeInteger(c.issuedAt) ||
        !Number.isSafeInteger(c.expiresAt) ||
        c.issuedAt > now() + 5000 ||
        c.expiresAt <= now() ||
        c.expiresAt - c.issuedAt > 60000 ||
        c.expiresAt <= c.issuedAt
      ) {
        deny(400, 'INVALID_FRESHNESS');
        return;
      }
      correlation = c.idempotencyKey;
      if (
        typeof body.signature !== 'string' ||
        !/^[A-Za-z0-9_-]{86}$/.test(body.signature) ||
        !verify(
          'sha256',
          Buffer.from(canonical(c)),
          { key: source.publicKey, dsaEncoding: 'ieee-p1363' },
          Buffer.from(body.signature, 'base64url'),
        )
      ) {
        deny(403, 'SIGNATURE_INVALID');
        return;
      }
      const submission = c.submission;
      if (!exact(submission, ['envelope', 'signature', 'ciphertext', 'proof'])) {
        deny(400, 'INVALID_SUBMISSION');
        return;
      }
      const e = submission.envelope;
      if (
        !e ||
        e.senderUserId !== source.senderUserId ||
        e.senderDeviceId !== source.senderDeviceId ||
        !source.destinationUnits.includes(e.recipientUnitId) ||
        !source.missionIds.includes(e.missionId)
      ) {
        deny(403, 'SOURCE_SCOPE_DENIED');
        return;
      }
      const token = req.headers.authorization;
      if (!token?.startsWith('Bearer ')) {
        deny(401, 'CONTROL_AUTH_REQUIRED');
        return;
      }
      const requestDigest = digest({
        envelope: e,
        signature: submission.signature,
        ciphertext: submission.ciphertext,
      });
      let old;
      db.exec('BEGIN IMMEDIATE');
      try {
        db.prepare('DELETE FROM nonces WHERE expires < ?').run(now());
        if (db.prepare('SELECT 1 FROM nonces WHERE source=? AND nonce=?').get(sourceId, c.nonce)) {
          db.exec('ROLLBACK');
          deny(409, 'REPLAY');
          return;
        }
        if (db.prepare('SELECT COUNT(*) AS n FROM nonces').get().n >= maxEntries) {
          db.exec('ROLLBACK');
          deny(507, 'ADAPTER_CAPACITY');
          return;
        }
        db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(sourceId, c.nonce, c.expiresAt);
        old = db
          .prepare('SELECT * FROM requests WHERE source=? AND id=?')
          .get(sourceId, correlation);
        if (old && old.digest !== requestDigest) {
          db.exec('COMMIT');
          deny(409, 'IDEMPOTENCY_CONFLICT');
          return;
        }
        if (!old) {
          if (db.prepare('SELECT COUNT(*) AS n FROM requests').get().n >= maxEntries) {
            db.exec('ROLLBACK');
            deny(507, 'ADAPTER_CAPACITY');
            return;
          }
          db.prepare('INSERT INTO requests VALUES(?,?,?,?,NULL)').run(
            sourceId,
            correlation,
            requestDigest,
            'PENDING',
          );
        }
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      if (old) {
        if (old.status !== 'COMPLETE') {
          deny(409, 'RECOVERY_REQUIRED');
          return;
        }
        event(sourceId, correlation, 'IDEMPOTENT_RECEIPT');
        const result = JSON.parse(old.result);
        reply(result.status, { ...result.body, correlationId: correlation, idempotent: true });
        return;
      }
      // No trust in adapter scope alone: the live control API rechecks MFA/session,
      // device proof, sender policy and ciphertext envelope before durable admission.
      const result = await controlSubmit(submission, token);
      if (!Number.isSafeInteger(result.status) || result.status < 200 || result.status > 599)
        throw new Error('Invalid control result');
      db.exec('BEGIN IMMEDIATE');
      try {
        db.prepare('UPDATE requests SET status=?,result=? WHERE source=? AND id=?').run(
          'COMPLETE',
          JSON.stringify(result),
          sourceId,
          correlation,
        );
        event(sourceId, correlation, result.status < 300 ? 'SUBMITTED' : 'CONTROL_DENIED');
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      reply(result.status, { ...result.body, correlationId: correlation, idempotent: false });
    } catch {
      if (!res.headersSent) deny(503, 'ADAPTER_UNAVAILABLE');
      else res.destroy();
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.on('close', () => db.close());
  return server;
}
