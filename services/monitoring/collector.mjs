import { DatabaseSync } from 'node:sqlite';
import { canonical, hash, verifyPacket, packet } from '../control/primitives.mjs';
import { createTransportServer, fingerprint } from '../../packages/transport/tls.mjs';
import { X509Certificate } from 'node:crypto';

const fields = ['eventId', 'eventType', 'timestamp', 'epoch', 'correlationId', 'reason'];
const token = /^[A-Z][A-Z0-9_]{0,63}$/;
export function redactSecurityEvents(authority) {
  const evidence = authority
    .all('SELECT record FROM evidence ORDER BY sequence DESC LIMIT 1000')
    .map((r) => JSON.parse(r.record));
  const events = evidence.map((r) => ({
    eventId: hash(canonical(r)),
    eventType: r.payload.eventType,
    timestamp: r.payload.timestamp,
    epoch: r.payload.epoch,
    correlationId: hash(String(r.payload.objectId ?? r.payload.eventId)),
    reason: token.test(r.payload.reason ?? '') ? r.payload.reason : 'RECORDED',
  }));
  for (const a of authority.all('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 1000'))
    events.push({
      eventId: hash(a.id),
      eventType: token.test(a.kind) ? a.kind : 'SECURITY_EVENT',
      timestamp: a.timestamp,
      // Epoch recorded with the alert: an export must never change an already-sent event.
      epoch: a.epoch,
      correlationId: hash(a.id),
      reason: token.test(a.reason) ? a.reason : 'REQUEST_DENIED',
    });
  return { version: 1, events };
}
export class SecurityCollector {
  constructor({ database, sourceKey, signingKey, retentionMs = 7 * 86400000, maxEvents = 100000 }) {
    if (
      !Number.isSafeInteger(retentionMs) ||
      retentionMs < 60000 ||
      !Number.isSafeInteger(maxEvents) ||
      maxEvents < 1
    )
      throw new Error('RETENTION_CONFIG');
    Object.assign(this, { sourceKey, signingKey, retentionMs, maxEvents });
    this.db = new DatabaseSync(database);
    this.db.exec(
      'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,digest TEXT NOT NULL,event TEXT NOT NULL,received INTEGER NOT NULL,ack TEXT);',
    );
  }
  ingest(signed, now = Date.now()) {
    if (
      !verifyPacket(this.sourceKey, signed) ||
      signed.payload.version !== 1 ||
      Object.keys(signed.payload).sort().join() !== 'events,version' ||
      !Array.isArray(signed.payload.events) ||
      signed.payload.events.length > 2000
    )
      throw new Error('TELEMETRY_SIGNATURE_OR_SCHEMA');
    const events = signed.payload.events;
    for (const e of events)
      if (
        Object.keys(e).sort().join() !== [...fields].sort().join() ||
        !token.test(e.eventType) ||
        !token.test(e.reason) ||
        !/^[a-f0-9]{64}$/.test(e.eventId) ||
        !/^[a-f0-9]{64}$/.test(e.correlationId) ||
        !Number.isSafeInteger(e.timestamp) ||
        e.timestamp > now + 1000 ||
        e.timestamp < now - this.retentionMs ||
        !Number.isSafeInteger(e.epoch) ||
        e.epoch < 1
      )
        throw new Error('TELEMETRY_REDACTION_OR_TIME');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db
        .prepare('DELETE FROM events WHERE received<? AND ack IS NOT NULL')
        .run(now - this.retentionMs);
      let accepted = 0;
      for (const e of events) {
        const digest = hash(canonical(e)),
          old = this.db.prepare('SELECT digest FROM events WHERE id=?').get(e.eventId);
        if (old && old.digest !== digest) throw new Error('TELEMETRY_CONFLICT');
        if (!old) {
          this.db
            .prepare('INSERT INTO events VALUES(?,?,?,?,NULL)')
            .run(e.eventId, digest, canonical(e), now);
          accepted++;
        }
      }
      if (this.db.prepare('SELECT count(*) n FROM events').get().n > this.maxEvents)
        throw new Error('COLLECTOR_CAPACITY');
      this.db.exec('COMMIT');
      return packet(this.signingKey, {
        version: 1,
        batchDigest: hash(canonical(signed)),
        accepted,
        receivedAt: now,
      });
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  list() {
    return this.db
      .prepare('SELECT event,ack FROM events ORDER BY received DESC LIMIT 2000')
      .all()
      .map((x) => ({ event: JSON.parse(x.event), ack: x.ack ? JSON.parse(x.ack) : null }));
  }
  acknowledge({ eventId, disposition }, operator, now = Date.now()) {
    if (
      !/^[a-f0-9]{64}$/.test(eventId) ||
      !['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].includes(disposition)
    )
      throw new Error('ACK_SCHEMA');
    const receipt = packet(this.signingKey, { eventId, disposition, operator, timestamp: now });
    if (
      this.db.prepare('UPDATE events SET ack=? WHERE id=?').run(canonical(receipt), eventId)
        .changes !== 1
    )
      throw new Error('EVENT_NOT_FOUND');
    return receipt;
  }
  close() {
    this.db.close();
  }
}
export function createCollectorServer({ collector, tls, sourcePin, operatorPin }) {
  if (!tls?.requestCert || sourcePin === operatorPin) throw new Error('COLLECTOR_IDENTITY_CONFIG');
  const server = createTransportServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    try {
      const peer = fingerprint(
        new X509Certificate(req.socket.getPeerCertificate().raw).fingerprint256,
      );
      let body = {};
      if (req.method === 'POST') {
        if (req.headers['content-type'] !== 'application/json') throw new Error('CONTENT_TYPE');
        let size = 0;
        const chunks = [];
        for await (const chunk of req) {
          size += chunk.length;
          if (size > 1500000) throw new Error('BODY_LIMIT');
          chunks.push(chunk);
        }
        body = JSON.parse(Buffer.concat(chunks));
      }
      let result;
      if (req.url === '/v1/events' && req.method === 'POST' && peer === sourcePin)
        result = collector.ingest(body);
      else if (req.url === '/v1/events' && req.method === 'GET' && peer === operatorPin)
        result = { events: collector.list() };
      else if (
        req.url === '/v1/ack' &&
        req.method === 'POST' &&
        peer === operatorPin &&
        Object.keys(body).sort().join() === 'disposition,eventId'
      )
        result = collector.acknowledge(body, peer);
      else {
        res.writeHead(403);
        res.end('{"code":"COLLECTOR_ACCESS_DENIED"}');
        return;
      }
      res.end(JSON.stringify(result));
    } catch {
      res.writeHead(409);
      res.end('{"code":"COLLECTOR_REJECTED"}');
    }
  }, tls);
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  return server;
}
