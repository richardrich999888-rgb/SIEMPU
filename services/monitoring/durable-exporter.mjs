import { packet, canonical, hash, verifyPacket, publicJwk } from '../control/primitives.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import { openPrivateDatabase, transaction } from '../../packages/storage/private-sqlite.mjs';
import { redactEvidence, redactAlert } from './collector.mjs';

const zero = '0'.repeat(64);
const exact = (v, keys) =>
  v &&
  typeof v === 'object' &&
  !Array.isArray(v) &&
  Object.keys(v).sort().join() === [...keys].sort().join();
const integer = (n) => Number.isSafeInteger(n) && n >= 0;
const digest = (s) => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);

// At-least-once, source-bound delivery with a durable signed cursor and one pending
// batch. The source log remains the backlog. Retention rejection never skips records.
export class DurableTelemetryExporter {
  #db;
  #inflight;
  constructor({ database, url, tls, collectorKey, authority, batchSize = 250 }) {
    if (
      !tls ||
      new URL(url).protocol !== 'https:' ||
      !Number.isSafeInteger(batchSize) ||
      batchSize < 1 ||
      batchSize > 1000
    )
      throw new Error('MONITORING_CONFIG');
    this.url = url;
    this.tls = tls;
    this.collectorKey = structuredClone(collectorKey);
    this.authority = authority;
    this.batchSize = batchSize;
    this.sourceKey = publicJwk(authority.key);
    this.binding = hash(
      canonical({ version: 1, url, sourceKey: this.sourceKey, collectorKey: this.collectorKey }),
    );
    this.state = 'NOT_DELIVERED';
    this.lastDeliveredAt = null;
    this.#db = openPrivateDatabase(database);
    try {
      this.#db.exec(
        'CREATE TABLE IF NOT EXISTS telemetry_cursor(id INTEGER PRIMARY KEY CHECK(id=1),signed TEXT NOT NULL);',
      );
      transaction(this.#db, () => {
        if (!this.#db.prepare('SELECT signed FROM telemetry_cursor WHERE id=1').get())
          this.#db
            .prepare('INSERT INTO telemetry_cursor VALUES(1,?)')
            .run(
              this.#sign({
                evidence: 0,
                alert: 0,
                evidenceHash: zero,
                alertHash: zero,
                pending: null,
              }),
            );
        this.#read();
      });
    } catch (error) {
      this.#db.close();
      throw error;
    }
  }
  #sign(value) {
    return canonical(
      packet(this.authority.key, {
        version: 1,
        domain: 'SIEPMU_TELEMETRY_CURSOR',
        binding: this.binding,
        ...value,
      }),
    );
  }
  #read() {
    const raw = this.#db.prepare('SELECT signed FROM telemetry_cursor WHERE id=1').get()?.signed;
    let signed;
    try {
      signed = JSON.parse(raw);
    } catch {
      throw new Error('MONITORING_CURSOR_INVALID');
    }
    const p = signed.payload;
    if (
      !verifyPacket(this.sourceKey, signed) ||
      !exact(p, [
        'version',
        'domain',
        'binding',
        'evidence',
        'alert',
        'evidenceHash',
        'alertHash',
        'pending',
      ]) ||
      p.version !== 1 ||
      p.domain !== 'SIEPMU_TELEMETRY_CURSOR' ||
      p.binding !== this.binding ||
      !integer(p.evidence) ||
      !integer(p.alert) ||
      !digest(p.evidenceHash) ||
      !digest(p.alertHash) ||
      (p.pending !== null &&
        (!exact(p.pending, ['batch', 'evidence', 'alert', 'evidenceHash', 'alertHash']) ||
          !integer(p.pending.evidence) ||
          !integer(p.pending.alert) ||
          p.pending.evidence < p.evidence ||
          p.pending.alert < p.alert ||
          !digest(p.pending.evidenceHash) ||
          !digest(p.pending.alertHash) ||
          !verifyPacket(this.sourceKey, p.pending.batch) ||
          !Array.isArray(p.pending.batch.payload.events) ||
          p.pending.batch.payload.events.length > 2000))
    )
      throw new Error('MONITORING_CURSOR_INVALID');
    return { raw, p };
  }
  #anchors(p) {
    if (p.evidence) {
      const row = this.authority.get(
        'SELECT record,hash FROM evidence WHERE sequence=?',
        p.evidence,
      );
      if (!row || row.hash !== p.evidenceHash || hash(row.record) !== p.evidenceHash)
        throw new Error('MONITORING_SOURCE_ROLLBACK');
    }
    if (p.alert) {
      const row = this.authority.get(
        'SELECT rowid AS sequence,* FROM alerts WHERE rowid=?',
        p.alert,
      );
      if (!row || hash(canonical(row)) !== p.alertHash)
        throw new Error('MONITORING_SOURCE_ROLLBACK');
    }
  }
  #pending() {
    return transaction(this.#db, () => {
      const { raw, p } = this.#read();
      this.#anchors(p);
      if (p.pending) {
        this.#anchors(p.pending);
        return { raw, p };
      }
      const evidence = this.authority.all(
        'SELECT sequence,record,hash FROM evidence WHERE sequence>? ORDER BY sequence LIMIT ?',
        p.evidence,
        this.batchSize,
      );
      const alerts = this.authority.all(
        'SELECT rowid AS sequence,* FROM alerts WHERE rowid>? ORDER BY rowid LIMIT ?',
        p.alert,
        this.batchSize,
      );
      const next = {
        evidence: p.evidence,
        alert: p.alert,
        evidenceHash: p.evidenceHash,
        alertHash: p.alertHash,
      };
      const events = [];
      for (const row of evidence) {
        const record = JSON.parse(row.record);
        if (
          row.sequence !== next.evidence + 1 ||
          !verifyPacket(this.sourceKey, record) ||
          record.payload.sequence !== row.sequence ||
          record.payload.previousHash !== next.evidenceHash ||
          hash(row.record) !== row.hash
        )
          throw new Error('MONITORING_SOURCE_GAP');
        events.push(redactEvidence(record));
        next.evidence = row.sequence;
        next.evidenceHash = row.hash;
      }
      for (const row of alerts) {
        if (row.sequence !== next.alert + 1) throw new Error('MONITORING_SOURCE_GAP');
        events.push(redactAlert(row));
        next.alert = row.sequence;
        next.alertHash = hash(canonical(row));
      }
      if (!events.length) return { raw, p };
      p.pending = { ...next, batch: packet(this.authority.key, { version: 1, events }) };
      const updated = this.#sign({
        evidence: p.evidence,
        alert: p.alert,
        evidenceHash: p.evidenceHash,
        alertHash: p.alertHash,
        pending: p.pending,
      });
      this.#db.prepare('UPDATE telemetry_cursor SET signed=? WHERE id=1').run(updated);
      return { raw: updated, p };
    });
  }
  deliver(authority = this.authority) {
    if (this.#inflight) return this.#inflight;
    this.#inflight = this.#deliver(authority).finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }
  async #deliver(authority) {
    try {
      if (!this.#db || authority !== this.authority) throw new Error('MONITORING_SOURCE_INVALID');
      const { raw, p } = this.#pending();
      if (!p.pending) {
        this.state = 'CAUGHT_UP';
        return { caughtUp: true };
      }
      const pending = p.pending;
      const response = await requestBytes(this.url, {
        method: 'POST',
        tls: this.tls,
        headers: { 'content-type': 'application/json' },
        body: canonical(pending.batch),
        timeoutMs: 2000,
        maxBytes: 32768,
      });
      const receipt = JSON.parse(response.body),
        r = receipt.payload;
      if (
        response.status !== 200 ||
        !verifyPacket(this.collectorKey, receipt) ||
        !exact(r, ['version', 'batchDigest', 'accepted', 'receivedAt']) ||
        r.version !== 1 ||
        r.batchDigest !== hash(canonical(pending.batch)) ||
        !integer(r.accepted) ||
        r.accepted > pending.batch.payload.events.length ||
        !integer(r.receivedAt)
      )
        throw new Error('COLLECTOR_ACK_INVALID');
      transaction(this.#db, () => {
        if (this.#read().raw !== raw) throw new Error('MONITORING_CURSOR_CONFLICT');
        this.#anchors(pending);
        this.#db.prepare('UPDATE telemetry_cursor SET signed=? WHERE id=1').run(
          this.#sign({
            evidence: pending.evidence,
            alert: pending.alert,
            evidenceHash: pending.evidenceHash,
            alertHash: pending.alertHash,
            pending: null,
          }),
        );
      });
      this.state = 'BATCH_DELIVERED';
      this.lastDeliveredAt = Date.now();
      return receipt;
    } catch {
      this.state = 'DEGRADED';
      return null;
    }
  }
  async close() {
    await this.#inflight;
    this.#db?.close();
    this.#db = null;
    this.state = 'CLOSED';
  }
}
