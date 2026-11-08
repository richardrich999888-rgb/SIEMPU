import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { canonical } from '../../packages/protocol/canonical.mjs';
import { openPrivateDatabase, transaction } from '../../packages/storage/private-sqlite.mjs';

const fail = (code) => Object.assign(new Error(code), { code });
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

// Endpoint-only storage: encrypted sealed objects and cached signed creation grant.
// Storage key must be retained separately. AEAD detects changes, not whole-store rollback.
export class ManagedOutbox {
  #key;
  #db;
  #binding;
  constructor({ database, key, binding, maxEntries = 1000, maxBytes = 64 * 1024 * 1024 }) {
    if (
      !Buffer.isBuffer(key) ||
      key.length !== 32 ||
      !Number.isSafeInteger(maxEntries) ||
      maxEntries < 1 ||
      maxEntries > 10000 ||
      !Number.isSafeInteger(maxBytes) ||
      maxBytes < 1024 ||
      maxBytes > 256 * 1024 * 1024
    )
      throw fail('OUTBOX_CONFIG');
    this.#key = Buffer.from(key);
    this.#binding = createHmac('sha256', this.#key)
      .update('SIEPMU_MANAGED_OUTBOX_V1\0' + canonical(binding))
      .digest('hex');
    this.maxEntries = maxEntries;
    this.maxBytes = maxBytes;
    try {
      this.#db = openPrivateDatabase(database);
      this.#db.exec(
        'CREATE TABLE IF NOT EXISTS outbox_binding(id INTEGER PRIMARY KEY CHECK(id=1),digest TEXT NOT NULL); CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY, encrypted TEXT NOT NULL);',
      );
      transaction(this.#db, () => {
        const prior = this.#db.prepare('SELECT digest FROM outbox_binding WHERE id=1').get();
        if (!prior) {
          if (this.#db.prepare('SELECT count(*) n FROM outbox').get().n)
            throw fail('OUTBOX_BINDING_MISSING');
          this.#db.prepare('INSERT INTO outbox_binding VALUES(1,?)').run(this.#binding);
        } else if (prior.digest !== this.#binding) throw fail('OUTBOX_BINDING_MISMATCH');
      });
    } catch (error) {
      this.#db?.close();
      this.#key.fill(0);
      throw error;
    }
  }
  #check() {
    if (!this.#db) throw fail('OUTBOX_CLOSED');
    if (
      this.#db.prepare('SELECT digest FROM outbox_binding WHERE id=1').get()?.digest !==
      this.#binding
    )
      throw fail('OUTBOX_BINDING_MISMATCH');
  }
  #encode(id, value) {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(Buffer.from(this.#binding + ':' + id));
    return Buffer.concat([
      iv,
      cipher.update(canonical(value)),
      cipher.final(),
      cipher.getAuthTag(),
    ]).toString('base64');
  }
  #decode(id, encrypted) {
    try {
      const b = Buffer.from(encrypted, 'base64');
      if (b.toString('base64') !== encrypted || b.length < 29 || b.length > this.maxBytes)
        throw fail('OUTBOX_INTEGRITY');
      const decipher = createDecipheriv('aes-256-gcm', this.#key, b.subarray(0, 12));
      decipher.setAAD(Buffer.from(this.#binding + ':' + id));
      decipher.setAuthTag(b.subarray(-16));
      return JSON.parse(Buffer.concat([decipher.update(b.subarray(12, -16)), decipher.final()]));
    } catch {
      throw fail('OUTBOX_INTEGRITY');
    }
  }
  get(id) {
    this.#check();
    const row = this.#db.prepare('SELECT encrypted FROM outbox WHERE id=?').get(id);
    return row ? this.#decode(id, row.encrypted) : null;
  }
  #put(id, value, insertOnly = false) {
    this.#check();
    const encrypted = this.#encode(id, value);
    transaction(this.#db, () => {
      const prior = this.#db
        .prepare('SELECT length(encrypted) bytes FROM outbox WHERE id=?')
        .get(id);
      if (prior && insertOnly) throw fail('OUTBOX_DUPLICATE');
      const size = this.#db
        .prepare(
          "SELECT count(*) n,coalesce(sum(length(encrypted)),0) bytes FROM outbox WHERE id!='grant'",
        )
        .get();
      if (
        (id !== 'grant' && !prior && size.n >= this.maxEntries) ||
        this.#db.prepare('SELECT coalesce(sum(length(encrypted)),0) bytes FROM outbox').get()
          .bytes -
          (prior?.bytes ?? 0) +
          encrypted.length >
          this.maxBytes
      )
        throw fail('OUTBOX_CAPACITY');
      this.#db
        .prepare(
          'INSERT INTO outbox VALUES(?,?) ON CONFLICT(id) DO UPDATE SET encrypted=excluded.encrypted',
        )
        .run(id, encrypted);
    });
  }
  saveGrant(grant) {
    this.#put('grant', grant);
  }
  grant() {
    return this.get('grant');
  }
  enqueue(sealed) {
    const id = sealed?.envelope?.objectId;
    if (!uuid.test(id ?? '')) throw fail('OUTBOX_OBJECT');
    this.#put(id, { sealed, state: 'PENDING', reason: null }, true);
    return id;
  }
  update(id, state, reason = null) {
    const row = this.get(id);
    if (
      !uuid.test(id) ||
      !row ||
      !['SUBMITTED', 'HELD'].includes(state) ||
      (reason !== null && !/^[A-Z][A-Z0-9_]{1,79}$/.test(reason))
    )
      throw fail('OUTBOX_STATE');
    this.#put(id, { ...row, state, reason });
  }
  list() {
    this.#check();
    return this.#db
      .prepare("SELECT id,encrypted FROM outbox WHERE id!='grant' ORDER BY rowid")
      .all()
      .map(({ id, encrypted }) => {
        const row = this.#decode(id, encrypted);
        return {
          id,
          state: row.state,
          reason: row.reason,
          expiresAt: row.sealed.envelope.expiresAt,
        };
      });
  }
  remove(id) {
    this.#check();
    if (!uuid.test(id ?? '')) throw fail('OUTBOX_OBJECT');
    this.#db.prepare('DELETE FROM outbox WHERE id=?').run(id);
  }
  close() {
    this.#db?.close();
    this.#db = null;
    this.#key.fill(0);
  }
}
