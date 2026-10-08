import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { verifyEvidence } from '../../apps/verifier/verify.mjs';
import { canonical, hash, packet, verifyPacket } from '../control/primitives.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';

export function authoritySnapshot(authority) {
  return {
    records: authority
      .all('SELECT record FROM evidence ORDER BY sequence')
      .map((r) => JSON.parse(r.record)),
    checkpoint: authority.checkpoint(),
  };
}
export function authorizationDigest(authority) {
  return hash(
    canonical({
      authority: authority.epoch(),
      users: authority.all(
        'SELECT id,unit_id,role,missions,active,duty_role FROM users ORDER BY id',
      ),
      devices: authority.all(
        'SELECT id,user_id,signing_key,encryption_key,status FROM devices ORDER BY id',
      ),
      policies: authority.all('SELECT * FROM policies ORDER BY from_unit,to_unit,mission_id'),
    }),
  );
}
export class CheckpointCustodian {
  constructor({ database, authorityKey, signingKey, maxAgeMs = 30000, allowBootstrap = false }) {
    this.allowBootstrap = allowBootstrap;
    this.key = signingKey;
    this.authorityKey = authorityKey;
    this.maxAgeMs = maxAgeMs;
    this.db = new DatabaseSync(database);
    this.db.exec(
      'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS anchor(id INTEGER PRIMARY KEY CHECK(id=1), checkpoint TEXT NOT NULL, state TEXT NOT NULL);',
    );
  }
  async accept(request, now = Date.now()) {
    if (!verifyPacket(this.authorityKey, request)) throw new Error('CHECKPOINT_SIGNATURE');
    const p = request.payload;
    if (
      p.version !== 1 ||
      !/^[a-f0-9]{64}$/.test(p.stateDigest) ||
      typeof p.nonce !== 'string' ||
      !Number.isSafeInteger(p.issuedAt) ||
      Math.abs(now - p.issuedAt) > this.maxAgeMs
    )
      throw new Error('CHECKPOINT_REQUEST_STALE');
    // Verify before taking a synchronous SQLite transaction; re-read the anchor
    // inside it so concurrent requests cannot regress independent custody.
    await verifyEvidence(p.evidence, this.authorityKey);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const old = this.db.prepare('SELECT * FROM anchor WHERE id=1').get();
      if (!old && !this.allowBootstrap) throw new Error('CHECKPOINT_ANCHOR_MISSING');
      const cp = p.evidence.checkpoint,
        head = cp.payload;
      if (old) {
        const saved = JSON.parse(old.checkpoint).payload;
        const at = p.evidence.records[saved.sequence - 1];
        if (
          saved.sequence > head.sequence ||
          (saved.sequence > 0 && hash(canonical(at)) !== saved.headHash) ||
          (saved.sequence === head.sequence &&
            (saved.headHash !== head.headHash || old.state !== p.stateDigest))
        )
          throw new Error('RECOVERY_ROLLBACK_OR_FORK');
      }
      this.db
        .prepare(
          'INSERT INTO anchor VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint,state=excluded.state',
        )
        .run(canonical(cp), p.stateDigest);
      this.db.exec('COMMIT');
      this.allowBootstrap = false;
      return packet(this.key, {
        version: 1,
        nonce: p.nonce,
        authorityKeyId: request.keyId,
        sequence: head.sequence,
        headHash: head.headHash,
        stateDigest: p.stateDigest,
        issuedAt: now,
        expiresAt: now + this.maxAgeMs,
      });
    } catch (error) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      throw error;
    }
  }
  close() {
    this.db.close();
  }
}

export function createRecoveryGuard({ custodianKey, exchange, maxAgeMs = 30000 }) {
  let lease = null;
  return {
    state: 'QUARANTINED',
    reason: 'RECOVERY_NOT_VALIDATED',
    allows(authority) {
      const head = authority.checkpoint().payload;
      return (
        this.state === 'VALIDATED' &&
        lease &&
        Date.now() < lease.expiresAt &&
        Date.now() >= lease.issuedAt - 1000 &&
        lease.stateDigest === authorizationDigest(authority) &&
        lease.sequence === head.sequence &&
        lease.headHash === head.headHash
      );
    },
    async authorize(authority) {
      this.state = 'QUARANTINED';
      lease = null;
      const evidence = authoritySnapshot(authority),
        stateDigest = authorizationDigest(authority),
        nonce = randomUUID(),
        issuedAt = Date.now();
      try {
        const response = await exchange(
          packet(authority.key, { version: 1, nonce, issuedAt, stateDigest, evidence }),
        );
        if (!verifyPacket(custodianKey, response)) throw new Error('CUSTODIAN_SIGNATURE');
        const p = response.payload,
          now = Date.now();
        if (
          p.version !== 1 ||
          p.nonce !== nonce ||
          p.authorityKeyId !== evidence.checkpoint.keyId ||
          p.stateDigest !== stateDigest ||
          p.sequence !== evidence.checkpoint.payload.sequence ||
          p.headHash !== evidence.checkpoint.payload.headHash ||
          !Number.isSafeInteger(p.issuedAt) ||
          !Number.isSafeInteger(p.expiresAt) ||
          p.issuedAt > now + 1000 ||
          now - p.issuedAt > maxAgeMs ||
          p.expiresAt <= now ||
          p.expiresAt - p.issuedAt > maxAgeMs
        )
          throw new Error('CUSTODIAN_LEASE_INVALID');
        lease = p;
        this.state = 'VALIDATED';
        this.reason = null;
        if (!this.allows(authority)) throw new Error('AUTHORITY_CHANGED_DURING_RECOVERY');
      } catch (error) {
        this.state = 'QUARANTINED';
        this.reason = error.message;
        lease = null;
        throw Object.assign(new Error('Recovery trust is unavailable or inconsistent'), {
          status: 503,
          code: 'RECOVERY_QUARANTINED',
        });
      }
    },
  };
}
export function remoteCustodyExchange(url, tls) {
  if (!tls || new URL(url).protocol !== 'https:')
    throw new Error('Custody requires authenticated TLS');
  return async (request) => {
    const result = await requestBytes(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: canonical(request),
      tls,
      maxBytes: 32768,
      timeoutMs: 5000,
    });
    if (result.status !== 200) throw new Error('CUSTODIAN_REJECTED');
    return JSON.parse(result.body);
  };
}
