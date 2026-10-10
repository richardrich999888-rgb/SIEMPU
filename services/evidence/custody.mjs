import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { verifyEvidence, verifyEvidenceRange } from '../../apps/verifier/verify.mjs';
import { canonical, hash, packet, verifyPacket } from '../control/primitives.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import {
  DELTA_MAX_RECORDS,
  RANGE_VERSION,
  anchorFromAnswer,
  checkAnchorTransition,
  leaseMatches,
  planRanges,
  validateAnchorQuery,
  validateRangeRequest,
} from './incremental.mjs';

/** Full evidence export (protocol version 1 and offline audit). Cost O(chain length). */
export function authoritySnapshot(authority) {
  return {
    records: authority
      .all('SELECT record FROM evidence ORDER BY sequence')
      .map((r) => JSON.parse(r.record)),
    checkpoint: authority.checkpoint(),
  };
}
/**
 * Authority records with after < sequence <= until, in order, as signed packets with their
 * stored digests. Cost O(until - after) via the evidence primary key.
 * @param {any} authority
 * @param {number} after
 * @param {number} until
 */
export function authorityRange(authority, after, until) {
  const rows = authority.all(
    'SELECT sequence,record,hash FROM evidence WHERE sequence>? AND sequence<=? ORDER BY sequence',
    after,
    until,
  );
  // A missing row means the local store has a hole; never send a range the custodian would
  // have to reject anyway, and never let a gap look like a shorter chain.
  if (rows.length !== until - after || rows.some((r, i) => r.sequence !== after + i + 1))
    throw new Error('AUTHORITY_EVIDENCE_GAP');
  return rows.map((r) => ({ record: JSON.parse(r.record), hash: r.hash }));
}
/** Digest of the authorization-relevant state (users, devices, policies, epoch). */
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
  /**
   * Accepts a signed checkpoint request and returns a signed lease, or throws.
   * Version 1 carries the whole chain (verified from genesis); version 2 carries only the
   * records after the retained anchor (ADR-014). Both share one anchor table and lease format.
   */
  async accept(request, now = Date.now()) {
    if (!verifyPacket(this.authorityKey, request)) throw new Error('CHECKPOINT_SIGNATURE');
    const version = request.payload?.version;
    if (version === 1) return this.#acceptFull(request, now);
    if (version === RANGE_VERSION) return this.#acceptRange(request, now);
    throw new Error('CHECKPOINT_VERSION');
  }
  async #acceptFull(request, now) {
    const p = request.payload;
    if (
      !/^[a-f0-9]{64}$/.test(p.stateDigest) ||
      typeof p.nonce !== 'string' ||
      !Number.isSafeInteger(p.issuedAt) ||
      Math.abs(now - p.issuedAt) > this.maxAgeMs
    )
      throw new Error('CHECKPOINT_REQUEST_STALE');
    // Verify before taking a synchronous SQLite transaction; re-read the anchor
    // inside it so concurrent requests cannot regress independent custody.
    await verifyEvidence(p.evidence, this.authorityKey);
    const cp = p.evidence.checkpoint,
      head = cp.payload;
    return this.#anchor(request, cp, p.stateDigest, now, (old) => {
      const saved = JSON.parse(old.checkpoint).payload;
      const at = p.evidence.records[saved.sequence - 1];
      if (
        saved.sequence > head.sequence ||
        (saved.sequence > 0 && hash(canonical(at)) !== saved.headHash) ||
        (saved.sequence === head.sequence &&
          (saved.headHash !== head.headHash || old.state !== p.stateDigest))
      )
        throw new Error('RECOVERY_ROLLBACK_OR_FORK');
    });
  }
  async #acceptRange(request, now) {
    const p = request.payload;
    validateRangeRequest(p, now, this.maxAgeMs);
    // Signature and link verification of the increment only: O(records), not O(chain).
    const range = verifyEvidenceRange(
      { base: p.base, records: p.records, checkpoint: p.checkpoint },
      this.authorityKey,
      { maxRecords: DELTA_MAX_RECORDS },
    );
    const proposal = {
      base: p.base,
      head: { sequence: range.toSequence, headHash: range.headHash },
      stateDigest: p.stateDigest,
    };
    return this.#anchor(
      request,
      p.checkpoint,
      p.stateDigest,
      now,
      (old) => {
        const saved = JSON.parse(old.checkpoint).payload;
        checkAnchorTransition(
          { sequence: saved.sequence, headHash: saved.headHash, state: old.state },
          proposal,
          false,
        );
      },
      () => checkAnchorTransition(null, proposal, this.allowBootstrap),
    );
  }
  /**
   * Atomically checks the retained anchor and replaces it with `cp`, then signs a lease.
   * `check(old)` runs inside the write transaction against the current anchor row.
   */
  #anchor(
    request,
    cp,
    stateDigest,
    now,
    check,
    checkMissing = () => {
      if (!this.allowBootstrap) throw new Error('CHECKPOINT_ANCHOR_MISSING');
    },
  ) {
    const head = cp.payload;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const old = this.db.prepare('SELECT * FROM anchor WHERE id=1').get();
      if (old) check(old);
      else checkMissing();
      this.db
        .prepare(
          'INSERT INTO anchor VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint,state=excluded.state',
        )
        .run(canonical(cp), stateDigest);
      this.db.exec('COMMIT');
      this.allowBootstrap = false;
      return packet(this.key, {
        version: 1,
        nonce: request.payload.nonce,
        authorityKeyId: request.keyId,
        sequence: head.sequence,
        headHash: head.headHash,
        stateDigest,
        issuedAt: now,
        expiresAt: now + this.maxAgeMs,
      });
    } catch (error) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      throw error;
    }
  }
  /**
   * Answers a signed anchor query with the retained head, signed by the custodian. Lets a
   * restarted authority resume incremental custody without shipping its whole chain.
   * Read-only: never changes the anchor.
   */
  anchor(request, now = Date.now()) {
    if (!verifyPacket(this.authorityKey, request)) throw new Error('CHECKPOINT_SIGNATURE');
    validateAnchorQuery(request.payload, now, this.maxAgeMs);
    const row = this.db.prepare('SELECT checkpoint FROM anchor WHERE id=1').get();
    const saved = row ? JSON.parse(row.checkpoint).payload : null;
    return packet(this.key, {
      version: RANGE_VERSION,
      kind: 'ANCHOR',
      nonce: request.payload.nonce,
      anchored: Boolean(saved),
      sequence: saved?.sequence ?? 0,
      headHash: saved?.headHash ?? '0'.repeat(64),
      issuedAt: now,
    });
  }
  close() {
    this.db.close();
  }
}

/**
 * Recovery guard: the authority may serve protected requests only while it holds a fresh lease
 * from the independent custodian for its exact current head and authorization state.
 *
 * Without `anchorQuery`, every authorisation ships the whole chain (protocol version 1, cost
 * O(chain)). With `anchorQuery`, it ships only records after the custodian's anchor (version 2,
 * cost O(new records)); the anchor is learned once from the custodian and then tracked from
 * verified leases. Any failure quarantines the authority and forgets the tracked anchor, so the
 * next attempt re-learns it from the custodian rather than trusting local state.
 * @param {{ custodianKey: object, exchange: (request: object) => Promise<any>,
 *           anchorQuery?: (request: object) => Promise<any>, maxAgeMs?: number,
 *           maxDeltaRecords?: number }} options
 */
export function createRecoveryGuard({
  custodianKey,
  exchange,
  anchorQuery,
  maxAgeMs = 30000,
  maxDeltaRecords = DELTA_MAX_RECORDS,
}) {
  let lease = null;
  /** Custodian anchor as last confirmed by a verified signature; null means unknown. */
  let known = null;
  const verifiedLease = (response, expected) => {
    if (!verifyPacket(custodianKey, response)) throw new Error('CUSTODIAN_SIGNATURE');
    if (!leaseMatches(response.payload, expected, Date.now(), maxAgeMs))
      throw new Error('CUSTODIAN_LEASE_INVALID');
    return response.payload;
  };
  async function fullChain(authority, stateDigest) {
    const evidence = authoritySnapshot(authority),
      nonce = randomUUID();
    const response = await exchange(
      packet(authority.key, { version: 1, nonce, issuedAt: Date.now(), stateDigest, evidence }),
    );
    return verifiedLease(response, {
      nonce,
      authorityKeyId: evidence.checkpoint.keyId,
      stateDigest,
      sequence: evidence.checkpoint.payload.sequence,
      headHash: evidence.checkpoint.payload.headHash,
    });
  }
  async function learnAnchor(authority) {
    const nonce = randomUUID();
    const answer = await anchorQuery(
      packet(authority.key, {
        version: RANGE_VERSION,
        kind: 'ANCHOR_QUERY',
        nonce,
        issuedAt: Date.now(),
      }),
    );
    if (!verifyPacket(custodianKey, answer)) throw new Error('CUSTODIAN_SIGNATURE');
    return anchorFromAnswer(answer.payload, nonce, Date.now(), maxAgeMs);
  }
  async function incremental(authority, stateDigest) {
    known ??= await learnAnchor(authority);
    const head = authority.checkpoint();
    let accepted = null;
    for (const { after, until } of planRanges(
      known.sequence,
      head.payload.sequence,
      maxDeltaRecords,
    )) {
      const rows = authorityRange(authority, after, until);
      const final = until === head.payload.sequence;
      const checkpoint = final
        ? head
        : packet(authority.key, {
            sequence: until,
            headHash: rows.at(-1).hash,
            issuedAt: Date.now(),
          });
      const nonce = randomUUID();
      const response = await exchange(
        packet(authority.key, {
          version: RANGE_VERSION,
          nonce,
          issuedAt: Date.now(),
          stateDigest,
          base: { sequence: known.sequence, headHash: known.headHash },
          records: rows.map((r) => r.record),
          checkpoint,
        }),
      );
      accepted = verifiedLease(response, {
        nonce,
        authorityKeyId: checkpoint.keyId,
        stateDigest,
        sequence: checkpoint.payload.sequence,
        headHash: checkpoint.payload.headHash,
      });
      known = { sequence: accepted.sequence, headHash: accepted.headHash };
    }
    return accepted;
  }
  return {
    state: 'QUARANTINED',
    reason: 'RECOVERY_NOT_VALIDATED',
    mode: anchorQuery ? 'incremental' : 'full-chain',
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
      try {
        const stateDigest = authorizationDigest(authority);
        lease = anchorQuery
          ? await incremental(authority, stateDigest)
          : await fullChain(authority, stateDigest);
        this.state = 'VALIDATED';
        this.reason = null;
        if (!this.allows(authority)) throw new Error('AUTHORITY_CHANGED_DURING_RECOVERY');
      } catch (error) {
        this.state = 'QUARANTINED';
        this.reason = error.message;
        lease = null;
        known = null;
        throw Object.assign(new Error('Recovery trust is unavailable or inconsistent'), {
          status: 503,
          code: 'RECOVERY_QUARANTINED',
        });
      }
    },
  };
}
function postJson(url, tls, request) {
  return requestBytes(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: canonical(request),
    tls,
    maxBytes: 32768,
    timeoutMs: 5000,
  }).then((result) => {
    if (result.status !== 200) throw new Error('CUSTODIAN_REJECTED');
    return JSON.parse(result.body);
  });
}
/** Full-chain (version 1) or range (version 2) checkpoint exchange over mTLS. */
export function remoteCustodyExchange(url, tls) {
  if (!tls || new URL(url).protocol !== 'https:')
    throw new Error('Custody requires authenticated TLS');
  return (request) => postJson(url, tls, request);
}
/**
 * Anchor query over mTLS. `checkpointUrl` is the `/v1/checkpoints` URL; the anchor endpoint is
 * its sibling `/v1/anchor`, so one configured URL selects one custodian for both calls.
 */
export function remoteAnchorQuery(checkpointUrl, tls) {
  const url = new URL('anchor', checkpointUrl);
  if (!tls || url.protocol !== 'https:') throw new Error('Custody requires authenticated TLS');
  return (request) => postJson(url.href, tls, request);
}
