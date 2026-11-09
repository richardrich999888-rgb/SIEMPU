import { authorizationDigest, assertAuthorizationCommit } from './authorization-state.mjs';
export { authorizationDigest } from './authorization-state.mjs';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { verifyEvidence, verifyEvidenceRange } from '../../apps/verifier/verify.mjs';
import { canonical, hash, packet, verifyPacket } from '../control/primitives.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import {
  FENCED_CUSTODY_VERSION,
  normalizeWriter,
  fencedRequest,
  validateFencedRequest,
  checkWriterFence,
  unwrapFencedLease,
  validateWriterPublicKey,
  validateAuthorityFloor,
  validGeneration,
} from './fencing.mjs';
import { keyId } from '../control/primitives.mjs';
import {
  DELTA_MAX_RECORDS,
  exactMembers,
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
export class CheckpointCustodian {
  constructor({
    database,
    authorityKey,
    signingKey,
    maxAgeMs = 30000,
    allowBootstrap = false,
    requireFencing = false,
  }) {
    if (typeof requireFencing !== 'boolean') throw new TypeError('requireFencing must be boolean');
    this.requireFencing = requireFencing;
    this.allowBootstrap = allowBootstrap;
    this.key = signingKey;
    this.authorityKey = authorityKey;
    this.maxAgeMs = maxAgeMs;
    this.db = new DatabaseSync(database);
    this.db.exec(
      'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS anchor(id INTEGER PRIMARY KEY CHECK(id=1), checkpoint TEXT NOT NULL, state TEXT NOT NULL);',
    );
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS writer_fence(id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, public_key TEXT NOT NULL, epoch INTEGER NOT NULL, revocation_version INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS fence_history(generation INTEGER PRIMARY KEY, receipt TEXT NOT NULL);',
    );
  }
  /**
   * Accepts a signed checkpoint request and returns a signed lease, or throws.
   * Version 1 carries the whole chain (verified from genesis); version 2 carries only the
   * records after the retained anchor (ADR-014). Both share one anchor table and lease format.
   */
  async accept(request, now = Date.now()) {
    let context;
    const fence = this.db.prepare('SELECT * FROM writer_fence WHERE id=1').get();
    if (request?.payload?.version === FENCED_CUSTODY_VERSION) {
      context = validateFencedRequest(request, fence);
      request = request.payload.request;
    } else if (this.requireFencing || fence) throw new Error('FENCING_REQUIRED');
    if (!verifyPacket(this.authorityKey, request)) throw new Error('CHECKPOINT_SIGNATURE');
    const version = request.payload?.version;
    if (version === 1) return this.#acceptFull(request, now, context);
    if (version === RANGE_VERSION) return this.#acceptRange(request, now, context);
    throw new Error('CHECKPOINT_VERSION');
  }
  async #acceptFull(request, now, context) {
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
    return this.#anchor(request, cp, p.stateDigest, now, context, (old) => {
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
  async #acceptRange(request, now, context) {
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
      context,
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
    context,
    check,
    checkMissing = () => {
      if (!this.allowBootstrap) throw new Error('CHECKPOINT_ANCHOR_MISSING');
    },
  ) {
    const head = cp.payload;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      // Recheck after asynchronous signature verification, inside the SAME write transaction
      // as the retained checkpoint. A handover in between cannot authorize an old writer.
      const fence = this.db.prepare('SELECT * FROM writer_fence WHERE id=1').get();
      if (this.requireFencing || fence || context) checkWriterFence(fence, context);
      const old = this.db.prepare('SELECT * FROM anchor WHERE id=1').get();
      if (old) check(old);
      else checkMissing();
      this.db
        .prepare(
          'INSERT INTO anchor VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint,state=excluded.state',
        )
        .run(canonical(cp), stateDigest);
      if (context)
        this.db
          .prepare('UPDATE writer_fence SET epoch=?,revocation_version=? WHERE id=1')
          .run(context.authority.epoch, context.authority.revocationVersion);
      this.db.exec('COMMIT');
      this.allowBootstrap = false;
      const lease = packet(this.key, {
        version: 1,
        nonce: request.payload.nonce,
        authorityKeyId: request.keyId,
        sequence: head.sequence,
        headHash: head.headHash,
        stateDigest,
        issuedAt: now,
        expiresAt: now + this.maxAgeMs,
      });
      return context
        ? packet(this.key, {
            version: FENCED_CUSTODY_VERSION,
            kind: 'FENCED_LEASE',
            generation: context.generation,
            writerKeyId: context.writerKeyId,
            authority: context.authority,
            lease,
          })
        : lease;
    } catch (error) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      throw error;
    }
  }
  /** Local maintenance only: no HTTP route. Compare-and-swap a reviewed anchor and generation.
   * Zero initializes a newly reviewed fence; later handovers preserve both authority floors.
   * Ownership does not expire. The operator must retain the receipt outside this database.
   */
  transferWriter(options) {
    if (!exactMembers(options, ['writerKey', 'expectedGeneration', 'expectedAnchor', 'authority']))
      throw new Error('FENCE_HANDOVER_INVALID');
    const { writerKey, expectedGeneration, expectedAnchor, authority } = options;
    const publicKey = validateWriterPublicKey(writerKey);
    if ([keyId(this.authorityKey), keyId(this.key)].includes(keyId(publicKey)))
      throw new Error('FENCE_KEY_SEPARATION_REQUIRED');
    if (
      !Number.isSafeInteger(expectedGeneration) ||
      expectedGeneration < 0 ||
      expectedGeneration >= Number.MAX_SAFE_INTEGER
    )
      throw new Error('FENCE_GENERATION_INVALID');
    validateAuthorityFloor(authority);
    if (
      !exactMembers(expectedAnchor, ['headHash', 'sequence', 'stateDigest']) ||
      !Number.isSafeInteger(expectedAnchor.sequence) ||
      expectedAnchor.sequence < 0 ||
      !/^[a-f0-9]{64}$/.test(expectedAnchor.headHash) ||
      !/^[a-f0-9]{64}$/.test(expectedAnchor.stateDigest)
    )
      throw new Error('FENCE_ANCHOR_INVALID');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const old = this.db.prepare('SELECT * FROM writer_fence WHERE id=1').get();
      const anchor = this.db.prepare('SELECT * FROM anchor WHERE id=1').get();
      if (!anchor) throw new Error('CHECKPOINT_ANCHOR_MISSING');
      const cp = JSON.parse(anchor.checkpoint).payload;
      if (
        cp.sequence !== expectedAnchor.sequence ||
        cp.headHash !== expectedAnchor.headHash ||
        anchor.state !== expectedAnchor.stateDigest
      )
        throw new Error('FENCE_ANCHOR_CHANGED');
      if ((old?.generation ?? 0) !== expectedGeneration)
        throw new Error('FENCE_GENERATION_CHANGED');
      if (old && keyId(JSON.parse(old.public_key)) === keyId(publicKey))
        throw new Error('FENCE_NEW_WRITER_KEY_REQUIRED');
      if (
        old &&
        (authority.epoch !== old.epoch || authority.revocationVersion !== old.revocation_version)
      )
        throw new Error('FENCE_AUTHORITY_STATE_MISMATCH');
      const generation = expectedGeneration + 1;
      if (!validGeneration(generation)) throw new Error('FENCE_GENERATION_INVALID');
      const receipt = packet(this.key, {
        version: 1,
        kind: 'WRITER_HANDOVER',
        generation,
        writerKeyId: keyId(publicKey),
        previousWriterKeyId: old ? keyId(JSON.parse(old.public_key)) : null,
        anchor: expectedAnchor,
        authority,
        issuedAt: Date.now(),
      });
      this.db
        .prepare(
          'INSERT INTO writer_fence VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,public_key=excluded.public_key,epoch=excluded.epoch,revocation_version=excluded.revocation_version',
        )
        .run(generation, canonical(publicKey), authority.epoch, authority.revocationVersion);
      this.db.prepare('INSERT INTO fence_history VALUES(?,?)').run(generation, canonical(receipt));
      this.db.exec('COMMIT');
      this.requireFencing = true;
      return receipt;
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
 *           maxDeltaRecords?: number, writer?: { key: object, generation: number } }} options
 */
export function createRecoveryGuard({
  custodianKey,
  exchange,
  anchorQuery,
  maxAgeMs = 30000,
  maxDeltaRecords = DELTA_MAX_RECORDS,
  writer,
}) {
  const owner = writer === undefined ? null : normalizeWriter(writer);
  async function exchangeFor(authority, request) {
    if (!owner) return exchange(request);
    const response = await exchange(fencedRequest(owner, authority, request));
    return unwrapFencedLease(response, owner, custodianKey, authority);
  }
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
    const response = await exchangeFor(
      authority,
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
      const response = await exchangeFor(
        authority,
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
    fencing: owner ? 'EXPLICIT_WRITER_GENERATION' : 'NOT_CONFIGURED',
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
        assertAuthorizationCommit(authority);
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
