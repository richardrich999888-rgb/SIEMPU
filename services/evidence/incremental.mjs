// Pure decision logic for incremental checkpoint custody (ADR-014). No IO, no clock, no
// randomness: every function takes its inputs explicitly so it can be tested in isolation.
//
// Model. The custodian retains one anchor A = (sequence, headHash, state) that it has verified
// earlier. A request proposes a base B, a range of signed records R and a head H. The custodian
// accepts only if B = A (the range starts exactly at the retained head) and R verifies as a
// contiguous extension of B ending at H (verifyEvidenceRange). By induction on accepted
// requests, the anchor is always the digest of a record in one verified, append-only chain, so
// verifying the increment alone gives the same rollback, fork, gap and reorder detection as
// re-verifying from genesis, at a cost proportional to |R| instead of H.sequence.

/** Head hash of the empty chain. */
export const GENESIS = '0'.repeat(64);

/**
 * Records sent per custody request. Bounded so a single request has a fixed worst-case size
 * (about 0.5 KiB per record, so about 256 KiB) far below the custodian's 16 MiB body limit;
 * longer catch-ups are split into several requests, each advancing the anchor.
 */
export const DELTA_MAX_RECORDS = 512;

/** Incremental protocol version carried in requests and anchor queries. */
export const RANGE_VERSION = 2;

const HEX64 = /^[a-f0-9]{64}$/;

/** Error carrying a stable custody reason code as its message. */
export class CustodyError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const fail = (code) => {
  throw new CustodyError(code);
};

/**
 * True when `value` is a plain object whose own member names are exactly `names`.
 * @param {unknown} value
 * @param {string[]} names
 */
export function exactMembers(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...names].sort();
  return actual.length === expected.length && actual.every((n, i) => n === expected[i]);
}

/**
 * Validates a chain position `{ sequence, headHash }`.
 * @param {unknown} value
 * @returns {value is { sequence: number, headHash: string }}
 */
export function isPosition(value) {
  return (
    exactMembers(value, ['sequence', 'headHash']) &&
    Number.isSafeInteger(value.sequence) &&
    value.sequence >= 0 &&
    typeof value.headHash === 'string' &&
    HEX64.test(value.headHash) &&
    (value.sequence === 0) === (value.headHash === GENESIS)
  );
}

/**
 * Checks request freshness: |now - issuedAt| must not exceed maxAgeMs.
 * @param {unknown} issuedAt
 * @param {number} now
 * @param {number} maxAgeMs
 */
export function isFresh(issuedAt, now, maxAgeMs) {
  return Number.isSafeInteger(issuedAt) && Math.abs(now - issuedAt) <= maxAgeMs;
}

/**
 * Validates the shape of a version-2 (range) checkpoint request payload. Signature and
 * record verification happen elsewhere; this rejects unknown or missing members fail-closed.
 * @param {unknown} p
 * @param {number} now
 * @param {number} maxAgeMs
 */
export function validateRangeRequest(p, now, maxAgeMs) {
  if (
    !exactMembers(p, [
      'version',
      'nonce',
      'issuedAt',
      'stateDigest',
      'base',
      'records',
      'checkpoint',
    ]) ||
    p.version !== RANGE_VERSION ||
    typeof p.nonce !== 'string' ||
    p.nonce.length === 0 ||
    p.nonce.length > 128 ||
    typeof p.stateDigest !== 'string' ||
    !HEX64.test(p.stateDigest) ||
    !isPosition(p.base) ||
    !Array.isArray(p.records) ||
    p.records.length > DELTA_MAX_RECORDS
  )
    fail('CHECKPOINT_REQUEST_INVALID');
  if (!isFresh(p.issuedAt, now, maxAgeMs)) fail('CHECKPOINT_REQUEST_STALE');
}

/**
 * Decides whether a verified range may move the retained anchor. Throws a CustodyError with
 * a stable code when it may not. The order of checks is part of the contract.
 *
 * - No anchor: only an explicit bootstrap from genesis is accepted.
 * - head below anchor: rollback (an older chain state is being presented).
 * - base differs from anchor: the range does not start at the retained head (fork, stale
 *   authority view, or replay of an old increment).
 * - head equal to anchor: the chain did not move, so the authorization state must not have
 *   moved either (state change without evidence) and the head must be identical.
 * @param {{ sequence: number, headHash: string, state: string } | null} saved retained anchor
 * @param {{ base: { sequence: number, headHash: string },
 *           head: { sequence: number, headHash: string },
 *           stateDigest: string }} proposal verified range summary
 * @param {boolean} allowBootstrap
 */
export function checkAnchorTransition(saved, proposal, allowBootstrap) {
  const { base, head, stateDigest } = proposal;
  if (!saved) {
    if (!allowBootstrap) fail('CHECKPOINT_ANCHOR_MISSING');
    if (base.sequence !== 0) fail('CHECKPOINT_BASE_MISMATCH');
    return;
  }
  if (head.sequence < saved.sequence) fail('RECOVERY_ROLLBACK_OR_FORK');
  if (base.sequence !== saved.sequence || base.headHash !== saved.headHash)
    fail('CHECKPOINT_BASE_MISMATCH');
  if (
    head.sequence === saved.sequence &&
    (head.headHash !== saved.headHash || stateDigest !== saved.state)
  )
    fail('RECOVERY_ROLLBACK_OR_FORK');
}

/**
 * Splits catching up from `from` to `to` into bounded requests.
 * Returns the half-open ranges (after, until] in order; an empty catch-up yields one empty
 * range so the unchanged head (and state) is still re-attested.
 * @param {number} from sequence already anchored
 * @param {number} to sequence of the current head
 * @param {number} [max]
 * @returns {{ after: number, until: number }[]}
 */
export function planRanges(from, to, max = DELTA_MAX_RECORDS) {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to < 0)
    throw new RangeError('Invalid range bounds');
  if (!Number.isSafeInteger(max) || max <= 0) throw new RangeError('Invalid range size');
  if (to < from) fail('RECOVERY_ROLLBACK_OR_FORK');
  if (to === from) return [{ after: from, until: to }];
  const ranges = [];
  for (let after = from; after < to; after += max)
    ranges.push({ after, until: Math.min(after + max, to) });
  return ranges;
}

/**
 * Validates a custodian lease against the request it answers. Shared by protocol versions 1
 * and 2: the lease format is unchanged (version 1).
 * @param {any} p lease payload (already signature-verified)
 * @param {{ nonce: string, authorityKeyId: string, stateDigest: string,
 *           sequence: number, headHash: string }} expected
 * @param {number} now
 * @param {number} maxAgeMs
 */
export function leaseMatches(p, expected, now, maxAgeMs) {
  return (
    p?.version === 1 &&
    p.nonce === expected.nonce &&
    p.authorityKeyId === expected.authorityKeyId &&
    p.stateDigest === expected.stateDigest &&
    p.sequence === expected.sequence &&
    p.headHash === expected.headHash &&
    Number.isSafeInteger(p.issuedAt) &&
    Number.isSafeInteger(p.expiresAt) &&
    p.issuedAt <= now + 1000 &&
    now - p.issuedAt <= maxAgeMs &&
    p.expiresAt > now &&
    p.expiresAt - p.issuedAt <= maxAgeMs
  );
}

/**
 * Validates an anchor-query request payload `{ version, kind, nonce, issuedAt }`.
 * @param {unknown} p
 * @param {number} now
 * @param {number} maxAgeMs
 */
export function validateAnchorQuery(p, now, maxAgeMs) {
  if (
    !exactMembers(p, ['version', 'kind', 'nonce', 'issuedAt']) ||
    p.version !== RANGE_VERSION ||
    p.kind !== 'ANCHOR_QUERY' ||
    typeof p.nonce !== 'string' ||
    p.nonce.length === 0 ||
    p.nonce.length > 128
  )
    fail('CHECKPOINT_REQUEST_INVALID');
  if (!isFresh(p.issuedAt, now, maxAgeMs)) fail('CHECKPOINT_REQUEST_STALE');
}

/**
 * Validates a signed anchor answer against the query nonce and returns the anchored position.
 * @param {any} p answer payload (already signature-verified)
 * @param {string} nonce
 * @param {number} now
 * @param {number} maxAgeMs
 * @returns {{ sequence: number, headHash: string }}
 */
export function anchorFromAnswer(p, nonce, now, maxAgeMs) {
  if (
    !exactMembers(p, [
      'version',
      'kind',
      'nonce',
      'anchored',
      'sequence',
      'headHash',
      'issuedAt',
    ]) ||
    p.version !== RANGE_VERSION ||
    p.kind !== 'ANCHOR' ||
    p.nonce !== nonce ||
    typeof p.anchored !== 'boolean' ||
    !isPosition({ sequence: p.sequence, headHash: p.headHash }) ||
    (!p.anchored && p.sequence !== 0) ||
    !isFresh(p.issuedAt, now, maxAgeMs)
  )
    fail('CUSTODIAN_ANCHOR_INVALID');
  return { sequence: p.sequence, headHash: p.headHash };
}
