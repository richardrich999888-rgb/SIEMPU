// Pure decision logic (services/evidence/incremental.mjs) and range verification
// (apps/verifier/verify.mjs verifyEvidenceRange) for incremental custody, ADR-014.
// No services, no SQLite: chains are built in memory with an ephemeral key.
import test from 'node:test';
import assert from 'node:assert/strict';
import { pair } from './helpers/client.mjs';
import { canonical, hash, packet } from '../services/control/primitives.mjs';
import { verifyEvidence, verifyEvidenceRange } from '../apps/verifier/verify.mjs';
import {
  GENESIS,
  DELTA_MAX_RECORDS,
  CustodyError,
  anchorFromAnswer,
  checkAnchorTransition,
  isPosition,
  leaseMatches,
  planRanges,
  validateAnchorQuery,
  validateRangeRequest,
} from '../services/evidence/incremental.mjs';

const T0 = 1_700_000_000_000;
const D1 = 'a'.repeat(64);
const D2 = 'b'.repeat(64);

/** Builds a signed chain of `n` records with deterministic content (timestamps fixed). */
function chain(key, n, { from = { sequence: 0, headHash: GENESIS }, tag = 'E' } = {}) {
  const records = [];
  let previousHash = from.headHash;
  for (let i = 1; i <= n; i++) {
    const sequence = from.sequence + i;
    const rec = packet(key, {
      sequence,
      previousHash,
      eventId: `${tag}-${sequence}`,
      eventType: 'TEST_EVENT',
      timestamp: T0 + sequence,
      epoch: 1,
      actorId: 'system',
    });
    records.push(rec);
    previousHash = hash(canonical(rec));
  }
  return records;
}
const headOf = (records, base = { sequence: 0, headHash: GENESIS }) =>
  records.length
    ? { sequence: records.at(-1).payload.sequence, headHash: hash(canonical(records.at(-1))) }
    : base;
const cp = (key, head) => packet(key, { ...head, issuedAt: T0 });
const code = (re) => (error) => error instanceof CustodyError && re.test(error.code);

// ---------------------------------------------------------------- verifyEvidenceRange

test('range: extends a verified prefix and agrees with full-chain verification', async () => {
  const { privateKey, publicKey } = pair();
  const all = chain(privateKey, 12);
  const base = headOf(all.slice(0, 7));
  const range = verifyEvidenceRange(
    { base, records: all.slice(7), checkpoint: cp(privateKey, headOf(all)) },
    publicKey,
  );
  const full = await verifyEvidence(
    { records: all, checkpoint: cp(privateKey, headOf(all)) },
    publicKey,
  );
  assert.equal(range.type, 'evidence-range');
  assert.equal(range.fromSequence, 7);
  assert.equal(range.toSequence, 12);
  assert.equal(range.records, 5);
  assert.equal(range.headHash, full.headHash);
});

test('range: empty range re-attests an unchanged head; genesis base covers a whole chain', () => {
  const { privateKey, publicKey } = pair();
  const all = chain(privateKey, 3);
  const head = headOf(all);
  assert.equal(
    verifyEvidenceRange({ base: head, records: [], checkpoint: cp(privateKey, head) }, publicKey)
      .toSequence,
    3,
  );
  assert.equal(
    verifyEvidenceRange(
      { base: { sequence: 0, headHash: GENESIS }, records: all, checkpoint: cp(privateKey, head) },
      publicKey,
    ).headHash,
    head.headHash,
  );
});

test('range rejects gap, reorder, fork, tamper, foreign key and head mismatch', () => {
  const { privateKey, publicKey } = pair();
  const all = chain(privateKey, 6);
  const base = headOf(all.slice(0, 2));
  const tail = all.slice(2);
  const ok = cp(privateKey, headOf(all));
  const run = (records, checkpoint = ok, b = base) =>
    verifyEvidenceRange({ base: b, records, checkpoint }, publicKey);
  // Gap: record 3 missing.
  assert.throws(() => run(tail.slice(1)), /Sequence discontinuity at record 3/);
  // Reorder: 4 before 3.
  assert.throws(
    () => run([tail[1], tail[0], ...tail.slice(2)]),
    /Sequence discontinuity at record 3/,
  );
  // Fork: a validly signed alternative history from the same base position but a different
  // predecessor (built on a different record 2).
  const fork = chain(privateKey, 4, {
    from: { sequence: 2, headHash: 'c'.repeat(64) },
    tag: 'F',
  });
  assert.throws(
    () => run(fork, cp(privateKey, headOf(fork))),
    /Previous hash mismatch at record 3/,
  );
  // Tamper: payload changed after signing.
  const tampered = structuredClone(tail);
  tampered[1].payload.eventType = 'ALTERED';
  assert.throws(() => run(tampered), /Signature invalid/);
  // Records signed by another key.
  const other = pair();
  assert.throws(() => run(chain(other.privateKey, 4, { from: base })), /Signing key ID mismatch/);
  // Checkpoint names a different head than the records produce.
  assert.throws(
    () => run(tail, cp(privateKey, { sequence: 6, headHash: 'd'.repeat(64) })),
    /Range checkpoint does not match range head/,
  );
  assert.throws(() => run(tail.slice(0, 3), ok), /Range checkpoint does not match range head/);
});

test('range rejects malformed base, members and oversize input (fail closed)', () => {
  const { privateKey, publicKey } = pair();
  const all = chain(privateKey, 2);
  const checkpoint = cp(privateKey, headOf(all));
  const zero = { sequence: 0, headHash: GENESIS };
  const run = (input, options) => verifyEvidenceRange(input, publicKey, options);
  assert.throws(
    () => run({ base: zero, records: all, checkpoint, extra: 1 }),
    /Unexpected or missing/,
  );
  assert.throws(
    () => run({ base: { ...zero, x: 1 }, records: all, checkpoint }),
    /Unexpected or missing/,
  );
  assert.throws(
    () => run({ base: { sequence: 0, headHash: D1 }, records: all, checkpoint }),
    /Inconsistent range base genesis reference/,
  );
  assert.throws(
    () => run({ base: { sequence: 1, headHash: GENESIS }, records: all, checkpoint }),
    /Inconsistent range base genesis reference/,
  );
  assert.throws(
    () => run({ base: { sequence: -1, headHash: D1 }, records: all, checkpoint }),
    /Invalid range base sequence/,
  );
  assert.throws(
    () => run({ base: { sequence: 1, headHash: 'A'.repeat(64) }, records: all, checkpoint }),
    /Invalid range base hash/,
  );
  assert.throws(() => run({ base: zero, records: {}, checkpoint }), /must be an array/);
  assert.throws(
    () => run({ base: zero, records: all, checkpoint }, { maxRecords: 1 }),
    /exceeds record limit/,
  );
});

// ---------------------------------------------------------------- checkAnchorTransition

const at = (sequence, headHash) => ({ sequence, headHash });

test('anchor transition: extension and unchanged re-attestation are accepted', () => {
  const saved = { sequence: 5, headHash: D1, state: D2 };
  checkAnchorTransition(saved, { base: at(5, D1), head: at(9, D2), stateDigest: D1 }, false);
  checkAnchorTransition(saved, { base: at(5, D1), head: at(5, D1), stateDigest: D2 }, false);
});

test('anchor transition: rollback, fork/stale base and silent state change are rejected', () => {
  const saved = { sequence: 5, headHash: D1, state: D2 };
  // Rollback: presented head is older than the retained anchor.
  assert.throws(
    () =>
      checkAnchorTransition(saved, { base: at(2, D2), head: at(4, D2), stateDigest: D2 }, false),
    code(/^RECOVERY_ROLLBACK_OR_FORK$/),
  );
  // Stale base (replayed earlier increment) and forked base (same position, other hash).
  assert.throws(
    () =>
      checkAnchorTransition(saved, { base: at(3, D2), head: at(8, D2), stateDigest: D2 }, false),
    code(/^CHECKPOINT_BASE_MISMATCH$/),
  );
  assert.throws(
    () =>
      checkAnchorTransition(saved, { base: at(5, D2), head: at(8, D2), stateDigest: D2 }, false),
    code(/^CHECKPOINT_BASE_MISMATCH$/),
  );
  // Base ahead of the anchor (records the custodian never verified).
  assert.throws(
    () =>
      checkAnchorTransition(saved, { base: at(6, D2), head: at(8, D2), stateDigest: D2 }, false),
    code(/^CHECKPOINT_BASE_MISMATCH$/),
  );
  // Same head, different authorization state: state changed without evidence.
  assert.throws(
    () =>
      checkAnchorTransition(saved, { base: at(5, D1), head: at(5, D1), stateDigest: D1 }, false),
    code(/^RECOVERY_ROLLBACK_OR_FORK$/),
  );
});

test('anchor transition: bootstrap only when allowed and only from genesis', () => {
  const genesis = at(0, GENESIS);
  checkAnchorTransition(null, { base: genesis, head: at(3, D1), stateDigest: D2 }, true);
  assert.throws(
    () => checkAnchorTransition(null, { base: genesis, head: at(3, D1), stateDigest: D2 }, false),
    code(/^CHECKPOINT_ANCHOR_MISSING$/),
  );
  assert.throws(
    () => checkAnchorTransition(null, { base: at(2, D1), head: at(3, D1), stateDigest: D2 }, true),
    code(/^CHECKPOINT_BASE_MISMATCH$/),
  );
});

// ---------------------------------------------------------------- planRanges

test('planRanges: bounded, contiguous, covering; empty catch-up re-attests', () => {
  assert.deepEqual(planRanges(7, 7), [{ after: 7, until: 7 }]);
  assert.deepEqual(planRanges(0, 3, 2), [
    { after: 0, until: 2 },
    { after: 2, until: 3 },
  ]);
  assert.deepEqual(planRanges(10, 14, 2), [
    { after: 10, until: 12 },
    { after: 12, until: 14 },
  ]);
  const ranges = planRanges(0, 1300);
  assert.equal(ranges.length, Math.ceil(1300 / DELTA_MAX_RECORDS));
  assert.ok(ranges.every((r) => r.until - r.after <= DELTA_MAX_RECORDS));
  assert.ok(ranges.every((r, i) => i === 0 || r.after === ranges[i - 1].until));
  assert.equal(ranges.at(-1).until, 1300);
});

test('planRanges: rollback and invalid bounds fail', () => {
  assert.throws(() => planRanges(5, 4), code(/^RECOVERY_ROLLBACK_OR_FORK$/));
  assert.throws(() => planRanges(-1, 4), RangeError);
  assert.throws(() => planRanges(0, 1.5), RangeError);
  assert.throws(() => planRanges(0, 4, 0), RangeError);
});

// ---------------------------------------------------------------- message validation

const goodRequest = () => ({
  version: 2,
  nonce: 'n-1',
  issuedAt: T0,
  stateDigest: D1,
  base: at(0, GENESIS),
  records: [],
  checkpoint: {},
});

test('range request validation: exact members, version, bounds and freshness', () => {
  validateRangeRequest(goodRequest(), T0, 30000);
  const bad = (patch, re = /^CHECKPOINT_REQUEST_INVALID$/) =>
    assert.throws(() => validateRangeRequest({ ...goodRequest(), ...patch }, T0, 30000), code(re));
  bad({ extra: true });
  bad({ version: 1 });
  bad({ version: 3 });
  bad({ nonce: '' });
  bad({ nonce: 'x'.repeat(129) });
  bad({ stateDigest: 'zz' });
  bad({ base: at(1, GENESIS) });
  bad({ records: 'none' });
  bad({ records: new Array(DELTA_MAX_RECORDS + 1).fill({}) });
  bad({ issuedAt: T0 - 30001 }, /^CHECKPOINT_REQUEST_STALE$/);
  bad({ issuedAt: T0 + 30001 }, /^CHECKPOINT_REQUEST_STALE$/);
  bad({ issuedAt: 1.5 }, /^CHECKPOINT_REQUEST_STALE$/);
});

test('position, lease and anchor-answer validation', () => {
  assert.equal(isPosition(at(0, GENESIS)), true);
  assert.equal(isPosition(at(3, D1)), true);
  assert.equal(isPosition(at(3, GENESIS)), false);
  assert.equal(isPosition({ ...at(3, D1), extra: 1 }), false);
  const expected = { nonce: 'n', authorityKeyId: D1, stateDigest: D2, sequence: 4, headHash: D1 };
  const lease = { version: 1, ...expected, issuedAt: T0, expiresAt: T0 + 30000 };
  assert.equal(leaseMatches(lease, expected, T0, 30000), true);
  for (const patch of [
    { version: 2 },
    { nonce: 'other' },
    { sequence: 3 },
    { headHash: D2 },
    { stateDigest: D1 },
    { expiresAt: T0 },
    { expiresAt: T0 + 30001 },
    { issuedAt: T0 + 1001 },
  ])
    assert.equal(
      leaseMatches({ ...lease, ...patch }, expected, T0, 30000),
      false,
      JSON.stringify(patch),
    );
  const answer = {
    version: 2,
    kind: 'ANCHOR',
    nonce: 'q',
    anchored: true,
    sequence: 4,
    headHash: D1,
    issuedAt: T0,
  };
  assert.deepEqual(anchorFromAnswer(answer, 'q', T0, 30000), at(4, D1));
  for (const patch of [
    { nonce: 'r' },
    { kind: 'LEASE' },
    { anchored: false },
    { sequence: 4, headHash: GENESIS },
    { issuedAt: T0 - 60000 },
    { extra: 1 },
  ])
    assert.throws(
      () => anchorFromAnswer({ ...answer, ...patch }, 'q', T0, 30000),
      code(/^CUSTODIAN_ANCHOR_INVALID$/),
      JSON.stringify(patch),
    );
  validateAnchorQuery({ version: 2, kind: 'ANCHOR_QUERY', nonce: 'q', issuedAt: T0 }, T0, 30000);
  assert.throws(
    () => validateAnchorQuery({ version: 2, kind: 'ANCHOR', nonce: 'q', issuedAt: T0 }, T0, 30000),
    code(/^CHECKPOINT_REQUEST_INVALID$/),
  );
  assert.throws(
    () =>
      validateAnchorQuery({ version: 2, kind: 'ANCHOR_QUERY', nonce: 'q', issuedAt: 0 }, T0, 30000),
    code(/^CHECKPOINT_REQUEST_STALE$/),
  );
});
