// Incremental checkpoint custody (ADR-014, defect D-T5-01) against a real authority and
// custodian. Every negative case must fail closed: quarantine and no key issuance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { coreFixture } from './helpers/fixture.mjs';
import { pair, createObject } from './helpers/client.mjs';
import {
  CheckpointCustodian,
  authorityRange,
  authoritySnapshot,
  authorizationDigest,
  createRecoveryGuard,
} from '../services/evidence/custody.mjs';
import { GENESIS } from '../services/evidence/incremental.mjs';
import { packet } from '../services/control/primitives.mjs';
import { Authority } from '../services/control/core.mjs';

/** Custodian plus an instrumented in-process transport (records what was shipped). */
function custodyLab(f, { database = ':memory:', allowBootstrap = true, keys = pair() } = {}) {
  const custodian = new CheckpointCustodian({
    allowBootstrap,
    database,
    authorityKey: f.provisioned.serverPublicKey,
    signingKey: keys.privateKey,
  });
  const log = { requests: [], queries: 0, offline: false };
  const transport = {
    exchange: async (request) => {
      if (log.offline) throw new Error('OFFLINE');
      // Round-trip through JSON as the network would.
      const wire = JSON.parse(JSON.stringify(request));
      log.requests.push(wire);
      return custodian.accept(wire);
    },
    anchorQuery: async (request) => {
      if (log.offline) throw new Error('OFFLINE');
      log.queries++;
      return custodian.anchor(JSON.parse(JSON.stringify(request)));
    },
  };
  const guard = (options = {}) =>
    createRecoveryGuard({ custodianKey: keys.publicKey, ...transport, ...options });
  return { custodian, keys, log, transport, guard };
}
const shipped = (log) => log.requests.map((r) => r.payload.records?.length ?? 'full');
const head = (authority) => authority.checkpoint().payload;
const addEvents = (authority, n, type = 'TEST_EVENT') =>
  authority.tx(() => {
    for (let i = 0; i < n; i++) authority.event(type, null);
  });
/** Signed range request built directly (bypasses the guard) for protocol-level negatives. */
function rangeRequest(authority, { base, records, checkpoint, stateDigest, issuedAt, nonce }) {
  return packet(authority.key, {
    version: 2,
    nonce: nonce ?? crypto.randomUUID(),
    issuedAt: issuedAt ?? Date.now(),
    stateDigest: stateDigest ?? authorizationDigest(authority),
    base,
    records,
    checkpoint: checkpoint ?? authority.checkpoint(),
  });
}

test('incremental guard bootstraps from genesis, then ships only new records per request', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  const guard = lab.guard();
  assert.equal(guard.mode, 'incremental');
  f.authority.recoveryGuard = guard;
  const start = head(f.authority).sequence;
  await guard.authorize(f.authority);
  assert.equal(lab.log.queries, 1);
  assert.deepEqual(shipped(lab.log), [start]); // bootstrap: genesis..head once
  assert.equal(guard.allows(f.authority), true);

  // Grow the chain well beyond any per-request bound; subsequent authorisations ship deltas.
  addEvents(f.authority, 300);
  lab.log.requests.length = 0;
  await guard.authorize(f.authority);
  await guard.authorize(f.authority);
  assert.deepEqual(shipped(lab.log), [300, 0]);
  assert.equal(lab.log.queries, 1, 'anchor is tracked from leases, not re-queried');

  // Real requests through dispatch: each authorisation carries only that request's evidence.
  await f.clients.admin.authenticate();
  await f.clients.alice.authenticate();
  const before = lab.log.requests.length;
  await f.clients.alice.grant();
  const deltas = lab.log.requests.slice(before).map((r) => r.payload.records.length);
  assert.ok(deltas.length >= 2 && deltas.every((n) => n <= 5), JSON.stringify(deltas));
});

test('rollback after revocation is quarantined: stale snapshot cannot extend the anchor', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f, { database: join(f.dir, 'custody.sqlite') });
  t.after(() => lab.custodian.close());
  f.authority.recoveryGuard = lab.guard();
  await f.clients.admin.authenticate();
  await f.clients.alice.authenticate();
  await f.clients.bob.authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  await f.clients.alice.submit(object);
  await f.clients.alice.prepare(object.envelope.objectId);
  const snapshot = join(f.dir, 'rollback.sqlite');
  f.authority.db.prepare('VACUUM INTO ?').run(snapshot);
  const revoked = await f.clients.admin.admin(
    'POST',
    '/api/admin/devices/' + f.profiles.alice.deviceId + '/revoke',
    {},
  );
  assert.equal(revoked.status, 200, JSON.stringify(revoked));

  const stale = new Authority({
    dbPath: snapshot,
    signingKey: f.authority.key,
    masterKey: f.authority.masterKey,
    relay: f.authority.relay,
    recoveryGuard: lab.guard(), // fresh guard: learns the anchor from the custodian
  });
  t.after(() => stale.close());
  await assert.rejects(stale.recoveryGuard.authorize(stale), /Recovery trust/);
  assert.equal(stale.recoveryGuard.state, 'QUARANTINED');
  assert.equal(stale.recoveryGuard.reason, 'RECOVERY_ROLLBACK_OR_FORK');
  assert.equal(stale.get('SELECT count(*) n FROM issuances').n, 0);
  const claim = await stale
    .dispatch('GET', '/api/control', {}, f.clients.bob.token)
    .catch((error) => error);
  assert.equal(claim.status, 503);
  // The genuine authority continues incrementally.
  await f.authority.recoveryGuard.authorize(f.authority);
  assert.equal(f.authority.recoveryGuard.allows(f.authority), true);
});

test('fork: a validly signed divergent history from an older snapshot is rejected', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f, { database: join(f.dir, 'custody.sqlite') });
  t.after(() => lab.custodian.close());
  const guard = lab.guard();
  await guard.authorize(f.authority);
  const snapshot = join(f.dir, 'fork.sqlite');
  f.authority.db.prepare('VACUUM INTO ?').run(snapshot);
  addEvents(f.authority, 5, 'GENUINE');
  await guard.authorize(f.authority);
  // The forked copy appends *more* records than the genuine chain, so it is not a rollback by
  // length: only the hash linkage to the anchor can expose it.
  const forked = new Authority({
    dbPath: snapshot,
    signingKey: f.authority.key,
    masterKey: f.authority.masterKey,
    relay: f.authority.relay,
  });
  t.after(() => forked.close());
  addEvents(forked, 9, 'FORKED');
  const forkGuard = lab.guard();
  await assert.rejects(forkGuard.authorize(forked), /Recovery trust/);
  assert.match(forkGuard.reason, /Previous hash mismatch|BASE_MISMATCH|ROLLBACK_OR_FORK/);
  assert.equal(forkGuard.allows(forked), false);
  // Anchor unchanged: the genuine authority still extends it.
  addEvents(f.authority, 1, 'GENUINE');
  await guard.authorize(f.authority);
  assert.equal(guard.allows(f.authority), true);
});

test('gap, reorder, tamper and over-limit ranges are rejected; anchor does not move', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  const guard = lab.guard();
  await guard.authorize(f.authority);
  const anchored = { sequence: head(f.authority).sequence, headHash: head(f.authority).headHash };
  addEvents(f.authority, 4);
  const delta = authorityRange(f.authority, anchored.sequence, head(f.authority).sequence).map(
    (r) => r.record,
  );
  const send = (records, extra = {}) =>
    lab.custodian.accept(rangeRequest(f.authority, { base: anchored, records, ...extra }));
  await assert.rejects(send([delta[0], delta[2], delta[3]]), /Sequence discontinuity/); // gap
  await assert.rejects(send([delta[1], delta[0], delta[2], delta[3]]), /Sequence discontinuity/);
  const tampered = structuredClone(delta);
  tampered[2].payload.eventType = 'ALTERED';
  await assert.rejects(send(tampered), /Signature invalid/);
  await assert.rejects(send(delta.slice(0, 3)), /Range checkpoint does not match/); // truncated
  await assert.rejects(
    send(new Array(513).fill(delta[0])),
    /CHECKPOINT_REQUEST_INVALID/,
    'over the per-request bound',
  );
  await assert.rejects(
    lab.custodian.accept(
      packet(f.authority.key, {
        ...rangeRequest(f.authority, { base: anchored, records: delta }).payload,
        extra: 1,
      }),
    ),
    /CHECKPOINT_REQUEST_INVALID/,
  );
  await assert.rejects(
    lab.custodian.accept(packet(f.authority.key, { version: 9, nonce: 'n' })),
    /CHECKPOINT_VERSION/,
  );
  await assert.rejects(
    lab.custodian.accept(
      packet(
        pair().privateKey,
        rangeRequest(f.authority, { base: anchored, records: delta }).payload,
      ),
    ),
    /CHECKPOINT_SIGNATURE/,
  );
  await assert.rejects(send(delta, { issuedAt: 0 }), /CHECKPOINT_REQUEST_STALE/);
  // None of the rejections advanced the anchor; the genuine range is still accepted.
  const lease = await send(delta);
  assert.equal(lease.payload.sequence, anchored.sequence + 4);
});

test('replayed increment and stale base after the anchor advanced are rejected', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  const guard = lab.guard();
  await guard.authorize(f.authority);
  addEvents(f.authority, 2);
  await guard.authorize(f.authority);
  const replay = lab.log.requests.at(-1); // a genuine, still-fresh, authority-signed request
  addEvents(f.authority, 2);
  await guard.authorize(f.authority);
  await assert.rejects(lab.custodian.accept(replay), /RECOVERY_ROLLBACK_OR_FORK|BASE_MISMATCH/);
  // A request built on the genesis base once an anchor exists (not a bootstrap any more).
  const genesis = { sequence: 0, headHash: GENESIS };
  await assert.rejects(
    lab.custodian.accept(
      rangeRequest(f.authority, {
        base: genesis,
        records: authorityRange(f.authority, 0, head(f.authority).sequence).map((r) => r.record),
      }),
    ),
    /CHECKPOINT_BASE_MISMATCH/,
  );
});

test('authorization state changed without a chain event is detected on the unchanged head', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  const guard = lab.guard();
  await guard.authorize(f.authority);
  f.authority.run('UPDATE users SET active=0 WHERE id=?', f.profiles.alice.userId);
  assert.equal(guard.allows(f.authority), false);
  await assert.rejects(guard.authorize(f.authority), /Recovery trust/);
  assert.equal(guard.reason, 'RECOVERY_ROLLBACK_OR_FORK');
});

test('missing local record (storage hole) quarantines instead of shipping a short chain', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  const guard = lab.guard();
  await guard.authorize(f.authority);
  addEvents(f.authority, 3);
  const victim = head(f.authority).sequence - 1;
  f.authority.run('DELETE FROM evidence WHERE sequence=?', victim);
  await assert.rejects(guard.authorize(f.authority), /Recovery trust/);
  assert.equal(guard.reason, 'AUTHORITY_EVIDENCE_GAP');
});

test('long catch-up is split into bounded requests; restart of either side resumes incrementally', async (t) => {
  const f = await coreFixture(t);
  const database = join(f.dir, 'custody.sqlite');
  const keys = pair();
  let lab = custodyLab(f, { database, keys });
  addEvents(f.authority, 1300);
  const guard = lab.guard({ maxDeltaRecords: 512 });
  await guard.authorize(f.authority);
  const n = head(f.authority).sequence;
  assert.deepEqual(shipped(lab.log), [512, 512, n - 1024]);
  assert.equal(guard.allows(f.authority), true);

  // Custodian restart: durable anchor survives; a new guard (authority restart) learns it once.
  lab.custodian.close();
  lab = custodyLab(f, { database, keys, allowBootstrap: false });
  t.after(() => lab.custodian.close());
  addEvents(f.authority, 3);
  const restarted = lab.guard();
  await restarted.authorize(f.authority);
  assert.equal(lab.log.queries, 1);
  assert.deepEqual(shipped(lab.log), [3]);
  assert.equal(restarted.allows(f.authority), true);
});

test('crash between batches leaves a valid intermediate anchor; the next attempt completes', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  addEvents(f.authority, 40);
  let calls = 0;
  const flaky = createRecoveryGuard({
    custodianKey: lab.keys.publicKey,
    anchorQuery: lab.transport.anchorQuery,
    exchange: async (request) => {
      if (++calls === 2) throw new Error('CONNECTION_RESET');
      return lab.transport.exchange(request);
    },
    maxDeltaRecords: 16,
  });
  await assert.rejects(flaky.authorize(f.authority), /Recovery trust/);
  assert.equal(flaky.state, 'QUARANTINED');
  const intermediate = lab.custodian.anchor(
    packet(f.authority.key, { version: 2, kind: 'ANCHOR_QUERY', nonce: 'n', issuedAt: Date.now() }),
  ).payload;
  assert.equal(intermediate.sequence, 16, 'first batch committed, second lost');
  await flaky.authorize(f.authority);
  assert.equal(flaky.allows(f.authority), true);
});

test('anchor answers are authenticated: wrong custodian key, wrong nonce, outage', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  const wrongKey = createRecoveryGuard({
    custodianKey: pair().publicKey,
    exchange: lab.transport.exchange,
    anchorQuery: lab.transport.anchorQuery,
  });
  await assert.rejects(wrongKey.authorize(f.authority), /Recovery trust/);
  assert.equal(wrongKey.reason, 'CUSTODIAN_SIGNATURE');
  let stored;
  const wrongNonce = lab.guard({
    anchorQuery: async (request) => {
      stored ??= await lab.custodian.anchor(request);
      return stored; // replays the first answer to a later query
    },
  });
  await wrongNonce.authorize(f.authority);
  f.authority.run('UPDATE users SET active=0 WHERE id=?', f.profiles.alice.userId);
  await assert.rejects(wrongNonce.authorize(f.authority)); // forgets anchor
  f.authority.run('UPDATE users SET active=1 WHERE id=?', f.profiles.alice.userId);
  await assert.rejects(wrongNonce.authorize(f.authority), /Recovery trust/);
  assert.equal(wrongNonce.reason, 'CUSTODIAN_ANCHOR_INVALID');
  const guard = lab.guard();
  lab.log.offline = true;
  await assert.rejects(guard.authorize(f.authority), /Recovery trust/);
  lab.log.offline = false;
  await guard.authorize(f.authority);
  assert.equal(guard.allows(f.authority), true);
});

test('v1 full-chain and v2 range requests interoperate on one anchor', async (t) => {
  const f = await coreFixture(t);
  const lab = custodyLab(f);
  t.after(() => lab.custodian.close());
  const full = createRecoveryGuard({
    custodianKey: lab.keys.publicKey,
    exchange: lab.transport.exchange,
  });
  assert.equal(full.mode, 'full-chain');
  await full.authorize(f.authority);
  addEvents(f.authority, 2);
  const inc = lab.guard();
  await inc.authorize(f.authority);
  assert.deepEqual(shipped(lab.log).slice(-1), [2]);
  addEvents(f.authority, 1);
  await full.authorize(f.authority);
  assert.equal(full.allows(f.authority), true);
  // A stale v1 export is still a rollback under the shared anchor.
  const old = authoritySnapshot(f.authority);
  addEvents(f.authority, 1);
  // The full-chain guard advanced the anchor behind the incremental guard: its tracked base is
  // stale, so it fails closed once, forgets the base, re-learns it and then succeeds.
  await assert.rejects(inc.authorize(f.authority), /Recovery trust/);
  assert.equal(inc.reason, 'CHECKPOINT_BASE_MISMATCH');
  await inc.authorize(f.authority);
  assert.equal(inc.allows(f.authority), true);
  await assert.rejects(
    lab.custodian.accept(
      packet(f.authority.key, {
        version: 1,
        nonce: 'x',
        issuedAt: Date.now(),
        stateDigest: authorizationDigest(f.authority),
        evidence: old,
      }),
    ),
    /ROLLBACK/,
  );
});
