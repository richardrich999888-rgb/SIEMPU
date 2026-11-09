import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { coreFixture } from './helpers/fixture.mjs';
import { pair, createObject, ApiClient, coreTransport } from './helpers/client.mjs';
import { Authority } from '../services/control/core.mjs';
import { packet, verifyPacket, publicJwk } from '../services/control/primitives.mjs';
import {
  CheckpointCustodian,
  createRecoveryGuard,
  authoritySnapshot,
  authorizationDigest,
} from '../services/evidence/custody.mjs';
import { fencedRequest, normalizeWriter } from '../services/evidence/fencing.mjs';

function proposal(custody, writerKey, expectedGeneration) {
  const row = custody.db.prepare('SELECT * FROM anchor WHERE id=1').get();
  const cp = JSON.parse(row.checkpoint).payload;
  const floor = custody.db.prepare('SELECT * FROM writer_fence WHERE id=1').get();
  return {
    writerKey,
    expectedGeneration,
    expectedAnchor: { sequence: cp.sequence, headHash: cp.headHash, stateDigest: row.state },
    authority: { epoch: floor?.epoch ?? 1, revocationVersion: floor?.revocation_version ?? 0 },
  };
}
function fullRequest(authority) {
  return packet(authority.key, {
    version: 1,
    nonce: crypto.randomUUID(),
    issuedAt: Date.now(),
    stateDigest: authorizationDigest(authority),
    evidence: authoritySnapshot(authority),
  });
}
async function fixture(t, incremental = true) {
  const f = await coreFixture(t),
    keys = pair(),
    owner = pair();
  const config = {
    database: join(f.dir, 'custody.sqlite'),
    authorityKey: f.provisioned.serverPublicKey,
    signingKey: keys.privateKey,
    allowBootstrap: true,
  };
  const custody = new CheckpointCustodian(config);
  t.after(() => custody.close());
  await custody.accept(fullRequest(f.authority));
  const p = proposal(custody, owner.publicKey, 0),
    epoch = f.authority.epoch();
  p.authority = { epoch: epoch.epoch, revocationVersion: epoch.revocation_version };
  const receipt = custody.transferWriter(p);
  assert.ok(verifyPacket(keys.publicKey, receipt));
  const writer = { key: owner.privateKey, generation: 1 };
  const guard = (credential = writer, exchange = (r) => custody.accept(r)) =>
    createRecoveryGuard({
      writer: credential,
      custodianKey: keys.publicKey,
      exchange,
      ...(incremental ? { anchorQuery: (r) => custody.anchor(r) } : {}),
    });
  f.authority.recoveryGuard = guard();
  return { ...f, custody, config, keys, writer, guard };
}

for (const incremental of [false, true]) {
  const mode = incremental ? 'incremental' : 'full';
  test(`${mode}: only the nominated writer can use custody; no downgrade or automatic takeover`, async (t) => {
    const f = await fixture(t, incremental);
    await f.clients.alice.authenticate();
    assert.equal((await f.clients.alice.request('GET', '/api/control')).status, 200);
    await assert.rejects(f.custody.accept(fullRequest(f.authority)), /FENCING_REQUIRED/);
    for (const writer of [
      { key: pair().privateKey, generation: 1 },
      { key: f.writer.key, generation: 2 },
    ]) {
      f.authority.recoveryGuard = f.guard(writer);
      assert.equal((await f.clients.alice.request('GET', '/api/control')).status, 503);
      assert.equal(f.authority.recoveryGuard.reason, 'WRITER_FENCED');
    }
    f.authority.recoveryGuard = f.guard();
    assert.equal((await f.clients.alice.request('GET', '/api/control')).status, 200);
    assert.throws(() => f.guard({ ...f.writer, generation: 0 }), /FENCE_CONFIG_INVALID/);
    assert.throws(
      () => f.guard({ key: publicJwk(f.writer.key), generation: 1 }),
      /FENCE_PRIVATE_KEY/,
    );
  });

  test(`${mode}: lower policy epoch or revocation floor fails even with correctly signed new history`, async (t) => {
    const f = await fixture(t, incremental);
    f.authority.tx(() => {
      f.authority.run('UPDATE authority SET epoch=10,revocation_version=9 WHERE id=1');
      f.authority.event('TEST_FLOOR_ADVANCE', 'synthetic-test');
    });
    await f.authority.recoveryGuard.authorize(f.authority);
    const snapshot = join(f.dir, 'before-rollback.sqlite');
    f.authority.db.prepare('VACUUM INTO ?').run(snapshot);
    for (const [epoch, revocation] of [
      [9, 9],
      [10, 8],
    ]) {
      const stale = new Authority({
        dbPath: snapshot,
        signingKey: f.authority.key,
        masterKey: f.authority.masterKey,
        relay: f.authority.relay,
        recoveryGuard: f.guard(),
      });
      try {
        // Fault injection in a trusted transaction: a valid seal still cannot lower custody floors.
        stale.tx(() => {
          stale.run(
            'UPDATE authority SET epoch=?,revocation_version=? WHERE id=1',
            epoch,
            revocation,
          );
          stale.event('TEST_ROLLBACK_WITH_SIGNED_EVENT', 'synthetic-test');
        });
        await assert.rejects(stale.recoveryGuard.authorize(stale), /Recovery trust/);
        assert.equal(stale.recoveryGuard.reason, 'AUTHORITY_EPOCH_ROLLBACK');
        assert.equal(stale.get('SELECT count(*) n FROM issuances').n, 0);
      } finally {
        stale.close();
      }
    }
    assert.equal(f.custody.db.prepare('SELECT epoch FROM writer_fence').get().epoch, 10);
  });
}

test('handover compares current anchor and generation; interrupted write leaves prior owner intact', async (t) => {
  const f = await fixture(t),
    next = pair();
  const p = proposal(f.custody, next.publicKey, 1);
  assert.throws(() => f.custody.transferWriter({ ...p, extra: true }), /HANDOVER_INVALID/);
  assert.throws(
    () => f.custody.transferWriter({ ...p, writerKey: next.privateKey }),
    /PUBLIC_KEY_REQUIRED/,
  );
  assert.throws(
    () => f.custody.transferWriter({ ...p, writerKey: f.provisioned.serverPublicKey }),
    /KEY_SEPARATION_REQUIRED/,
  );
  assert.throws(
    () => f.custody.transferWriter({ ...p, writerKey: f.keys.publicKey }),
    /KEY_SEPARATION_REQUIRED/,
  );
  assert.throws(
    () => f.custody.transferWriter({ ...p, writerKey: publicJwk(f.writer.key) }),
    /NEW_WRITER_KEY_REQUIRED/,
  );
  assert.throws(
    () => f.custody.transferWriter({ ...p, expectedGeneration: 0 }),
    /GENERATION_CHANGED/,
  );
  assert.throws(
    () => f.custody.transferWriter({ ...p, authority: { epoch: 2, revocationVersion: 0 } }),
    /STATE_MISMATCH/,
  );
  assert.throws(
    () =>
      f.custody.transferWriter({
        ...p,
        expectedAnchor: { ...p.expectedAnchor, headHash: 'f'.repeat(64) },
      }),
    /ANCHOR_CHANGED/,
  );
  f.custody.db.exec(
    "CREATE TRIGGER simulate_disk_failure BEFORE INSERT ON fence_history BEGIN SELECT RAISE(ABORT, 'DISK_FAILURE'); END",
  );
  assert.throws(() => f.custody.transferWriter(p), /DISK_FAILURE/);
  assert.equal(f.custody.db.prepare('SELECT generation FROM writer_fence').get().generation, 1);
  await f.authority.recoveryGuard.authorize(f.authority);
  f.custody.db.exec('DROP TRIGGER simulate_disk_failure');
  const receipt = f.custody.transferWriter(p);
  assert.ok(verifyPacket(f.keys.publicKey, receipt));
  assert.equal(receipt.payload.generation, 2);
  await assert.rejects(f.authority.recoveryGuard.authorize(f.authority));
  f.authority.recoveryGuard = f.guard({ key: next.privateKey, generation: 2 });
  await f.authority.recoveryGuard.authorize(f.authority);
});

test('two independent processes contend for the same writer generation; exactly one commits', async (t) => {
  const f = await fixture(t),
    children = [];
  for (let i = 0; i < 2; i++) {
    const path = join(f.dir, `contender-${i}.json`);
    await writeFile(
      path,
      JSON.stringify({ custody: f.config, request: proposal(f.custody, pair().publicKey, 1) }),
      { mode: 0o600 },
    );
    const child = fork(new URL('./helpers/fence-worker.mjs', import.meta.url), [path], {
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    });
    t.after(() => {
      if (child.exitCode === null) child.kill();
    });
    const [ready] = await once(child, 'message');
    assert.deepEqual(ready, { ready: true });
    children.push(child);
  }
  const results = children.map((child) => once(child, 'message'));
  const exits = children.map((child) => once(child, 'exit'));
  for (const child of children) child.send({ go: true });
  const values = (await Promise.all(results)).map(([r]) => r);
  assert.deepEqual(values.map((r) => r.outcome).sort(), ['ACCEPTED', 'REJECTED']);
  assert.equal(values.find((r) => r.outcome === 'REJECTED').code, 'FENCE_GENERATION_CHANGED');
  assert.equal(f.custody.db.prepare('SELECT generation FROM writer_fence').get().generation, 2);
  for (const [code] of await Promise.all(exits)) assert.equal(code, 0);
});

test('handover during asynchronous full-history verification fences the old request at commit', async (t) => {
  const f = await fixture(t, false),
    next = pair();
  const pending = f.custody.accept(
    fencedRequest(normalizeWriter(f.writer), f.authority, fullRequest(f.authority)),
  );
  f.custody.transferWriter(proposal(f.custody, next.publicKey, 1));
  await assert.rejects(pending, /WRITER_FENCED/);
});

test('handover after local issuance prevents a key-bearing response; reviewed snapshot resumes', async (t) => {
  const f = await fixture(t),
    next = pair();
  for (const name of ['alice', 'bob']) await f.clients[name].authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  await f.clients.alice.submit(object);
  await f.clients.alice.prepare(object.envelope.objectId);
  const proof = await f.clients.bob.proof('claim:' + object.envelope.objectId, {
    expectedEpoch: f.authority.epoch().epoch,
  });
  let reviewedSnapshot;
  f.authority.recoveryGuard = f.guard(f.writer, async (r) => {
    // Dispatch: precheck -> consume proof -> pre-claim check -> local issuance -> final check.
    if (f.authority.get('SELECT count(*) n FROM issuances').n === 0) {
      const response = await f.custody.accept(r);
      if (f.authority.get('SELECT used FROM challenges WHERE id=?', proof.challengeId).used) {
        reviewedSnapshot = join(f.dir, 'anchored-before-issuance.sqlite');
        f.authority.db.prepare('VACUUM INTO ?').run(reviewedSnapshot);
      }
      return response;
    }
    f.custody.transferWriter(proposal(f.custody, next.publicKey, 1));
    return f.custody.accept(r);
  });
  const result = await f.clients.bob.request(
    'POST',
    `/api/objects/${object.envelope.objectId}/claim`,
    { expectedEpoch: f.authority.epoch().epoch, proof },
  );
  assert.equal(result.status, 503);
  assert.equal(result.body.code, 'RECOVERY_QUARANTINED');
  assert.equal(result.body.wrappedKey, undefined);
  // The unacknowledged local issuance is retained for reconciliation, not treated as delivered.
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 1);
  const recovered = new Authority({
    dbPath: reviewedSnapshot,
    signingKey: f.authority.key,
    masterKey: f.authority.masterKey,
    relay: f.authority.relay,
    recoveryGuard: f.guard({ key: next.privateKey, generation: 2 }),
  });
  t.after(() => recovered.close());
  const recipient = new ApiClient(coreTransport(recovered), f.profiles.bob);
  recipient.token = f.clients.bob.token;
  assert.equal(
    (await recipient.claim(object.envelope.objectId, recovered.epoch().epoch)).status,
    200,
  );
  assert.equal((await f.clients.bob.request('GET', '/api/control')).status, 503);
});

test('partition before and after local issuance fails closed; only a fresh successful custody check resumes release', async (t) => {
  const f = await fixture(t);
  for (const name of ['alice', 'bob']) await f.clients[name].authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  await f.clients.alice.submit(object);
  await f.clients.alice.prepare(object.envelope.objectId);
  f.authority.recoveryGuard = f.guard(f.writer, () => {
    throw new Error('PARTITION');
  });
  await assert.rejects(
    f.clients.bob.claim(object.envelope.objectId, f.authority.epoch().epoch),
    /503/,
  );
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
  f.authority.recoveryGuard = f.guard();
  const body = { expectedEpoch: f.authority.epoch().epoch };
  const proof = await f.clients.bob.proof('claim:' + object.envelope.objectId, body);
  f.authority.recoveryGuard = f.guard(f.writer, (r) => {
    if (f.authority.get('SELECT count(*) n FROM issuances').n) throw new Error('PARTITION');
    return f.custody.accept(r);
  });
  const denied = await f.clients.bob.request(
    'POST',
    `/api/objects/${object.envelope.objectId}/claim`,
    { ...body, proof },
  );
  assert.equal(denied.status, 503);
  assert.equal(denied.body.wrappedKey, undefined);
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 1);
  f.authority.recoveryGuard = f.guard();
  assert.equal(
    (await f.clients.bob.claim(object.envelope.objectId, body.expectedEpoch)).status,
    200,
  );
});

test('custodian restart preserves fencing, missing fence fails closed and malformed leases are rejected', async (t) => {
  const f = await fixture(t),
    restarted = new CheckpointCustodian({
      ...f.config,
      allowBootstrap: false,
      requireFencing: true,
    });
  t.after(() => restarted.close());
  f.authority.recoveryGuard = f.guard(f.writer, (r) => restarted.accept(r));
  await f.authority.recoveryGuard.authorize(f.authority);
  assert.equal(restarted.db.prepare('SELECT generation FROM writer_fence').get().generation, 1);
  f.authority.recoveryGuard = f.guard(f.writer, async (r) => {
    const good = await restarted.accept(r);
    return packet(f.keys.privateKey, { ...good.payload, generation: 99 });
  });
  await assert.rejects(f.authority.recoveryGuard.authorize(f.authority));
  assert.equal(f.authority.recoveryGuard.reason, 'FENCE_LEASE_INVALID');
  restarted.db.exec('DELETE FROM writer_fence');
  await assert.rejects(restarted.accept(fullRequest(f.authority)), /FENCING_REQUIRED/);
  f.authority.recoveryGuard = f.guard(f.writer, (r) => restarted.accept(r));
  await assert.rejects(f.authority.recoveryGuard.authorize(f.authority));
  assert.equal(f.authority.recoveryGuard.reason, 'FENCE_STATE_MISSING');
});
