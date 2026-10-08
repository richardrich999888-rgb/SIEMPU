import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { coreFixture } from './helpers/fixture.mjs';
import { pair, createObject, ApiClient, coreTransport } from './helpers/client.mjs';
import {
  CheckpointCustodian,
  createRecoveryGuard,
  authoritySnapshot,
  authorizationDigest,
} from '../services/evidence/custody.mjs';
import { packet } from '../services/control/primitives.mjs';
import { Authority } from '../services/control/core.mjs';

test('independent custody blocks rollback after revocation, fork, corruption and outage; resumes trusted current state', async (t) => {
  const f = await coreFixture(t),
    keys = pair();
  const custodian = new CheckpointCustodian({
    allowBootstrap: true,
    database: join(f.dir, 'custodian.sqlite'),
    authorityKey: f.provisioned.serverPublicKey,
    signingKey: keys.privateKey,
  });
  t.after(() => custodian.close());
  let unavailable = false;
  const makeGuard = () =>
    createRecoveryGuard({
      custodianKey: keys.publicKey,
      exchange: (req) => {
        if (unavailable) throw new Error('OFFLINE');
        return custodian.accept(req);
      },
    });
  f.authority.recoveryGuard = makeGuard();
  await f.clients.admin.authenticate();
  await f.clients.alice.authenticate();
  await f.clients.bob.authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  await f.clients.alice.submit(object);
  await f.clients.alice.prepare(object.envelope.objectId);
  const before = authoritySnapshot(f.authority),
    stateDigest = authorizationDigest(f.authority);
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
    recoveryGuard: makeGuard(),
  });
  t.after(() => stale.close());
  await assert.rejects(stale.recoveryGuard.authorize(stale), /Recovery trust/);
  assert.equal(stale.recoveryGuard.state, 'QUARANTINED');
  assert.equal(stale.get('SELECT count(*) n FROM issuances').n, 0);
  await assert.rejects(
    custodian.accept(
      packet(f.authority.key, {
        version: 1,
        nonce: crypto.randomUUID(),
        issuedAt: Date.now(),
        stateDigest,
        evidence: before,
      }),
    ),
    /ROLLBACK/,
  );
  const current = authoritySnapshot(f.authority);
  const corrupted = structuredClone(current);
  corrupted.records[0].payload.eventType = 'corrupted';
  await assert.rejects(
    custodian.accept(
      packet(f.authority.key, {
        version: 1,
        nonce: crypto.randomUUID(),
        issuedAt: Date.now(),
        stateDigest: authorizationDigest(f.authority),
        evidence: corrupted,
      }),
    ),
    /Signature/,
  );
  await assert.rejects(
    custodian.accept(
      packet(f.authority.key, {
        version: 1,
        nonce: 'old',
        issuedAt: 0,
        stateDigest,
        evidence: before,
      }),
    ),
    /STALE/,
  );
  unavailable = true;
  await assert.rejects(
    f.clients.bob.claim(object.envelope.objectId, f.authority.epoch().epoch),
    /503/,
  );
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
  unavailable = false;
  await f.authority.recoveryGuard.authorize(f.authority);
  const held = await f.clients.bob.claim(object.envelope.objectId, f.authority.epoch().epoch);
  assert.notEqual(held.status, 200);
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
  const replayClient = new ApiClient(coreTransport(stale), f.profiles.bob);
  replayClient.token = f.clients.bob.token;
  assert.equal((await replayClient.request('GET', '/api/control')).status, 503);
});

test('custody rejects altered authorization without a new chain event and untrusted or replayed leases', async (t) => {
  const f = await coreFixture(t),
    keys = pair();
  const custody = new CheckpointCustodian({
    allowBootstrap: true,
    database: ':memory:',
    authorityKey: f.provisioned.serverPublicKey,
    signingKey: keys.privateKey,
  });
  t.after(() => custody.close());
  let old;
  const guard = createRecoveryGuard({
    custodianKey: keys.publicKey,
    exchange: async (req) => {
      old = await custody.accept(req);
      return old;
    },
  });
  await guard.authorize(f.authority);
  assert.equal(guard.allows(f.authority), true);
  const replay = createRecoveryGuard({ custodianKey: keys.publicKey, exchange: () => old });
  await assert.rejects(replay.authorize(f.authority));
  const wrong = createRecoveryGuard({
    custodianKey: pair().publicKey,
    exchange: (req) => custody.accept(req),
  });
  await assert.rejects(wrong.authorize(f.authority));
  f.authority.run('UPDATE users SET active=0 WHERE id=?', f.profiles.alice.userId);
  assert.equal(guard.allows(f.authority), false);
  await assert.rejects(guard.authorize(f.authority));
});
