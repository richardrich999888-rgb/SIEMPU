import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { coreFixture } from './helpers/fixture.mjs';
import { canonical, createObject, sign, verify } from './helpers/client.mjs';
import { decryptObject, unpackPayload } from '../packages/crypto/crypto.mjs';

const profile = { schemaVersion: 2, messagePriority: 'FLASH', messageDomain: 'GENERAL' };

async function ready(t, context = profile) {
  const f = await coreFixture(t);
  for (const user of ['alice', 'bob', 'admin']) await f.clients[user].authenticate();
  f.object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant(), {
    context,
    data: Buffer.from([0, 1, 127, 128, 255, 10]),
    kind: 'file',
    name: 'synthetic.bin',
    mime: 'application/octet-stream',
  });
  f.id = f.object.envelope.objectId;
  await f.clients.alice.submit(f.object);
  assert.equal((await f.clients.alice.prepare(f.id)).body.object.state, 'READY');
  return f;
}

async function duty(f, user, dutyRole) {
  const result = await f.clients.admin.admin(
    'PATCH',
    '/api/admin/users/' + f.profiles[user].userId,
    {
      dutyRole,
    },
  );
  assert.equal(result.status, 200, JSON.stringify(result));
}

function durableHold(f, eventType, reason) {
  const row = f.authority.get('SELECT * FROM objects WHERE id=?', f.id);
  assert.equal(row.state, 'HELD');
  assert.equal(row.reason, reason);
  const receipt = f.authority.findReceipt(f.id, eventType);
  assert.equal(receipt.payload.decision, 'HELD');
  assert.equal(receipt.payload.reason, reason);
  assert.ok(verify(receipt.payload, receipt.signature, f.provisioned.serverPublicKey));
  assert.equal(f.authority.get('SELECT COUNT(*) AS n FROM issuances').n, 0);
}

test('v1 and v2 independent peers retain exact-byte release and WebCrypto compatibility', async (t) => {
  for (const context of [{}, profile]) {
    await t.test('schema ' + (context.schemaVersion ?? 1), async (t) => {
      const f = await ready(t, context);
      const result = await f.clients.bob.claim(f.id, f.authority.epoch().epoch);
      assert.equal(result.status, 200, JSON.stringify(result));
      const payload = await decryptObject(
        result.body,
        f.profiles.bob.keys.encryption.privateKey,
        f.profiles.alice.keys.signing.publicKey,
      );
      assert.deepEqual(
        Buffer.from(unpackPayload(payload).bytes),
        Buffer.from([0, 1, 127, 128, 255, 10]),
      );
    });
  }
});

test('signed v1/v2 submissions enforce exact schemas without version fallback', async (t) => {
  const f = await coreFixture(t);
  await f.clients.alice.authenticate();
  const grant = await f.clients.alice.grant();
  for (const context of [
    { ...profile, schemaVersion: 1 },
    { schemaVersion: 2 },
    { ...profile, messagePriority: undefined },
    { ...profile, unexpected: 'not authenticated by a known contract' },
    { ...profile, schemaVersion: 3 },
    { schemaVersion: '1' },
  ]) {
    // Omit undefined members as they would be absent after JSON transport.
    const cleanContext = Object.fromEntries(
      Object.entries(context).filter(([, v]) => v !== undefined),
    );
    const object = createObject(f.profiles.alice, f.profiles.bob, grant, { context: cleanContext });
    const response = await f.clients.alice.request('POST', '/api/objects', {
      ...object,
      proof: await f.clients.alice.proof('submit', object),
    });
    assert.equal(response.status, 400, JSON.stringify(response));
    assert.equal(response.body.code, 'ENVELOPE_SCHEMA');
  }
  assert.equal(f.authority.get('SELECT COUNT(*) AS n FROM objects').n, 0);
});

test('persisted v2 keeps strict signatures, column bindings, canonical bytes and schema checks', async (t) => {
  const f = await ready(t);
  const cases = [
    ['signature', (e) => e, 'OBJECT_SIGNATURE_INVALID'],
    ['binding', (e) => ({ ...e, recipientUserId: randomUUID() }), 'OBJECT_BINDING_MISMATCH'],
    [
      'schema downgrade with v2 members',
      (e) => ({ ...e, schemaVersion: 1 }),
      'OBJECT_ENVELOPE_SCHEMA',
    ],
    ['unknown schema', (e) => ({ ...e, schemaVersion: 99 }), 'OBJECT_ENVELOPE_SCHEMA'],
    ['unknown field', (e) => ({ ...e, extra: true }), 'OBJECT_ENVELOPE_SCHEMA'],
    ['priority', (e) => ({ ...e, messagePriority: 'FLASH!' }), 'OBJECT_ENVELOPE_INVALID'],
    ['domain', (e) => ({ ...e, messageDomain: 'UNKNOWN' }), 'OBJECT_ENVELOPE_INVALID'],
    ['canonical bytes', (e) => e, 'OBJECT_ENVELOPE_NONCANONICAL'],
  ];
  for (const [label, mutate, reason] of cases) {
    await t.test(label, async () => {
      const envelope = mutate(structuredClone(f.object.envelope));
      f.authority.run(
        'UPDATE objects SET envelope=?,signature=? WHERE id=?',
        label === 'canonical bytes' ? JSON.stringify(envelope, null, 2) : canonical(envelope),
        label === 'signature'
          ? 'A'.repeat(86)
          : sign(envelope, f.profiles.alice.keys.signing.privateKey),
        f.id,
      );
      const result = await f.clients.bob.claim(f.id, f.authority.epoch().epoch);
      assert.equal(result.status, 409, JSON.stringify(result));
      assert.equal(result.body.envelope, undefined);
      assert.equal(result.body.ciphertext, undefined);
      durableHold(f, 'RELEASE_DENIED', reason);
    });
  }
});

test('late recipient duty restriction commits denial before opaque404', async (t) => {
  const f = await ready(t);
  await duty(f, 'bob', 'FIELD_OPERATOR');
  const result = await f.clients.bob.claim(f.id, f.authority.epoch().epoch);
  assert.equal(result.status, 404);
  assert.equal(result.body.code, 'OBJECT_NOT_FOUND');
  assert.equal(result.body.object, undefined);
  assert.equal(result.body.receipt, undefined);
  durableHold(f, 'RELEASE_DENIED', 'ROLE_PRIORITY_DENIED');
});

test('late sender duty restriction commits admission HOLD before opaque404', async (t) => {
  const f = await ready(t);
  await duty(f, 'alice', 'FIELD_OPERATOR');
  const result = await f.clients.alice.prepare(f.id);
  assert.equal(result.status, 404);
  assert.equal(result.body.code, 'OBJECT_NOT_FOUND');
  durableHold(f, 'ADMISSION', 'ROLE_PRIORITY_DENIED');
});

test('legacy object cannot bypass a subsequently assigned duty role', async (t) => {
  const f = await ready(t, {});
  await duty(f, 'bob', 'FIELD_OPERATOR');
  const result = await f.clients.bob.claim(f.id, f.authority.epoch().epoch);
  assert.equal(result.status, 404);
  durableHold(f, 'RELEASE_DENIED', 'DUTY_PROFILE_REQUIRES_V2');
});

test('unreadable stored v2 remains hidden and produces durable evidence for assigned duty user', async (t) => {
  const f = await ready(t);
  await duty(f, 'bob', 'UNIT_COMMANDER');
  f.authority.run('UPDATE objects SET envelope=? WHERE id=?', '{', f.id);
  const listed = await f.clients.bob.ok('GET', '/api/objects');
  assert.ok(!listed.objects.some((row) => row.id === f.id));
  assert.equal((await f.clients.bob.prepare(f.id)).status, 404);
  durableHold(f, 'ADMISSION', 'OBJECT_ENVELOPE_SCHEMA');
  assert.equal((await f.clients.bob.claim(f.id, f.authority.epoch().epoch)).status, 404);
  durableHold(f, 'RELEASE_DENIED', 'OBJECT_ENVELOPE_SCHEMA');
});
