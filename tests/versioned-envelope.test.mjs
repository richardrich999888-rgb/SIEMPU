import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';
import { createObject, canonical, sign, decryptObject } from './helpers/client.mjs';

test('combined authority accepts v1/v2 and records the signed object version at issuance', async (t) => {
  const f = await coreFixture(t);
  const { alice, bob } = f.clients;
  await alice.authenticate();
  await bob.authenticate();
  for (const schemaVersion of [1, 2]) {
    const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
      context:
        schemaVersion === 1
          ? {}
          : { schemaVersion, messagePriority: 'ROUTINE', messageDomain: 'GENERAL' },
    });
    await alice.submit(object);
    const claim = await bob.claim(object.envelope.objectId, f.authority.epoch().epoch);
    assert.equal(claim.status, 200);
    assert.equal(claim.body.receipt.payload.details.objectSchemaVersion, schemaVersion);
    assert.match(decryptObject(claim.body, f.profiles.bob).bytes.toString(), /SYNTHETIC/);
  }
});

test('v2 storage substitution and unsupported versions cannot bypass persisted signature/schema checks', async (t) => {
  const f = await coreFixture(t);
  const { alice, bob } = f.clients;
  await alice.authenticate();
  await bob.authenticate();
  for (const mutate of [
    (e) => {
      e.messagePriority = 'FLASH';
    },
    (e) => {
      e.messageDomain = 'INTEL';
    },
    (e) => {
      e.schemaVersion = 1;
    },
    (e) => {
      delete e.messagePriority;
    },
    (e) => {
      e.schemaVersion = 3;
    },
  ]) {
    const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
      context: { schemaVersion: 2, messagePriority: 'ROUTINE', messageDomain: 'GENERAL' },
    });
    await alice.submit(object);
    mutate(object.envelope);
    f.authority.run(
      'UPDATE objects SET envelope=? WHERE id=?',
      canonical(object.envelope),
      object.envelope.objectId,
    );
    const denied = await bob.claim(object.envelope.objectId, f.authority.epoch().epoch);
    assert.equal(denied.status, 409);
    assert.ok(!JSON.stringify(denied.body).includes('wrappedKey'));
    assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
  }
  const invalid = createObject(f.profiles.alice, f.profiles.bob, await alice.grant());
  invalid.envelope.schemaVersion = 7;
  invalid.signature = sign(invalid.envelope, f.profiles.alice.keys.signing.privateKey);
  assert.equal(
    (
      await alice.request('POST', '/api/objects', {
        ...invalid,
        proof: await alice.proof('submit', invalid),
      })
    ).status,
    400,
  );
});

test('changing a duty role after enqueue prevents issuance under the new policy', async (t) => {
  const f = await coreFixture(t);
  const { alice, bob, admin } = f.clients;
  for (const client of [alice, bob, admin]) await client.authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
    context: { schemaVersion: 2, messagePriority: 'IMMEDIATE', messageDomain: 'GENERAL' },
  });
  await alice.submit(object);
  assert.equal((await alice.prepare(object.envelope.objectId)).body.object.state, 'READY');
  assert.equal(
    (
      await admin.admin('PATCH', '/api/admin/users/' + f.profiles.bob.userId, {
        dutyRole: 'FIELD_OPERATOR',
      })
    ).status,
    200,
  );
  assert.equal((await bob.claim(object.envelope.objectId, f.authority.epoch().epoch)).status, 404);
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
});
