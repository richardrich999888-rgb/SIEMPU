import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';
import { createObject } from './helpers/client.mjs';

async function assignDuty(client, userId, dutyRole) {
  const path = '/api/admin/users/' + userId;
  const body = { dutyRole };
  const response = await client.request('PATCH', path, {
    ...body,
    proof: await client.proof('admin:PATCH:' + path, body),
  });
  assert.equal(response.status, 200, JSON.stringify(response));
}

test('signed schema-v2 priority permits routine and holds forbidden FLASH recipient', async (t) => {
  const f = await coreFixture(t);
  const { alice, bob, admin } = f.clients;
  for (const client of [alice, bob, admin]) await client.authenticate();
  await assignDuty(admin, f.profiles.alice.userId, 'UNIT_COMMANDER');
  await assignDuty(admin, f.profiles.bob.userId, 'FIELD_OPERATOR');

  const routine = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
    context: { schemaVersion: 2, messagePriority: 'ROUTINE', messageDomain: 'GENERAL' },
  });
  assert.equal((await alice.submit(routine)).object.state, 'PENDING');
  assert.equal((await alice.prepare(routine.envelope.objectId)).body.object.state, 'READY');
  const ctl = await alice.ok('GET', '/api/control');
  const accepted = await bob.claim(routine.envelope.objectId, ctl.payload.epoch);
  assert.equal(accepted.status, 200, JSON.stringify(accepted));

  const urgent = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
    context: { schemaVersion: 2, messagePriority: 'FLASH', messageDomain: 'GENERAL' },
  });
  assert.equal((await alice.submit(urgent)).object.state, 'PENDING');
  const held = await alice.prepare(urgent.envelope.objectId);
  assert.equal(held.body.object.state, 'HELD');
  assert.equal(held.body.object.reason, 'ROLE_PRIORITY_DENIED');
  const rejected = await bob.claim(urgent.envelope.objectId, ctl.payload.epoch);
  assert.equal(rejected.status, 409);
  assert.equal(rejected.body.code, 'ROLE_PRIORITY_DENIED');
  assert.ok(!JSON.stringify(rejected.body).includes('wrappedKey'));
  const listed = await bob.ok('GET', '/api/objects');
  assert.ok(!listed.objects.some((x) => x.id === urgent.envelope.objectId));

  const tampered = structuredClone(urgent);
  tampered.envelope.messagePriority = 'ROUTINE';
  const attempt = await alice.request('POST', '/api/objects', {
    ...tampered,
    proof: await alice.proof('submit', tampered),
  });
  assert.ok([400, 403].includes(attempt.status));
});

test('FIELD_OPERATOR cannot submit FLASH or v1 to bypass duty tier', async (t) => {
  const f = await coreFixture(t);
  const { alice, bob, admin } = f.clients;
  for (const client of [alice, bob, admin]) await client.authenticate();
  await assignDuty(admin, f.profiles.alice.userId, 'FIELD_OPERATOR');
  const grant = await alice.grant();
  for (const context of [
    { schemaVersion: 2, messagePriority: 'FLASH', messageDomain: 'GENERAL' },
    {},
  ]) {
    const payload = createObject(f.profiles.alice, f.profiles.bob, grant, { context });
    const outcome = await alice.request('POST', '/api/objects', {
      ...payload,
      proof: await alice.proof('submit', payload),
    });
    assert.equal(outcome.status, 403, JSON.stringify(outcome));
  }
});
