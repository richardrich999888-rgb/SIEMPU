import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';
import { createObject, enrollUser, hash, canonical } from './helpers/client.mjs';

test('FLASH creation does not authorize release; separate commander approval is bound to digest and current epoch', async (t) => {
  const f = await coreFixture(t),
    { admin, alice, bob } = f.clients;
  for (const c of [admin, alice, bob]) await c.authenticate();
  for (const p of [f.profiles.alice, f.profiles.bob])
    assert.equal(
      (await admin.admin('PATCH', '/api/admin/users/' + p.userId, { dutyRole: 'UNIT_COMMANDER' }))
        .status,
      200,
    );
  const commander = await enrollUser(admin, {
    username: 'commander-two',
    unitId: f.profiles.alice.unitId,
  });
  await admin.admin('PATCH', '/api/admin/users/' + commander.profile.userId, {
    dutyRole: 'UNIT_COMMANDER',
  });
  const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
    context: { schemaVersion: 2, messagePriority: 'FLASH', messageDomain: 'GENERAL' },
  });
  await alice.submit(object);
  const id = object.envelope.objectId,
    epoch = f.authority.epoch().epoch;
  assert.equal((await bob.claim(id, epoch)).body.code, 'FLASH_APPROVAL_REQUIRED');
  const approve = async (client, digest = hash(canonical(object.envelope)), ep = epoch) => {
    const body = { expectedDigest: digest, expectedEpoch: ep };
    return client.request('POST', `/api/objects/${id}/authorize`, {
      ...body,
      proof: await client.proof('authorize:' + id, body),
    });
  };
  assert.equal((await approve(alice)).status, 403);
  assert.equal((await approve(admin)).status, 403);
  assert.equal((await approve(commander.client, '0'.repeat(64))).status, 409);
  assert.equal((await approve(commander.client)).status, 200);
  assert.equal((await bob.claim(id, epoch)).status, 200);
  await admin.admin('PATCH', '/api/admin/users/' + commander.profile.userId, {
    dutyRole: 'FIELD_OPERATOR',
  });
  assert.equal(
    (await bob.claim(id, f.authority.epoch().epoch)).body.code,
    'FLASH_APPROVAL_REQUIRED',
  );
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 1);
});

test('all six duty roles by four priorities and both domains enforce direct API sender and recipient decisions', async (t) => {
  const roles = {
    UNIT_COMMANDER: [
      'operator',
      ['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE'],
      ['GENERAL', 'INTEL'],
    ],
    SIGNALS_OFFICER: [
      'operator',
      ['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE'],
      ['GENERAL', 'INTEL'],
    ],
    INTELLIGENCE_ANALYST: ['operator', ['IMMEDIATE', 'PRIORITY', 'ROUTINE'], ['INTEL']],
    FIELD_OPERATOR: ['operator', ['PRIORITY', 'ROUTINE'], ['GENERAL']],
    AUDIT_OFFICER: ['auditor', [], []],
    SYSTEM_ADMIN: ['admin', [], []],
  };
  const f = await coreFixture(t),
    { admin, alice, bob } = f.clients;
  for (const c of [admin, alice, bob]) await c.authenticate();
  const assign = async (p, role, dutyRole) =>
    assert.equal(
      (await admin.admin('PATCH', '/api/admin/users/' + p.userId, { role, dutyRole })).status,
      200,
    );
  // Stable signing grant is an input to every attempted object, never authorization.
  const grant = await alice.grant();
  for (const action of ['send', 'receive'])
    for (const [duty, [role, priorities, domains]] of Object.entries(roles)) {
      await assign(
        f.profiles.alice,
        action === 'send' ? role : 'operator',
        action === 'send' ? duty : 'UNIT_COMMANDER',
      );
      await assign(
        f.profiles.bob,
        action === 'receive' ? role : 'operator',
        action === 'receive' ? duty : 'UNIT_COMMANDER',
      );
      for (const priority of ['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE'])
        for (const domain of ['GENERAL', 'INTEL']) {
          const allowed = priorities.includes(priority) && domains.includes(domain);
          const object = createObject(f.profiles.alice, f.profiles.bob, grant, {
            context: { schemaVersion: 2, messagePriority: priority, messageDomain: domain },
          });
          const submitted = await alice.request('POST', '/api/objects', {
            ...object,
            proof: await alice.proof('submit', object),
          });
          if (action === 'send' && !allowed) {
            assert.equal(submitted.status, 403, `${action} ${duty} ${priority} ${domain}`);
            continue;
          }
          assert.equal(submitted.status, 200);
          const result = await bob.claim(object.envelope.objectId, f.authority.epoch().epoch);
          if (allowed && priority !== 'FLASH')
            assert.equal(result.status, 200, `${action} ${duty} ${priority} ${domain}`);
          else {
            assert.notEqual(result.status, 200);
            assert.equal(JSON.stringify(result).includes('wrappedKey'), false);
          }
        }
    }
});
