import test from 'node:test';
import assert from 'node:assert/strict';
import { httpFixture } from '../../helpers/fixture.mjs';
import { createObject } from '../../helpers/client.mjs';
import { verifyEvidence } from '../../../apps/verifier/verify.mjs';

test(
  'revocation: ciphertext queued while sender is offline is held after recipient revocation and no wrapped key is returned',
  { timeout: 45000 },
  async (t) => {
    const f = await httpFixture(t);
    const { alice, bob, admin } = f.clients;
    for (const client of [alice, bob, admin]) await client.authenticate();
    const grant = await alice.grant();
    const transport = alice.transport;
    let blockedCalls = 0;
    alice.transport = async () => {
      blockedCalls++;
      throw new Error('SYNTHETIC_OFFLINE');
    };
    const queued = createObject(f.profiles.alice, f.profiles.bob, grant, {
      data: 'SYNTHETIC queued content: revoked recipient must not receive a key',
    });
    assert.equal(blockedCalls, 0, 'encryption and local queue construction use no HTTP');
    await assert.rejects(alice.submit(queued), /SYNTHETIC_OFFLINE/);
    assert.equal(blockedCalls, 1);
    const id = queued.envelope.objectId;
    const oldControl = await bob.ok('GET', '/api/control');
    const expectedEpoch = oldControl.payload.epoch;
    const proof = await bob.proof('claim:' + id, { expectedEpoch });
    const revoked = await admin.admin('PATCH', `/api/admin/users/${f.profiles.bob.userId}`, {
      active: false,
    });
    assert.equal(revoked.status, 200, JSON.stringify(revoked.body));
    alice.transport = transport;
    assert.equal((await alice.submit(queued)).object.state, 'PENDING');
    const prepared = await alice.prepare(id);
    assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
    assert.equal(prepared.body.object.state, 'HELD');
    assert.equal(prepared.body.object.reason, 'USER_REVOKED');
    const denied = await bob.request('POST', `/api/objects/${id}/claim`, { expectedEpoch, proof });
    assert.ok([401, 403].includes(denied.status), JSON.stringify(denied));
    for (const response of [prepared, denied]) {
      assert.ok(!JSON.stringify(response.body).includes('wrappedKey'));
      assert.ok(!JSON.stringify(response.body).includes(queued.envelope.wrappedKey.ciphertext));
      assert.equal(response.body.envelope, undefined);
      assert.equal(response.body.ciphertext, undefined);
    }
    const current = await alice.ok('GET', '/api/control');
    assert.ok(current.payload.epoch > expectedEpoch);
    const evidence = await admin.ok('GET', '/api/evidence/export');
    assert.equal(
      evidence.records.filter(
        (r) => r.payload.objectId === id && r.payload.eventType === 'RELEASE_ISSUED',
      ).length,
      0,
    );
    assert.ok(
      evidence.records.some((r) => r.payload.objectId === id && r.payload.decision === 'HELD'),
    );
    assert.equal(
      (await verifyEvidence(prepared.body.receipt, f.provisioned.serverPublicKey)).valid,
      true,
    );
    t.diagnostic(
      'Offline scope: sender transport is explicitly blocked while a local ciphertext queue is created; this does not simulate a radio or operating-system outage.',
    );
  },
);
