import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { httpFixture } from '../../helpers/fixture.mjs';
import { createObject, decryptObject, hash, unb64 } from '../../helpers/client.mjs';
import { verifyReleaseReceipt } from '../../../apps/verifier/verify.mjs';

test(
  'authorized backlog: offline ciphertext queue reconnects across an unrelated revocation and only current authorized releases succeed',
  { timeout: 45000 },
  async (t) => {
    const f = await httpFixture(t);
    const { alice, bob, admin } = f.clients;
    for (const client of [alice, bob, admin]) await client.authenticate();
    const grant = await alice.grant();
    const oldEpoch = (await alice.ok('GET', '/api/control')).payload.epoch;
    const transport = alice.transport;
    let blockedCalls = 0;
    alice.transport = async () => {
      blockedCalls++;
      throw new Error('SYNTHETIC_OFFLINE');
    };
    const plaintexts = [
      'SYNTHETIC authorized backlog item one',
      'SYNTHETIC authorized backlog item two',
    ];
    const backlog = plaintexts.map((data) =>
      createObject(f.profiles.alice, f.profiles.bob, grant, { data }),
    );
    assert.equal(blockedCalls, 0);
    await assert.rejects(alice.submit(backlog[0]), /SYNTHETIC_OFFLINE/);
    assert.equal(blockedCalls, 1);
    const unrelatedRevocation = await admin.admin(
      'PATCH',
      `/api/admin/users/${f.profiles.eve.userId}`,
      { active: false },
    );
    assert.equal(unrelatedRevocation.status, 200);
    alice.transport = transport;
    const current = await bob.ok('GET', '/api/control');
    const expectedEpoch = current.payload.epoch;
    assert.ok(expectedEpoch > oldEpoch);
    const receipts = [];
    for (const [index, object] of backlog.entries()) {
      const id = object.envelope.objectId;
      assert.equal((await alice.submit(object)).object.state, 'PENDING');
      const prepared = await alice.prepare(id);
      assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
      assert.equal(prepared.body.object.state, 'READY');
      const claim = await bob.claim(id, expectedEpoch);
      assert.equal(claim.status, 200, JSON.stringify(claim.body));
      assert.equal(decryptObject(claim.body, f.profiles.bob).bytes.toString(), plaintexts[index]);
      assert.equal(claim.body.receipt.payload.details.authorityEpoch, expectedEpoch);
      const receiptId = claim.body.receipt.payload.eventId;
      const ack = await bob.request('POST', `/api/objects/${id}/ack`, {
        receiptId,
        proof: await bob.proof('ack:' + id, { receiptId }),
      });
      assert.equal(ack.status, 200);
      assert.equal(ack.body.object.state, 'DELIVERED');
      receipts.push({ receipt: claim.body.receipt, object });
    }
    const evidence = await admin.ok('GET', '/api/evidence/export');
    for (const { object } of receipts)
      assert.equal(
        evidence.records.filter(
          (r) =>
            r.payload.objectId === object.envelope.objectId &&
            r.payload.eventType === 'RELEASE_ISSUED',
        ).length,
        1,
      );
    await f.stop();
    for (const { receipt, object } of receipts) {
      const result = await verifyReleaseReceipt(receipt, f.provisioned.serverPublicKey, {
        objectDigest: hash(unb64(object.ciphertext)),
        epoch: expectedEpoch,
        objectId: object.envelope.objectId,
        replayStore: join(f.dir, 'accepted.sqlite'),
      });
      assert.equal(result.strictReleaseVerified, true);
    }
    t.diagnostic(
      'Synthetic offline sender transport; saved creation grants do not confer release authority. Each item is evaluated at the new authority epoch.',
    );
  },
);
