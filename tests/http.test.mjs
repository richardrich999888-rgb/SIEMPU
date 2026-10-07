import test from 'node:test';
import assert from 'node:assert/strict';
import { httpFixture } from './helpers/fixture.mjs';
import { createObject, decryptObject, enrollUser } from './helpers/client.mjs';

test(
  'real three-process HTTP deployment enforces the complete secure-exchange workflow',
  { timeout: 45000 },
  async (t) => {
    const f = await httpFixture(t),
      { alice, bob, eve, admin } = f.clients;
    for (const client of [alice, bob, eve, admin]) await client.authenticate();
    const secret = 'SYNTHETIC HTTP file contents';
    const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
      kind: 'file',
      name: 'orders-demo.txt',
      data: secret,
    });
    const submitted = await alice.submit(object),
      id = object.envelope.objectId;
    assert.equal(submitted.object.state, 'PENDING');
    assert.equal((await alice.prepare(id)).body.object.state, 'READY');
    const current = await bob.ok('GET', '/api/control');
    const unauthorized = await eve.claim(id, current.payload.epoch);
    assert.ok([403, 404].includes(unauthorized.status));
    assert.ok(!JSON.stringify(unauthorized.body).includes('wrappedKey'));
    const claim = await bob.claim(id, current.payload.epoch);
    assert.equal(claim.status, 200, JSON.stringify(claim.body));
    const content = decryptObject(claim.body, f.profiles.bob);
    assert.equal(content.bytes.toString(), secret);
    assert.equal(content.name, 'orders-demo.txt');
    const receiptId = claim.body.receipt.payload.eventId ?? claim.body.receipt.payload.decisionId;
    const acknowledged = await bob.request('POST', `/api/objects/${id}/ack`, {
      receiptId,
      proof: await bob.proof('ack:' + id, { receiptId }),
    });
    assert.equal(acknowledged.status, 200, JSON.stringify(acknowledged.body));
    assert.equal(acknowledged.body.object.state, 'DELIVERED');
    const overview = await admin.ok('GET', '/api/admin/overview');
    assert.ok(!JSON.stringify(overview).includes(secret));
    assert.ok(!JSON.stringify(overview).includes('wrappedKey'));
    const evidence = await admin.ok('GET', '/api/evidence/export');
    assert.ok(evidence.records.length > 5);
    const relayUnauth = await fetch(
      `http://127.0.0.1:${f.ports.relay}/blobs/${object.envelope.ciphertextHash}`,
    );
    assert.ok([401, 403, 404].includes(relayUnauth.status));
    const created = await enrollUser(admin, { username: 'charlie', unitId: f.provisioned.units.B });
    assert.equal((await created.client.ok('GET', '/api/auth/me')).user.username, 'charlie');
    const invalidOrigin = await alice.request(
      'POST',
      '/api/auth/logout',
      {},
      { headers: { Origin: 'https://attacker.invalid' } },
    );
    assert.ok([400, 403].includes(invalidOrigin.status));
    const wrongContent = await fetch(f.baseUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: '{}',
    });
    assert.ok([400, 415].includes(wrongContent.status));
    const traversal = await fetch(f.baseUrl + '/%2e%2e/server-key.json');
    assert.notEqual(traversal.status, 200);
  },
);
