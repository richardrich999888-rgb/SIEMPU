import test from 'node:test';
import assert from 'node:assert/strict';
import { createObject, decryptObject, ApiClient } from '../helpers/client.mjs';
import { apiTransport, secureFixture } from '../transport/fixture.mjs';
import { secureFetch, secureServerFactory } from '../../packages/transport/mtls.mjs';
import { createFaultProxy } from '../../deployment/testbed/fault-proxy.mjs';
import { listen, closeServer } from '../../deployment/secure/stack.mjs';

async function impaired(t, f, profile) {
  const proxy = createFaultProxy({
    serverFactory: secureServerFactory(f.pki.identities.web, { mutual: false }),
    upstream: f.baseUrl,
    fetchImpl: f.fetch,
    profile,
  });
  const url = await listen(proxy.server);
  t.after(() => closeServer(proxy.server));
  const fetchImpl = secureFetch({ ca: f.pki.ca, serverPin: f.pki.identities.web.pin });
  return { ...proxy, transport: apiTransport(fetchImpl, url) };
}

test('deterministic constrained reconnect preserves exact bytes and one issuance after response interruption', async (t) => {
  const f = await secureFixture(t);
  const proxy = await impaired(t, f, 'constrained');
  const alice = new ApiClient(proxy.transport, f.profiles.alice),
    bob = new ApiClient(proxy.transport, f.profiles.bob);
  await alice.authenticate();
  await bob.authenticate();
  const bytes = Buffer.from(Array.from({ length: 65536 }, (_, i) => i % 239));
  const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
    kind: 'file',
    data: bytes,
  });
  const started = performance.now();
  proxy.state.offline = true;
  await assert.rejects(alice.submit(object));
  proxy.state.offline = false;
  await alice.submit(object);
  await alice.prepare(object.envelope.objectId);
  const epoch = (await bob.ok('GET', '/api/control')).payload.epoch;
  const body = {
    expectedEpoch: epoch,
    proof: await bob.proof('claim:' + object.envelope.objectId, { expectedEpoch: epoch }),
  };
  proxy.state.cutAfterBytes = 1024;
  await assert.rejects(bob.request('POST', `/api/objects/${object.envelope.objectId}/claim`, body));
  const recovered = await bob.claim(object.envelope.objectId, epoch);
  assert.equal(recovered.status, 200);
  assert.deepEqual(decryptObject(recovered.body, f.profiles.bob).bytes, bytes);
  await f.clients.admin.authenticate();
  const evidence = await f.clients.admin.ok('GET', '/api/evidence/export');
  const records = evidence.records || evidence.evidence;
  const issuances = records.filter(
    (r) =>
      r.payload?.objectId === object.envelope.objectId && r.payload?.eventType === 'RELEASE_ISSUED',
  );
  assert.equal(issuances.length, 1);
  assert.equal(proxy.state.cuts, 2);
  t.diagnostic(
    JSON.stringify({
      synthetic: true,
      emulator: 'userspace HTTP request/chunk faults; not netem',
      profile: 'constrained',
      bytes: bytes.length,
      recoveryMs: Math.round(performance.now() - started),
      ...proxy.state,
    }),
  );
});

test('recipient policy revocation while disconnected prevents new release after queued submission', async (t) => {
  const f = await secureFixture(t);
  const proxy = await impaired(t, f, 'interrupted');
  const alice = new ApiClient(proxy.transport, f.profiles.alice);
  await alice.authenticate();
  await f.clients.bob.authenticate();
  await f.clients.admin.authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant());
  proxy.state.offline = true;
  await assert.rejects(alice.submit(object));
  await f.clients.admin.admin('PUT', '/api/admin/policies', {
    fromUnit: f.profiles.alice.unitId,
    toUnit: f.profiles.bob.unitId,
    missionId: 'DEMO-MISSION',
    allow: false,
  });
  proxy.state.offline = false;
  await alice.submit(object);
  const prepared = await alice.prepare(object.envelope.objectId);
  assert.equal(prepared.body.object.state, 'HELD');
  const epoch = (await f.clients.bob.ok('GET', '/api/control')).payload.epoch;
  const denied = await f.clients.bob.claim(object.envelope.objectId, epoch);
  assert.equal(denied.status, 409);
  assert.equal(denied.body.receipt.payload.eventType, 'RELEASE_DENIED');
  assert.equal(JSON.stringify(denied.body).includes('wrappedKey'), false);
});
