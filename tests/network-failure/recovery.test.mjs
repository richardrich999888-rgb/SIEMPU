import test from 'node:test';
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { provision } from '../helpers/fixture.mjs';
import { ApiClient, createObject, decryptObject } from '../helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../../deployment/secure/harness.mjs';
import { createTransportServer, requestBytes } from '../../packages/transport/tls.mjs';
import { createFaultProxy } from '../../deployment/testbed/fault-proxy.mjs';

// Re-targeted from the Q-agile branch (a4abc80) onto the TLS 1.3/mTLS stack of the
// engineering branch (32b4a1c). The proxy is a deterministic userspace HTTP fault
// injector; it is not tc/netem and does not model packet loss.

/** Adapts the bounded TLS 1.3 client to the minimal fetch contract used by the proxy. */
function tlsFetch(tls) {
  return async (url, { method, headers, body }) => {
    const r = await requestBytes(url, { method, headers, body, tls });
    return {
      status: r.status,
      headers: { get: (name) => r.headers[name.toLowerCase()] ?? null },
      arrayBuffer: async () => r.body,
    };
  };
}

async function impairedStack(t, profile) {
  const f = await provision();
  const stack = await startSecureStack(f.dir);
  t.after(async () => {
    await stack.stop();
    await rm(f.dir, { recursive: true, force: true });
  });
  const proxyIdentity = stack.pki.issue('fault-proxy');
  const proxy = createFaultProxy({
    serverFactory: (handler) =>
      createTransportServer(handler, { ...proxyIdentity, requestCert: false }),
    upstream: stack.baseUrl,
    fetchImpl: tlsFetch(stack.tls),
    profile,
  });
  await new Promise((resolve) => proxy.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => proxy.server.close(resolve)));
  const proxyUrl = `https://127.0.0.1:${proxy.server.address().port}`;
  const direct = secureApiTransport(stack.baseUrl, stack.tls);
  return {
    f,
    stack,
    proxy,
    impaired: secureApiTransport(proxyUrl, { ca: proxyIdentity.ca }),
    direct: (name) => new ApiClient(direct, f.profiles[name]),
  };
}

test('deterministic constrained reconnect preserves exact bytes and one issuance after response interruption', async (t) => {
  const { f, proxy, impaired, direct } = await impairedStack(t, 'constrained');
  const alice = new ApiClient(impaired, f.profiles.alice),
    bob = new ApiClient(impaired, f.profiles.bob);
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
  // The authority commits the issuance, then the response is cut mid-transfer.
  proxy.state.cutAfterBytes = 1024;
  await assert.rejects(bob.request('POST', `/api/objects/${object.envelope.objectId}/claim`, body));
  const recovered = await bob.claim(object.envelope.objectId, epoch);
  assert.equal(recovered.status, 200, JSON.stringify(recovered.body));
  assert.deepEqual(decryptObject(recovered.body, f.profiles.bob).bytes, bytes);
  const admin = direct('admin');
  await admin.authenticate();
  const evidence = await admin.ok('GET', '/api/evidence/export');
  const records = evidence.records || evidence.evidence;
  const issued = records.filter(
    (r) =>
      r.payload?.objectId === object.envelope.objectId && r.payload?.eventType === 'RELEASE_ISSUED',
  );
  // Retry after an interrupted response replays the committed issuance; it never issues twice.
  assert.equal(issued.length, 1);
  assert.equal(proxy.state.cuts, 2);
  t.diagnostic(
    JSON.stringify({
      synthetic: true,
      emulator: 'userspace HTTP request/chunk faults over TLS 1.3; not netem',
      profile: 'constrained',
      bytes: bytes.length,
      recoveryMs: Math.round(performance.now() - started),
      ...proxy.state,
    }),
  );
});

test('recipient policy revocation while disconnected prevents new release after queued submission', async (t) => {
  const { f, proxy, impaired, direct } = await impairedStack(t, 'interrupted');
  const alice = new ApiClient(impaired, f.profiles.alice),
    bob = direct('bob'),
    admin = direct('admin');
  await alice.authenticate();
  await bob.authenticate();
  await admin.authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant());
  proxy.state.offline = true;
  await assert.rejects(alice.submit(object));
  // Revocation commits while the sender is disconnected with a queued object.
  const revoked = await admin.admin('PUT', '/api/admin/policies', {
    fromUnit: f.profiles.alice.unitId,
    toUnit: f.profiles.bob.unitId,
    missionId: 'DEMO-MISSION',
    allow: false,
  });
  assert.equal(revoked.status, 200, JSON.stringify(revoked));
  proxy.state.offline = false;
  await alice.submit(object);
  const prepared = await alice.prepare(object.envelope.objectId);
  assert.equal(prepared.body.object.state, 'HELD');
  const epoch = (await bob.ok('GET', '/api/control')).payload.epoch;
  const denied = await bob.claim(object.envelope.objectId, epoch);
  assert.equal(denied.status, 409);
  assert.equal(denied.body.receipt.payload.eventType, 'RELEASE_DENIED');
  assert.equal(JSON.stringify(denied.body).includes('wrappedKey'), false);
});
