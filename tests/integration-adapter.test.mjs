// Adapter negative and recovery cases ported in intent from the Q-agile branch (a4abc80,
// tests/integration/synthetic-adapter.test.mjs) onto the kept adapter (services/integration).
// The kept adapter authenticates its source by mTLS pin, not a per-request signature, so the
// signature cases do not apply; freshness, scope, replay, capacity and restart do.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { provision } from './helpers/fixture.mjs';
import { ApiClient } from './helpers/client.mjs';
import { SyntheticAdapter, FRESHNESS_WINDOW_MS } from '../services/integration/adapter.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';
import { createObjectCryptography } from '../packages/crypto/crypto.mjs';

const SENDER = randomUUID();
const DESTINATION = randomUUID();
const crypto = createObjectCryptography();

/** Endpoint double: records every forward so tests can prove rejection happens before it. */
function fakeEndpoint() {
  const calls = { seal: 0, submit: 0 };
  return {
    calls,
    profile: { userId: SENDER },
    crypto,
    async seal() {
      calls.seal++;
      return { envelope: { objectId: randomUUID() }, signature: 's', ciphertext: 'c' };
    },
    async submit(sealed) {
      calls.submit++;
      return { object: { id: sealed.envelope.objectId }, receipt: { synthetic: true } };
    },
  };
}

function adapterWith(t, endpoint, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-adapter-'));
  const adapter = new SyntheticAdapter({
    database: join(dir, 'adapter.sqlite'),
    endpoint,
    destinations: [{ userId: DESTINATION }],
    ...options,
  });
  t.after(() => {
    adapter.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return adapter;
}

const request = (overrides = {}) => ({
  version: 1,
  requestId: randomUUID(),
  issuedAt: Date.now(),
  senderUserId: SENDER,
  destinationUserId: DESTINATION,
  payload: crypto.createTextPayload('SYNTHETIC adapter payload'),
  ...overrides,
});

test('schema, freshness, sender and destination violations are refused before any forward', async (t) => {
  const endpoint = fakeEndpoint();
  const adapter = adapterWith(t, endpoint);
  const cases = [
    [request({ version: 2 }), 'ADAPTER_SCHEMA_OR_REPLAY'],
    [{ ...request(), extra: true }, 'ADAPTER_SCHEMA_OR_REPLAY'],
    [request({ requestId: 'not-a-uuid' }), 'ADAPTER_SCHEMA_OR_REPLAY'],
    [request({ issuedAt: 1.5 }), 'ADAPTER_SCHEMA_OR_REPLAY'],
    // Freshness is symmetric: stale and future-dated requests are both refused.
    [request({ issuedAt: Date.now() - FRESHNESS_WINDOW_MS - 1000 }), 'ADAPTER_SCHEMA_OR_REPLAY'],
    [request({ issuedAt: Date.now() + FRESHNESS_WINDOW_MS + 1000 }), 'ADAPTER_SCHEMA_OR_REPLAY'],
    [request({ senderUserId: randomUUID() }), 'ADAPTER_SENDER_DENIED'],
    [request({ destinationUserId: randomUUID() }), 'ADAPTER_DESTINATION_DENIED'],
  ];
  for (const [value, code] of cases)
    await assert.rejects(adapter.submit(value), new RegExp(code), JSON.stringify(value));
  await assert.rejects(
    adapter.submit(request({ payload: { kind: 'text', name: '', mime: 'text/plain', data: '*' } })),
  );
  assert.deepEqual(endpoint.calls, { seal: 0, submit: 0 });
});

test('replay returns the stored result once; a changed body under the same ID conflicts', async (t) => {
  const endpoint = fakeEndpoint();
  const adapter = adapterWith(t, endpoint);
  const first = request();
  const accepted = await adapter.submit(first);
  assert.deepEqual(await adapter.submit(first), accepted);
  await assert.rejects(
    adapter.submit({ ...first, payload: crypto.createTextPayload('changed') }),
    /IDEMPOTENCY_CONFLICT/,
  );
  assert.deepEqual(endpoint.calls, { seal: 1, submit: 1 });
});

test('durable capacity is explicit: new IDs are refused, replay history is never evicted', async (t) => {
  const endpoint = fakeEndpoint();
  const adapter = adapterWith(t, endpoint, { maxEntries: 1 });
  const first = request();
  const accepted = await adapter.submit(first);
  await assert.rejects(adapter.submit(request()), /ADAPTER_CAPACITY/);
  // The stored request is still recognised, so the earlier ID cannot be replayed as new.
  assert.deepEqual(await adapter.submit(first), accepted);
  assert.deepEqual(endpoint.calls, { seal: 1, submit: 1 });
  assert.throws(
    () => new SyntheticAdapter({ database: ':memory:', endpoint, destinations: [], maxEntries: 0 }),
    /maxEntries/,
  );
});

test('a response lost after authority commit resumes safely after adapter restart', async (t) => {
  const f = await provision();
  const stack = await startSecureStack(f.dir);
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-adapter-restart-'));
  t.after(async () => {
    await stack.stop();
    rmSync(dir, { recursive: true, force: true });
    await rm(f.dir, { recursive: true, force: true });
  });
  const database = join(dir, 'adapter.sqlite');
  const destinations = [
    {
      userId: f.profiles.bob.userId,
      deviceId: f.profiles.bob.deviceId,
      unitId: f.profiles.bob.unitId,
      encryptionPublicKey: f.profiles.bob.keys.encryption.publicKey,
    },
  ];
  const endpointFor = async (profile) => {
    const endpoint = new IntegrationEndpoint({
      url: stack.baseUrl,
      tls: stack.tls,
      profile,
      authorityKey: f.provisioned.serverPublicKey,
    });
    await endpoint.authenticate();
    return endpoint;
  };
  const alice = await endpointFor(f.profiles.alice);
  // The authority commits the submission, then the response is lost before the adapter
  // records it: the classic ambiguous outcome.
  let committedObjectId;
  const lossy = Object.create(alice);
  lossy.submit = async (sealed) => {
    const result = await alice.submit(sealed);
    committedObjectId = result.object.id;
    throw new Error('SIMULATED_RESPONSE_LOSS');
  };
  const body = {
    version: 1,
    requestId: randomUUID(),
    issuedAt: Date.now(),
    senderUserId: f.profiles.alice.userId,
    destinationUserId: f.profiles.bob.userId,
    payload: alice.crypto.createTextPayload('SYNTHETIC restart canary'),
  };
  const first = new SyntheticAdapter({ database, endpoint: lossy, destinations });
  await assert.rejects(first.submit(body), /SIMULATED_RESPONSE_LOSS/);
  first.close();
  // Restart: a fresh adapter on the same durable store re-forwards the identical sealed object.
  const restarted = new SyntheticAdapter({ database, endpoint: alice, destinations });
  t.after(() => restarted.close());
  const resumed = await restarted.submit(body);
  assert.equal(resumed.accepted, true);
  assert.equal(resumed.objectId, committedObjectId);
  const admin = new ApiClient(secureApiTransport(stack.baseUrl, stack.tls), f.profiles.admin);
  await admin.authenticate();
  const { records } = await admin.ok('GET', '/api/evidence/export');
  const submitted = records.filter(
    (r) => r.payload.objectId === committedObjectId && r.payload.eventType === 'SUBMITTED',
  );
  assert.equal(submitted.length, 1, 'the authority recorded exactly one submission');
  const bob = await endpointFor(f.profiles.bob);
  const plaintext = await bob.receive(committedObjectId, f.profiles.alice.keys.signing.publicKey);
  assert.equal(bob.crypto.unpackPayload(plaintext).text, 'SYNTHETIC restart canary');

  // Current authority still applies to adapter traffic: a revoked sender device is refused.
  const revoke = await admin.admin(
    'POST',
    `/api/admin/devices/${f.profiles.alice.deviceId}/revoke`,
  );
  assert.equal(revoke.status, 200, JSON.stringify(revoke.body));
  await assert.rejects(
    restarted.submit({ ...body, requestId: randomUUID(), issuedAt: Date.now() }),
    /PLATFORM_REQUEST_REJECTED/,
  );
});
