import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { secureFixture } from '../transport/fixture.mjs';
import { createObject, decryptObject, pair, sign } from '../helpers/client.mjs';
import { createIntegrationAdapter } from '../../services/integration-adapter/server.mjs';
import { signSyntheticSubmission } from '../../deployment/testbed/legacy-emulator.mjs';
import { secureFetch } from '../../packages/transport/mtls.mjs';
import { listen, closeServer } from '../../deployment/secure/stack.mjs';

async function adapterFixture(t, { fake = false, maxEntries = 10000 } = {}) {
  const f = await secureFixture(t);
  await f.clients.alice.authenticate();
  const key = pair();
  let forwards = 0,
    fail = false;
  const settings = {
    database: join(f.dir, 'adapter/ingress.sqlite'),
    tls: f.pki.identities.adapter,
    sources: [
      {
        id: 'synthetic-legacy-1',
        signingPublicKey: key.publicKey,
        certificatePin: f.pki.identities.legacy.pin,
        senderUserId: f.profiles.alice.userId,
        senderDeviceId: f.profiles.alice.deviceId,
        destinationUnits: [f.profiles.bob.unitId],
        missionIds: ['DEMO-MISSION'],
      },
    ],
    maxEntries,
    controlSubmit: async (submission, authorization) => {
      forwards++;
      if (fail) throw new Error('Simulated cut after forwarding');
      if (fake) return { status: 201, body: { accepted: true } };
      const response = await f.fetch(`${f.baseUrl}/api/objects`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization },
        body: JSON.stringify(submission),
      });
      return { status: response.status, body: await response.json() };
    },
  };
  let server = createIntegrationAdapter(settings),
    baseUrl = await listen(server);
  t.after(() => closeServer(server));
  const fetchImpl = secureFetch({
    ...f.pki.identities.legacy,
    serverPin: f.pki.identities.adapter.pin,
  });
  const send = async (
    body,
    { token = f.clients.alice.token, path = '/integration/v1/submissions', headers = {} } = {},
  ) => {
    const r = await fetchImpl(baseUrl + path, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: 'Bearer ' + token } : {}),
        ...headers,
      },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
    return { status: r.status, body: await r.json() };
  };
  const request = (submission, options = {}) =>
    signSyntheticSubmission({
      sourceId: 'synthetic-legacy-1',
      signingKey: key.privateKey,
      signingPublicKey: key.publicKey,
      submission,
      ...options,
    });
  const resign = (body) => ({ ...body, signature: sign(body.context, key.privateKey) });
  const object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant(), {
    data: 'SYNTHETIC adapter exact-byte evidence',
  });
  const submission = { ...object, proof: await f.clients.alice.proof('submit', object) };
  return {
    ...f,
    settings,
    send,
    request,
    resign,
    object,
    submission,
    calls: () => forwards,
    setFail: () => {
      fail = true;
    },
    restart: async () => {
      await closeServer(server);
      server = createIntegrationAdapter(settings);
      baseUrl = await listen(server);
    },
    versions: async () => (await fetchImpl(baseUrl + '/integration/versions')).json(),
  };
}

test('independent synthetic signer, mTLS adapter and public control deliver ciphertext exactly once across restart', async (t) => {
  const f = await adapterFixture(t);
  assert.deepEqual((await f.versions()).versions, [1]);
  const initial = f.request(f.submission);
  const accepted = await f.send(initial);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.receipt.payload.eventType, 'SUBMITTED');
  assert.equal((await f.send(initial)).body.error, 'REPLAY');
  await f.restart();
  assert.equal((await f.send(initial)).body.error, 'REPLAY');
  const retry = await f.send(
    f.request(f.submission, { idempotencyKey: initial.context.idempotencyKey }),
  );
  assert.equal(retry.status, 200);
  assert.equal(retry.body.idempotent, true);
  assert.equal(f.calls(), 1);
  await f.clients.bob.authenticate();
  await f.clients.alice.prepare(f.object.envelope.objectId);
  const claim = await f.clients.bob.claim(
    f.object.envelope.objectId,
    (await f.clients.bob.ok('GET', '/api/control')).payload.epoch,
  );
  assert.equal(claim.status, 200);
  assert.equal(
    decryptObject(claim.body, f.profiles.bob).bytes.toString(),
    'SYNTHETIC adapter exact-byte evidence',
  );
  const changed = structuredClone(f.submission);
  changed.ciphertext += 'A';
  assert.equal(
    (await f.send(f.request(changed, { idempotencyKey: initial.context.idempotencyKey }))).body
      .error,
    'IDEMPOTENCY_CONFLICT',
  );
});

test('adapter denies schema, signature, freshness, scope, replay and session violations before forwarding', async (t) => {
  const f = await adapterFixture(t, { fake: true });
  assert.equal((await f.send('{')).body.error, 'INVALID_JSON');
  assert.equal((await f.send({})).body.error, 'INVALID_SCHEMA');
  assert.equal((await f.send({}, { path: '/api/objects/id/claim' })).body.error, 'NOT_FOUND');
  assert.equal((await f.send({}, { headers: { 'content-type': 'text/plain' } })).status, 415);
  const mutations = [
    [
      (b) => {
        b.context.extra = true;
      },
      'INVALID_SCHEMA',
    ],
    [
      (b) => {
        b.context.version = 2;
      },
      'UNSUPPORTED_PROTOCOL',
    ],
    [
      (b) => {
        b.context.sourceId = 'unknown';
      },
      'SOURCE_DENIED',
    ],
    [
      (b) => {
        b.context.keyId = '0'.repeat(64);
      },
      'SOURCE_DENIED',
    ],
    [
      (b) => {
        b.context.expiresAt = Date.now() - 1;
      },
      'INVALID_FRESHNESS',
    ],
    [
      (b) => {
        b.context.issuedAt = Date.now() + 30000;
      },
      'INVALID_FRESHNESS',
    ],
    [
      (b) => {
        b.context.nonce = 'bad';
      },
      'INVALID_FRESHNESS',
    ],
    [
      (b) => {
        b.context.submission.envelope.recipientUnitId = randomUUID();
      },
      'SOURCE_SCOPE_DENIED',
    ],
    [
      (b) => {
        b.context.submission.envelope.missionId = 'OTHER-MISSION';
      },
      'SOURCE_SCOPE_DENIED',
    ],
    [
      (b) => {
        b.context.submission.extra = true;
      },
      'INVALID_SUBMISSION',
    ],
  ];
  for (const [mutate, expected] of mutations) {
    const body = f.request(structuredClone(f.submission));
    mutate(body);
    assert.equal((await f.send(f.resign(body))).body.error, expected);
  }
  const tampered = f.request(f.submission);
  tampered.signature = 'A'.repeat(86);
  assert.equal((await f.send(tampered)).body.error, 'SIGNATURE_INVALID');
  assert.equal(
    (await f.send(f.request(f.submission), { token: null })).body.error,
    'CONTROL_AUTH_REQUIRED',
  );
  assert.equal(f.calls(), 0);
});

test('adapter preserves current control authorization and quarantines ambiguous in-flight restart', async (t) => {
  const f = await adapterFixture(t);
  await f.clients.admin.authenticate();
  const request = f.request(f.submission);
  await f.clients.admin.admin('POST', `/api/admin/devices/${f.profiles.alice.deviceId}/revoke`);
  const denied = await f.send(request);
  assert.equal(denied.status, 401);
  assert.equal(JSON.stringify(denied.body).includes('wrappedKey'), false);
  const recovery = f.request(f.submission);
  f.setFail();
  assert.equal((await f.send(recovery)).status, 503);
  await f.restart();
  assert.equal(
    (await f.send(f.request(f.submission, { idempotencyKey: recovery.context.idempotencyKey })))
      .body.error,
    'RECOVERY_REQUIRED',
  );
  assert.equal(f.calls(), 2);
});

test('adapter durable admission capacity is explicit rather than deleting replay history', async (t) => {
  const f = await adapterFixture(t, { fake: true, maxEntries: 1 });
  assert.equal((await f.send(f.request(f.submission))).status, 201);
  assert.equal((await f.send(f.request(f.submission))).body.error, 'ADAPTER_CAPACITY');
});
