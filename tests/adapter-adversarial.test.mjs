import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  SyntheticAdapter,
  FRESHNESS_WINDOW_MS,
  createAdapterServer,
} from '../services/integration/adapter.mjs';
import { startupDiagnostic, isAdapterReady } from '../services/integration/lifecycle.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';
import { createObjectCryptography } from '../packages/crypto/crypto.mjs';
import { startLabAdapter } from '../deployment/secure/adapter-process.mjs';
import { startSecureStack } from '../deployment/secure/harness.mjs';
import { generateLabPKI } from '../deployment/secure/lab-pki.mjs';
import { requestBytes } from '../packages/transport/tls.mjs';
import { provision } from './helpers/fixture.mjs';

const cryptography = createObjectCryptography();
const sender = randomUUID(),
  recipient = randomUUID();
const request = () => ({
  version: 1,
  requestId: randomUUID(),
  issuedAt: Date.now(),
  senderUserId: sender,
  destinationUserId: recipient,
  payload: cryptography.createTextPayload('SYNTHETIC_ADVERSARIAL_CANARY'),
});
function deferred() {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
function fixture(t, options = {}) {
  const endpoint = {
    profile: { userId: sender },
    crypto: cryptography,
    seen: [],
    submissions: 0,
    async seal(destination, payload) {
      this.seen.push(structuredClone(payload));
      return { envelope: { objectId: randomUUID() }, ciphertext: 'synthetic sealed fixture' };
    },
    async submit(sealed) {
      this.submissions++;
      return { object: { id: sealed.envelope.objectId }, receipt: {} };
    },
    async signed() {
      return { payload: { issuedAt: Date.now(), expiresAt: Date.now() + 60000 } };
    },
  };
  const adapter = new SyntheticAdapter({
    database: ':memory:',
    endpoint,
    destinations: [{ userId: recipient }],
    ...options,
  });
  t.after(() => adapter.close());
  return { adapter, endpoint };
}

test('ADV-ADAPTER-01 authenticated burst has a fixed pending bound and no overflow forwarding', async (t) => {
  const { adapter, endpoint } = fixture(t, { maxPending: 2 });
  const held = deferred(),
    entered = deferred();
  endpoint.submit = async (sealed) => {
    endpoint.submissions++;
    entered.resolve();
    await held.promise;
    return { object: { id: sealed.envelope.objectId }, receipt: {} };
  };
  const a = adapter.submit(request());
  await entered.promise;
  const b = adapter.submit(request());
  const overflow = await Promise.allSettled(
    Array.from({ length: 64 }, () => adapter.submit(request())),
  );
  assert.ok(overflow.every((r) => r.status === 'rejected' && r.reason.message === 'ADAPTER_BUSY'));
  assert.equal(adapter.pending, 2);
  assert.equal(endpoint.submissions, 1);
  assert.equal((await adapter.readiness()).ready, false);
  held.resolve();
  await Promise.all([a, b]);
  assert.equal(endpoint.submissions, 2);
  assert.equal(adapter.pending, 0);
  assert.equal((await adapter.readiness()).ready, true);
  await adapter.submit(request());
  assert.equal(endpoint.submissions, 3);
  for (const maxPending of [0, -1, 1.5, 1025, Infinity])
    assert.throws(
      () => new SyntheticAdapter({ database: ':memory:', endpoint, destinations: [], maxPending }),
      /maxPending/,
    );
});

test('ADV-ADAPTER-02 exceptions release queue slots without deleting ambiguous durable work', async (t) => {
  const { adapter, endpoint } = fixture(t, { maxPending: 1 });
  const original = endpoint.submit,
    body = request();
  endpoint.submit = async () => {
    throw new Error('SIMULATED_LOSS_AFTER_SEND');
  };
  await assert.rejects(adapter.submit(body), /SIMULATED_LOSS_AFTER_SEND/);
  assert.equal(adapter.pending, 0);
  assert.equal(adapter.db.prepare('SELECT COUNT(*) AS n FROM requests').get().n, 1);
  endpoint.submit = original;
  await adapter.submit(body);
  assert.equal(endpoint.seen.length, 1, 'retry keeps the identical sealed object');
  assert.equal(adapter.pending, 0);
});

test('ADV-ADAPTER-03 queued caller mutation cannot change the validated payload or scope', async (t) => {
  const { adapter, endpoint } = fixture(t);
  const held = deferred(),
    entered = deferred(),
    submit = endpoint.submit.bind(endpoint);
  endpoint.submit = async (sealed) => {
    entered.resolve();
    await held.promise;
    return submit(sealed);
  };
  const first = adapter.submit(request());
  await entered.promise;
  const body = request(),
    original = structuredClone(body);
  const queued = adapter.submit(body);
  body.payload = cryptography.createTextPayload('SYNTHETIC_MUTATION');
  body.senderUserId = randomUUID();
  body.destinationUserId = randomUUID();
  held.resolve();
  await Promise.all([first, queued]);
  assert.deepEqual(endpoint.seen[1], original.payload);
});

test('ADV-ADAPTER-04 a request expiring in the queue is rejected before sealing', async (t) => {
  const { adapter, endpoint } = fixture(t);
  const held = deferred(),
    entered = deferred();
  endpoint.submit = async (sealed) => {
    entered.resolve();
    await held.promise;
    return { object: { id: sealed.envelope.objectId }, receipt: {} };
  };
  const first = adapter.submit(request());
  await entered.promise;
  const body = request(),
    queued = adapter.submit(body);
  const rejected = assert.rejects(queued, /ADAPTER_SCHEMA_OR_REPLAY/);
  t.mock.method(Date, 'now', () => body.issuedAt + FRESHNESS_WINDOW_MS + 1);
  held.resolve();
  await first;
  await rejected;
  assert.equal(endpoint.seen.length, 1);
  assert.equal(adapter.pending, 0);
});

test('ADV-ADAPTER-05 malformed requests and stale or missing authority state fail closed', async (t) => {
  const { adapter, endpoint } = fixture(t);
  for (const invalid of [null, undefined, [], 'x', 1])
    await assert.rejects(adapter.submit(invalid), /ADAPTER_SCHEMA_OR_REPLAY/);
  assert.equal(endpoint.seen.length, 0);
  for (const payload of [
    null,
    {},
    { issuedAt: Date.now() + 10000, expiresAt: Date.now() + 20000 },
    { issuedAt: 1, expiresAt: 2 },
  ]) {
    endpoint.signed = async () => ({ payload });
    assert.equal((await adapter.readiness()).ready, false);
  }
  endpoint.signed = async () => {
    throw new Error('SYNTHETIC_SECRET_UPSTREAM_ERROR');
  };
  const state = await adapter.readiness();
  assert.equal(state.ready, false);
  assert.equal(JSON.stringify(state).includes('SYNTHETIC_SECRET'), false);
});

test('ADV-ADAPTER-06 readiness requires the exact service and successful dependencies', () => {
  const body = {
    service: 'synthetic-adapter',
    ready: true,
    checks: { database: true, capacity: true, authority: true },
  };
  assert.equal(isAdapterReady({ status: 200, body: JSON.stringify(body) }), true);
  for (const response of [
    { status: 404, body: '{}' },
    { status: 503, body: JSON.stringify(body) },
    { status: 200, body: 'not JSON' },
    { status: 200, body: JSON.stringify({ ...body, service: 'other' }) },
    { status: 200, body: JSON.stringify({ ...body, checks: { database: true, capacity: true } }) },
  ])
    assert.equal(isAdapterReady(response), false);
});

test('ADV-ADAPTER-07 partial login or bind failure clears all SDK session state', async () => {
  for (const failAt of [1, 2, 3]) {
    const endpoint = new IntegrationEndpoint({
      url: 'https://127.0.0.1',
      tls: {},
      profile: { deviceId: sender, totpSecret: 'JBSWY3DPEHPK3PXP', keys: { signing: {} } },
    });
    endpoint.token = 'synthetic-old-session';
    let calls = 0;
    endpoint.call = async () => {
      assert.equal(calls === 0 ? endpoint.token : null, null);
      if (++calls === failAt) throw new Error('SYNTHETIC_LOGIN_FAILURE');
      if (calls === 1) return { token: 'synthetic-new-session' };
      return {
        challengeId: randomUUID(),
        challenge: {
          domain: 'SIEPMU_DEVICE_PROOF_V1',
          nonce: 'a'.repeat(43),
          sessionId: randomUUID(),
          purpose: 'bind',
          deviceId: sender,
          expiresAt: Date.now() + 60000,
        },
      };
    };
    endpoint.crypto = { sign: async () => 'synthetic-signature' };
    await assert.rejects(endpoint.authenticate(), /SYNTHETIC_LOGIN_FAILURE/);
    assert.equal(calls, failAt);
    assert.equal(endpoint.token, null);
  }
});

test('ADV-ADAPTER-08 startup diagnostics preserve bounded reason codes without exception data', () => {
  const r = startupDiagnostic({
    adapterStage: 'AUTHENTICATE',
    code: 'LOGIN_DENIED',
    status: 401,
    message: 'SYNTHETIC_PASSWORD_CANARY',
    body: 'SYNTHETIC_PRIVATE_CANARY',
  });
  assert.deepEqual(r, {
    event: 'ADAPTER_STARTUP_FAILED',
    stage: 'AUTHENTICATE',
    code: 'LOGIN_DENIED',
    status: 401,
  });
  const unknown = startupDiagnostic({
    adapterStage: 'SYNTHETIC_PRIVATE',
    code: 'SYNTHETIC_PASSWORD',
    status: '401',
  });
  assert.equal(JSON.stringify(unknown).includes('SYNTHETIC'), false);
});

test('ADV-ADAPTER-09 HTTP overload is explicit and does not echo protected requests', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-adversarial-tls-'));
  const pki = generateLabPKI(dir);
  pki.issue('adapter');
  pki.issue('source');
  const material = pki.material('adapter');
  const server = createAdapterServer({
    adapter: {
      submit: async () => {
        throw new Error('ADAPTER_BUSY');
      },
    },
    tls: { ...material, requestCert: true, clientFingerprints: [pki.pin('source')] },
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => {
    await new Promise((r) => server.close(r));
    rmSync(dir, { recursive: true, force: true });
  });
  const r = await requestBytes(`https://127.0.0.1:${server.address().port}/v1/messages`, {
    tls: pki.material('source'),
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request()),
  });
  assert.equal(r.status, 503);
  assert.equal(r.headers['retry-after'], '1');
  assert.deepEqual(JSON.parse(r.body), { version: 1, code: 'ADAPTER_BUSY' });
});

test('ADV-ADAPTER-10 real startup failure is diagnosable and expired sessions withdraw readiness', async (t) => {
  const f = await provision(),
    stack = await startSecureStack(f.dir);
  const work = mkdtempSync(join(tmpdir(), 'siepmu-adversarial-process-'));
  let adapter;
  t.after(async () => {
    await adapter?.stop();
    await stack.stop();
    rmSync(work, { recursive: true, force: true });
    rmSync(f.dir, { recursive: true, force: true });
  });
  await assert.rejects(
    startLabAdapter({
      stack,
      dir: work,
      profile: { ...f.profiles.alice, password: 'synthetic-wrong-password' },
      destinations: [],
    }),
    (e) => {
      assert.equal(e.message, 'ADAPTER_EXITED');
      assert.equal(e.diagnostic.stage, 'AUTHENTICATE');
      assert.equal(e.diagnostic.code, 'LOGIN_DENIED');
      assert.equal(JSON.stringify(e).includes(f.profiles.alice.password), false);
      return true;
    },
  );
  adapter = await startLabAdapter({
    stack,
    dir: work,
    profile: f.profiles.alice,
    destinations: [],
  });
  const ready = () => requestBytes(adapter.url + '/ready', { tls: adapter.sourceTls });
  assert.equal(isAdapterReady(await ready()), true);
  assert.equal(
    (await requestBytes(adapter.url + '/ready', { tls: stack.pki.material('unit-denied') })).status,
    403,
  );
  const db = new DatabaseSync(join(f.dir, 'control.sqlite'));
  db.prepare('UPDATE sessions SET expires_at=0 WHERE user_id=?').run(f.profiles.alice.userId);
  db.close();
  const expired = await ready();
  assert.equal(expired.status, 503);
  assert.equal(JSON.parse(expired.body).checks.authority, false);
});

test('ADV-ADAPTER-11 synthetic adapter is observed as a trusted plaintext endpoint, not a ciphertext-only connector', async (t) => {
  const { adapter, endpoint } = fixture(t);
  const body = request();
  await adapter.submit(body);
  assert.equal(cryptography.unpackPayload(endpoint.seen[0]).text, 'SYNTHETIC_ADVERSARIAL_CANARY');
  assert.equal(endpoint.profile.userId, sender);
  // This passing boundary observation records a qualification blocker, not confidentiality proof.
});
