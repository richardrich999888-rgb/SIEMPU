import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { coreFixture } from './helpers/fixture.mjs';
import { totp } from './helpers/client.mjs';
import { createRelayServer } from '../services/relay/server.mjs';
import { relayHeaders, sha256 } from '../services/relay/auth.mjs';

test('public control capabilities are exact routes; protected dispatch always authenticates', async (t) => {
  const f = await coreFixture(t);
  for (const path of ['/health', '/live', '/ready', '/api/meta']) {
    const result = await f.transport('GET', path);
    assert.equal(result.status, 200, path);
    assert.equal('token' in result.body, false);
    assert.equal('masterKey' in result.body, false);
  }
  const protectedRoutes = [
    ['GET', '/api/objects'],
    ['POST', '/api/objects'],
    ['GET', '/api/admin/overview'],
    ['POST', '/api/admin/users'],
    ['GET', '/api/evidence/export'],
    ['GET', '/api/metrics'],
    ['GET', '/api/control'],
    ['GET', '/api/directory'],
    ['GET', '/api/auth/me'],
    ['POST', '/api/auth/challenge'],
    ['POST', '/api/devices/enroll'],
    ['GET', '/api/auth/login'],
    ['PUT', '/api/auth/login'],
    ['POST', '/api/meta'],
    ['POST', '/health'],
    ['POST', '/api/auth/login/'],
    ['POST', '/api/auth/login?next=/api/objects'],
    ['POST', '/api/auth/login/../objects'],
    ['GET', '/__proto__'],
    ['GET', '/constructor'],
  ];
  for (const [method, path] of protectedRoutes) {
    for (const token of [undefined, 'invalid-session-token-that-is-long-enough']) {
      const result = await f.transport(method, path, {}, token);
      assert.equal(result.status, 401, `${method} ${path}: ${JSON.stringify(result)}`);
      assert.equal('objects' in result.body, false);
      assert.equal('token' in result.body, false);
    }
  }
  assert.equal(f.authority.get('SELECT COUNT(*) n FROM sessions').n, 0);
  const alice = f.profiles.alice;
  const rejected = await f.transport('POST', '/api/auth/login', {
    username: alice.username,
    password: 'wrong-password-for-route-test',
    otp: totp(alice.totpSecret),
  });
  assert.equal(rejected.status, 401);
  assert.equal(f.authority.get('SELECT COUNT(*) n FROM sessions').n, 0);
  await f.clients.alice.authenticate();
  assert.equal((await f.clients.alice.request('GET', '/api/objects')).status, 200);
});

test('relay route, method and Origin fields cannot replace workload authentication', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-auth-routing-'));
  const database = join(dir, 'relay.sqlite');
  const secret = randomBytes(32);
  const server = createRelayServer({ database, secret });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    });
    await rm(dir, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const ciphertext = Buffer.from('synthetic-ciphertext-routing-regression');
  const path = '/blobs/' + sha256(ciphertext);
  const send = (method, target, headers = {}, body) =>
    fetch(base + target, {
      method,
      headers,
      ...(body ? { body } : {}),
      signal: AbortSignal.timeout(3000),
    });

  for (const target of ['/health', '/health/live', '/health/ready']) {
    const response = await send('GET', target);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: 'ok', service: 'blind-ciphertext-relay' });
  }
  for (const [method, target, headers, body] of [
    ['GET', path, {}, undefined],
    ['PUT', path, { 'Content-Type': 'application/octet-stream' }, ciphertext],
    ['GET', path, { Origin: 'https://attacker.invalid' }, undefined],
    ['POST', path, {}, undefined],
    ['GET', '/health?blob=' + sha256(ciphertext), {}, undefined],
    ['GET', '/health' + path, {}, undefined],
    ['POST', '/health', {}, undefined],
    ['GET', '/blobs/not-a-digest', {}, undefined],
  ]) {
    const response = await send(method, target, headers, body);
    assert.equal(response.status, 401, `${method} ${target}`);
    assert.equal((await response.json()).error, 'WORKLOAD_AUTHENTICATION');
  }

  // The HMAC binds the original route, method, and exact bytes, not only a caller label.
  const altered = Buffer.from(ciphertext);
  altered[0] ^= 1;
  const wrongPath = '/blobs/' + 'a'.repeat(64);
  for (const [method, target, headers, body] of [
    ['PUT', path, relayHeaders(secret, 'PUT', path, ciphertext), altered],
    ['PUT', path, relayHeaders(secret, 'GET', path), ciphertext],
    ['GET', wrongPath, relayHeaders(secret, 'GET', path), undefined],
  ]) {
    const response = await send(
      method,
      target,
      { ...headers, 'Content-Type': 'application/octet-stream' },
      body,
    );
    assert.equal(response.status, 401);
  }
  const probe = new DatabaseSync(database, { readOnly: true });
  try {
    assert.equal(probe.prepare('SELECT COUNT(*) n FROM blobs').get().n, 0);
    assert.equal(probe.prepare('SELECT COUNT(*) n FROM workload_nonces').get().n, 0);
  } finally {
    probe.close();
  }

  const origin = await send('GET', path, {
    ...relayHeaders(secret, 'GET', path),
    Origin: 'https://attacker.invalid',
  });
  assert.equal(origin.status, 403);
  assert.equal((await origin.json()).error, 'WORKLOAD_ONLY');
  const malformedPath = '/blobs/not-a-digest';
  assert.equal(
    (await send('GET', malformedPath, relayHeaders(secret, 'GET', malformedPath))).status,
    404,
  );
  const put = await send(
    'PUT',
    path,
    {
      ...relayHeaders(secret, 'PUT', path, ciphertext),
      'Content-Type': 'application/octet-stream',
    },
    ciphertext,
  );
  assert.equal(put.status, 201);
  const readHeaders = relayHeaders(secret, 'GET', path);
  const get = await send('GET', path, readHeaders);
  assert.equal(get.status, 200);
  assert.deepEqual(Buffer.from(await get.arrayBuffer()), ciphertext);
  assert.equal((await send('GET', path, readHeaders)).status, 409);
});
