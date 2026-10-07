import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { coreFixture } from './helpers/fixture.mjs';
import { createRelayServer } from '../services/relay/server.mjs';
import { relayHeaders, sha256 } from '../services/relay/auth.mjs';

test('only exact public method/path pairs bypass the protected authority handler', async (t) => {
  const f = await coreFixture(t);
  for (const path of ['/health', '/live', '/ready', '/api/meta']) {
    assert.equal((await f.transport('GET', path)).status, 200);
    assert.equal((await f.transport('POST', path, {})).status, 401);
  }
  for (const path of ['/api/auth/login', '/api/auth/login/', '/api/auth/login/extra']) {
    assert.equal((await f.transport('GET', path)).status, 401);
  }
  for (const path of ['/api/auth/login/', '/api/auth/login/extra', '/api/objects']) {
    assert.equal((await f.transport('POST', path, {})).status, 401);
  }
  // Entering the protected handler directly cannot select a public route.
  await assert.rejects(
    f.authority.dispatchAuthenticated('POST', '/api/auth/login', {}, undefined),
    (error) => error.status === 401 && error.code === 'UNAUTHENTICATED',
  );
  assert.equal(f.authority.get('SELECT count(*) n FROM sessions').n, 0);
});

test('relay health routing cannot bypass workload authentication or the post-auth Origin restriction', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'siepmu-route-boundary-'));
  const secret = randomBytes(32);
  const server = createRelayServer({ database: join(directory, 'relay.sqlite'), secret });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    });
    await rm(directory, { recursive: true, force: true });
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  for (const path of ['/health', '/health/live', '/health/ready']) {
    assert.equal((await fetch(url + path)).status, 200);
    assert.equal((await fetch(url + path, { method: 'PUT' })).status, 401);
    assert.equal((await fetch(url + path + '/')).status, 401);
  }
  const bytes = randomBytes(128);
  const path = `/blobs/${sha256(bytes)}`;
  const request = (headers) => fetch(url + path, { method: 'PUT', body: bytes, headers });
  assert.equal(
    (
      await request({
        Origin: 'https://untrusted.invalid',
        'content-type': 'application/octet-stream',
      })
    ).status,
    401,
  );
  assert.equal(
    (
      await request({
        ...relayHeaders(secret, 'PUT', path, bytes),
        Origin: 'https://untrusted.invalid',
        'content-type': 'application/octet-stream',
      })
    ).status,
    403,
  );
  const missing = await fetch(url + path, { headers: relayHeaders(secret, 'GET', path) });
  assert.equal(missing.status, 404, 'Rejected writes must not create ciphertext');
  assert.equal(
    (
      await request({
        ...relayHeaders(secret, 'PUT', path, bytes),
        'content-type': 'application/octet-stream',
      })
    ).status,
    201,
  );
  assert.equal(
    (await fetch(url + path)).status,
    401,
    'Stored ciphertext still requires workload authentication',
  );
});
