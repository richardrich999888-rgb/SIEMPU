import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createRelayServer } from './server.mjs';
import { createRelayClient } from './client.mjs';
import { relayHeaders, sha256 } from './auth.mjs';

async function fixture(t) {
  const folder = await mkdtemp(join(tmpdir(), 'siepmu-relay-'));
  const secret = randomBytes(32);
  const database = join(folder, 'relay.sqlite');
  let server;
  async function start() {
    server = createRelayServer({ database, secret });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    return `http://127.0.0.1:${server.address().port}`;
  }
  async function stop() {
    await new Promise((r) => {
      server.close(r);
      server.closeAllConnections();
    });
  }
  t.after(async () => {
    if (server.listening) await stop();
    await rm(folder, { recursive: true, force: true });
  });
  return { secret, start, stop };
}

test('relay authenticates, stores only immutable ciphertext and survives restart', async (t) => {
  const f = await fixture(t);
  let baseUrl = await f.start();
  const payload = randomBytes(512);
  const hash = sha256(payload);
  let client = createRelayClient({ baseUrl, secret: f.secret });
  assert.equal((await client.putBlob(hash, payload)).hash, hash);
  assert.deepEqual(await client.getBlob(hash), payload);
  await f.stop();
  baseUrl = await f.start();
  client = createRelayClient({ baseUrl, secret: f.secret });
  assert.deepEqual(await client.getBlob(hash), payload);
  assert.equal((await client.putBlob(hash, payload)).size, payload.length);
});

test('relay rejects missing auth, body/path tampering, stale auth and durable replay', async (t) => {
  const f = await fixture(t);
  let baseUrl = await f.start();
  const payload = randomBytes(256);
  const hash = sha256(payload);
  const path = `/blobs/${hash}`;
  const headers = {
    ...relayHeaders(f.secret, 'PUT', path, payload),
    'content-type': 'application/octet-stream',
  };
  assert.equal(
    (
      await fetch(baseUrl + path, {
        method: 'PUT',
        body: payload,
        headers: { 'content-type': 'application/octet-stream' },
      })
    ).status,
    401,
  );
  assert.equal(
    (await fetch(baseUrl + path, { method: 'PUT', body: randomBytes(256), headers })).status,
    401,
  );
  assert.equal(
    (
      await fetch(baseUrl + path, {
        method: 'PUT',
        body: payload,
        headers: {
          ...relayHeaders(f.secret, 'PUT', path, payload, Date.now() - 60_000),
          'content-type': 'application/octet-stream',
        },
      })
    ).status,
    401,
  );
  assert.equal(
    (await fetch(baseUrl + path, { method: 'PUT', body: payload, headers })).status,
    201,
  );
  await f.stop();
  baseUrl = await f.start();
  assert.equal(
    (await fetch(baseUrl + path, { method: 'PUT', body: payload, headers })).status,
    409,
  );
  const wrongPath = `/blobs/${'0'.repeat(64)}`;
  assert.equal(
    (
      await fetch(baseUrl + wrongPath, {
        method: 'PUT',
        body: payload,
        headers: {
          ...relayHeaders(f.secret, 'PUT', wrongPath, payload),
          'content-type': 'application/octet-stream',
        },
      })
    ).status,
    400,
  );
});
