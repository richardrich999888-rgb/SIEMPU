import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { generateLabPKI } from '../deployment/secure/lab-pki.mjs';
import { createTransportServer } from '../packages/transport/tls.mjs';
import { coreFixture } from './helpers/fixture.mjs';
import { createObject, decryptObject } from './helpers/client.mjs';
import {
  IUDX_CONTRACT,
  prepareIudxEntityRequest,
  readIudxEntity,
  createIudxLoopbackReader,
} from '../integrations/india-dpi/iudx-resource-reader.mjs';

const resourceId = '123e4567-e89b-12d3-a456-426614174000';
const token = 'synthetic.JWT.token';
const baseUrl = 'https://iudx-mock.example.test/';
const config = { baseUrl, allowedOrigins: ['https://iudx-mock.example.test'], resourceId, token };
const entity = () => ({
  type: 'urn:dx:rs:success',
  title: 'Success',
  results: [{ id: resourceId, synthetic: true }],
});
const response = (body = entity(), status = 200, headers = {}) =>
  new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
const read = (fetchFn, extra = {}) => readIudxEntity({ ...config, ...extra, fetchFn });

// Synthetic data only. Concrete transport tests bind literal loopback, never a government API.
test('pins the DX proxy v5.6.0 query contract; upstream tokens are not local identities', () => {
  const req = prepareIudxEntityRequest(config),
    url = new URL(req.url);
  assert.equal(IUDX_CONTRACT.apiVersion, '5.6.0');
  assert.match(IUDX_CONTRACT.source, new RegExp(IUDX_CONTRACT.upstreamCommit));
  assert.match(IUDX_CONTRACT.sourceSha256, /^[a-f0-9]{64}$/);
  assert.equal(url.origin, 'https://iudx-mock.example.test');
  assert.equal(url.pathname, '/ngsi-ld/v1/entities');
  assert.deepEqual([...url.searchParams], [['id', resourceId]]);
  assert.equal(req.init.method, 'GET');
  assert.equal(req.init.redirect, 'error');
  assert.equal(req.init.headers.token, token);
  assert.equal(req.init.headers.authorization, undefined);
  assert.equal(req.init.body, undefined);
  assert.ok(!req.url.includes(token));
});

test('refuses origin confusion, credentials, nonroot paths, noncanonical encodings and implicit allowlists', () => {
  for (const baseUrl of [
    'http://iudx-mock.example.test/',
    'https://evil.example.test/',
    'https://iudx-mock.example.test.evil.test',
    'https://iudx-mock.example.test/other',
    'https://user:pass@iudx-mock.example.test/',
    'https://iudx-mock.example.test/?id=unexpected',
    'https://iudx-mock.example.test/#x',
    'https://iudx-mock.example.test:8443',
    'https://iudx-mock.example.test/../',
    'https://%69udx-mock.example.test',
    'https://iudx-mock.example.test\\@evil.test',
  ])
    assert.throws(() => prepareIudxEntityRequest({ ...config, baseUrl }));
  for (const allowedOrigins of [
    undefined,
    [],
    ['https://another.example.test'],
    [baseUrl],
    ['not a URL'],
  ])
    assert.throws(() => prepareIudxEntityRequest({ ...config, allowedOrigins }));
});

test('refuses missing or malformed tokens and IDs before invoking a transport', async () => {
  let calls = 0;
  for (const rejected of [
    { token: '' },
    { token: 'a\r\nX-Test: true' },
    { token: 'x'.repeat(513) },
    { token: 'invalid token' },
    { token: 'outside-profile_' },
    { resourceId: 'x/../secrets' },
    { resourceId: 'not-a-uuid' },
  ])
    await assert.rejects(
      read(async () => {
        calls++;
        return response();
      }, rejected),
    );
  assert.equal(calls, 0);
});

test('accepts the explicit local success subset, hashes exact received bytes and freezes untrusted content', async () => {
  let calls = 0;
  const result = await read(async (url, options) => {
    calls++;
    assert.match(url, /ngsi-ld\/v1\/entities/);
    assert.equal(options.headers.token, token);
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    return response();
  });
  assert.equal(calls, 1);
  assert.equal(result.status, 'RECEIVED_UNTRUSTED');
  assert.deepEqual(result.entity, entity());
  assert.equal(
    result.provenance.sha256,
    createHash('sha256').update(JSON.stringify(entity())).digest('hex'),
  );
  assert.throws(() => {
    result.entity.results[0].synthetic = false;
  }, TypeError);
});

test('refuses absent transport and never exposes upstream error messages or credentials', async () => {
  await assert.rejects(readIudxEntity(config), { code: 'IUDX_TRANSPORT_REQUIRED' });
  await assert.rejects(
    read(async () => {
      throw new Error('secret ' + token);
    }),
    (e) =>
      e.code === 'IUDX_TRANSPORT_FAILED' && !e.message.includes(token) && e.cause === undefined,
  );
});

test('refuses access denial, redirection, rate limits and upstream errors without echoing bodies', async () => {
  for (const status of [401, 403, 301, 302, 307, 308, 404, 429, 500])
    await assert.rejects(
      read(async () => response({ secret: token }, status)),
      { code: [401, 403].includes(status) ? 'IUDX_ACCESS_DENIED' : 'IUDX_UPSTREAM_REJECTED' },
    );
  for (const changed of [{ redirected: true }, { url: 'https://evil.test' }]) {
    const res = response();
    for (const [key, value] of Object.entries(changed)) Object.defineProperty(res, key, { value });
    await assert.rejects(
      read(async () => res),
      { code: 'IUDX_REDIRECT_DENIED' },
    );
  }
});

test('handles no-content explicitly and rejects invalid content types and nonstreaming fallbacks', async () => {
  assert.deepEqual(await read(async () => response(null, 204)), { status: 'EMPTY', entity: null });
  for (const type of ['text/html', 'application/jsonp', ''])
    await assert.rejects(
      read(async () => response(entity(), 200, { 'content-type': type })),
      { code: 'IUDX_CONTENT_TYPE' },
    );
  let textCalled = false;
  await assert.rejects(
    read(async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      text: async () => {
        textCalled = true;
        return '{}';
      },
    })),
    { code: 'IUDX_RESPONSE_INVALID' },
  );
  assert.equal(textCalled, false);
});

test('rejects malformed JSON, invalid UTF-8 and arbitrary or manipulated schemas', async () => {
  for (const bytes of [Buffer.from('{bad'), Buffer.from([0xc0, 0xaf])])
    await assert.rejects(
      read(async () => new Response(bytes, { headers: { 'content-type': 'application/json' } })),
      { code: 'IUDX_RESPONSE_INVALID' },
    );
  for (const body of [
    null,
    'plain',
    [1, 2],
    {},
    { results: [] },
    { ...entity(), type: 'urn:dx:rs:failure' },
    { ...entity(), authority: true },
    { ...entity(), results: [{ id: 'different-resource' }] },
    { ...entity(), totalHits: -1 },
    { ...entity(), results: [null] },
    { ...entity(), title: 'x'.repeat(257) },
  ])
    await assert.rejects(
      read(async () => response(body)),
      { code: 'IUDX_SCHEMA' },
    );
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const body = entity();
    body.results[0].nested = JSON.parse('{"' + key + '":{"admin":true}}');
    await assert.rejects(
      read(async () => response(body)),
      { code: 'IUDX_SCHEMA' },
    );
  }
  assert.equal({}.admin, undefined);
});

test('bounds nesting, entry count, non-finite numeric values and result count', async () => {
  const deep = entity();
  let value = deep.results[0];
  for (let i = 0; i < 33; i++) value = value.child = {};
  for (const body of [
    deep,
    { ...entity(), results: Array.from({ length: 1001 }, () => ({ id: resourceId })) },
    { ...entity(), results: [{ id: resourceId, values: Array(21000).fill(1) }] },
  ])
    await assert.rejects(
      read(async () => response(body)),
      { code: 'IUDX_SCHEMA' },
    );
  await assert.rejects(
    read(
      async () =>
        new Response(JSON.stringify(entity()).replace('true', '1e999'), {
          headers: { 'content-type': 'application/json' },
        }),
    ),
    { code: 'IUDX_SCHEMA' },
  );
});

test('bounds announced and chunked lengths and cancels unfinished rejected streams', async () => {
  for (const length of ['9999999', '-1', 'NaN'])
    await assert.rejects(
      read(async () => response(entity(), 200, { 'content-length': length })),
      { code: 'IUDX_RESPONSE_LIMIT' },
    );
  let canceled = false,
    consumed = 0;
  const body = new ReadableStream({
    pull(c) {
      consumed++;
      c.enqueue(new Uint8Array(20));
    },
    cancel() {
      canceled = true;
    },
  });
  await assert.rejects(
    read(async () => new Response(body, { headers: { 'content-type': 'application/json' } }), {
      maxResponseBytes: 32,
    }),
    { code: 'IUDX_RESPONSE_LIMIT' },
  );
  assert.ok(canceled);
  assert.ok(consumed <= 3);
  let deniedCanceled = false;
  await assert.rejects(
    read(
      async () =>
        new Response(
          new ReadableStream({
            cancel() {
              deniedCanceled = true;
            },
          }),
          { status: 403 },
        ),
    ),
    { code: 'IUDX_ACCESS_DENIED' },
  );
  assert.ok(deniedCanceled);
});

test('enforces a whole-request deadline before headers and while a body is stalled', async () => {
  let signal,
    canceled = false;
  await assert.rejects(
    read(
      async (_url, options) => {
        signal = options.signal;
        return new Promise(() => {});
      },
      { timeoutMs: 20 },
    ),
    { code: 'IUDX_DEADLINE' },
  );
  assert.ok(signal.aborted);
  await assert.rejects(
    read(
      async () =>
        new Response(
          new ReadableStream({
            cancel() {
              canceled = true;
            },
          }),
          { headers: { 'content-type': 'application/json' } },
        ),
      { timeoutMs: 20 },
    ),
    { code: 'IUDX_DEADLINE' },
  );
  assert.ok(canceled);
  for (const extra of [
    { timeoutMs: 0 },
    { timeoutMs: 10001 },
    { maxResponseBytes: 0 },
    { maxResponseBytes: 1048577 },
  ])
    await assert.rejects(read(async () => response(), extra));
});

test('real TLS loopback enforces opt-in, CA, peer hostname, read-only requests and no redirected token leakage', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-iudx-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const pki = generateLabPKI(join(dir, 'pki'));
  pki.issue('server');
  pki.issue('wrong', { wrongHost: true });
  const material = pki.material('server');
  let seen = 0,
    leaked = 0,
    mode = 'ok';
  async function listen(handler, tls = material) {
    const server = createTransportServer(handler, { ...tls, requestCert: false });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    t.after(
      () =>
        new Promise((r) => {
          server.close(r);
          server.closeAllConnections();
        }),
    );
    return 'https://127.0.0.1:' + server.address().port;
  }
  const destination = await listen((_q, res) => {
    leaked++;
    res.end('{}');
  });
  const baseUrl = await listen((req, res) => {
    seen++;
    assert.equal(req.socket.getProtocol(), 'TLSv1.3');
    assert.equal(req.method, 'GET');
    assert.equal(req.url, '/ngsi-ld/v1/entities?id=' + resourceId);
    assert.equal(req.headers.token, token);
    assert.equal(req.headers.authorization, undefined);
    assert.equal(req.headers['content-length'], undefined);
    if (mode === 'redirect') {
      res.writeHead(302, { location: destination });
      res.end();
      return;
    }
    if (mode === 'large') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.write('x'.repeat(1024));
      res.end();
      return;
    }
    if (mode === 'deny') {
      res.writeHead(401);
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(entity()));
  });
  const factory = { enabled: true, baseUrl, ca: material.ca, maxResponseBytes: 512 };
  for (const changed of [
    { enabled: false },
    { enabled: undefined },
    { baseUrl: 'https://public.example.test' },
    { baseUrl: 'https://localhost' },
    { baseUrl: 'https://2130706433' },
    { baseUrl: 'https://127.0.0.2' },
    { ca: undefined },
  ])
    assert.throws(() => createIudxLoopbackReader({ ...factory, ...changed }));
  const reader = createIudxLoopbackReader(factory);
  assert.equal((await reader.read({ resourceId, token })).status, 'RECEIVED_UNTRUSTED');
  mode = 'redirect';
  await assert.rejects(reader.read({ resourceId, token }), { code: 'IUDX_TRANSPORT_FAILED' });
  assert.equal(leaked, 0);
  mode = 'large';
  await assert.rejects(reader.read({ resourceId, token }), { code: 'IUDX_TRANSPORT_FAILED' });
  mode = 'deny';
  await assert.rejects(reader.read({ resourceId, token }), { code: 'IUDX_ACCESS_DENIED' });
  const before = seen;
  const foreign = generateLabPKI(join(dir, 'foreign'));
  foreign.issue('client');
  await assert.rejects(
    createIudxLoopbackReader({ ...factory, ca: foreign.material('client').ca }).read({
      resourceId,
      token,
    }),
    { code: 'IUDX_TRANSPORT_FAILED' },
  );
  assert.equal(seen, before);
  const wrong = await listen(() => {
    throw new Error('Wrong TLS identity reached handler');
  }, pki.material('wrong'));
  await assert.rejects(
    createIudxLoopbackReader({ ...factory, baseUrl: wrong }).read({ resourceId, token }),
    { code: 'IUDX_TRANSPORT_FAILED' },
  );
});

test('external API tokens and embedded roles cannot become personnel or administrator authority', async (t) => {
  const f = await coreFixture(t);
  const untrusted = entity();
  untrusted.results[0].claims = { role: 'admin', missionIds: ['DEMO-MISSION'], status: 'VERIFIED' };
  const received = await read(async () => response(untrusted));
  assert.equal(received.status, 'RECEIVED_UNTRUSTED');
  for (const path of ['/api/grants', '/api/admin/users']) {
    const denied = await f.transport('POST', path, received.entity, token);
    assert.equal(denied.status, 401);
  }
  await f.clients.alice.authenticate();
  const denied = await f.clients.alice.request('POST', '/api/admin/users', received.entity);
  assert.equal(denied.status, 403);
  // Explicit synthetic endpoint action: content cannot choose identity, policy or recipient.
  await f.clients.bob.authenticate();
  const text = JSON.stringify(received.entity);
  const sealed = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant(), {
    data: text,
  });
  assert.ok(!JSON.stringify(sealed).includes(text));
  await f.clients.alice.submit(sealed);
  const id = sealed.envelope.objectId;
  assert.equal((await f.clients.alice.prepare(id)).status, 200);
  const control = await f.clients.bob.ok('GET', '/api/control');
  assert.equal((await f.clients.alice.claim(id, control.payload.epoch)).status, 403);
  const released = await f.clients.bob.claim(id, control.payload.epoch);
  assert.equal(released.status, 200);
  assert.equal(decryptObject(released.body, f.profiles.bob).bytes.toString(), text);
  assert.equal(released.body.envelope.senderUserId, f.profiles.alice.userId);
});
