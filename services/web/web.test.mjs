import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, get } from 'node:http';
import { createWebServer } from './server.mjs';

test('gateway restricts origins, hosts, assets and content type; forwards approved JSON request', async (t) => {
  let upstreamRequests = 0;
  const control = createServer((req, res) => {
    upstreamRequests++;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        path: req.url,
        authorization: req.headers.authorization,
        forwarded: req.headers['x-forwarded-host'] || null,
      }),
    );
  });
  await new Promise((r) => control.listen(0, '127.0.0.1', r));
  const gateway = createWebServer({ controlUrl: `http://127.0.0.1:${control.address().port}` });
  await new Promise((r) => gateway.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${gateway.address().port}`;
  t.after(async () => {
    await Promise.all(
      [gateway, control].map(
        (server) =>
          new Promise((r) => {
            server.close(r);
            server.closeAllConnections();
          }),
      ),
    );
  });
  let response = await fetch(base + '/');
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.match(await response.text(), /SYNTRIASS/);
  for (const path of [
    '/.data/server-key.json',
    '/package.json',
    '/services/control/server.mjs',
    '/apps/unit-client/../../.env',
    '/%2e%2e/.env',
  ])
    assert.notEqual((await fetch(base + path)).status, 200);
  const hostStatus = await new Promise((resolve, reject) => {
    const request = get(base + '/api/meta', { headers: { host: 'evil.invalid' } }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    request.on('error', reject);
  });
  assert.equal(hostStatus, 403);
  response = await fetch(base + '/api/meta', { headers: { origin: 'https://evil.invalid' } });
  assert.equal(response.status, 403);
  response = await fetch(base + '/api/auth/login', { method: 'POST', body: '{}' });
  assert.equal(response.status, 415);
  response = await fetch(base + '/api/auth/login', {
    method: 'POST',
    body: '{}',
    headers: {
      origin: base,
      'content-type': 'application/json',
      authorization: 'Bearer synthetic',
      'x-forwarded-host': 'evil.invalid',
    },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    path: '/api/auth/login',
    authorization: 'Bearer synthetic',
    forwarded: null,
  });
  const beforeInvalidTargets = upstreamRequests;
  for (const target of [
    '//evil.invalid/api/meta',
    'http://evil.invalid/api/meta',
    '/api/\\evil.invalid',
    '/api/%2f%2fevil.invalid',
    '/api/meta?redirect=https://evil.invalid',
  ]) {
    const status = await new Promise((resolve, reject) => {
      const request = get(
        { hostname: '127.0.0.1', port: gateway.address().port, path: target },
        (res) => {
          res.resume();
          resolve(res.statusCode);
        },
      );
      request.on('error', reject);
    });
    assert.equal(status, 400, target);
  }
  assert.equal(upstreamRequests, beforeInvalidTargets);
  response = await fetch(base + '/api//evil.invalid', {
    headers: { authorization: 'Bearer synthetic' },
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).code, 'INVALID_API_PATH');
  assert.equal(upstreamRequests, beforeInvalidTargets);
  response = await fetch(base + '/health/ready');
  assert.equal(response.status, 200);
});
