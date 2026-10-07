import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createWebServer } from './server.mjs';

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}
async function close(server) {
  await new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  });
}
function raw(port, path, method = 'GET', body) {
  return new Promise((resolve, reject) => {
    const call = request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: body ? { 'content-type': 'application/json' } : {},
      },
      (res) => {
        let bytes = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          bytes += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode, body: bytes }));
      },
    );
    call.on('error', reject);
    call.end(body);
  });
}

test('gateway cannot select an outbound authority through a crafted request target', async (t) => {
  let externalHits = 0;
  const observed = [];
  const unrelated = createServer((_req, res) => {
    externalHits++;
    res.end('{}');
  });
  const unrelatedPort = await listen(unrelated);
  const authority = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      observed.push({ path: req.url, method: req.method, body });
      res.setHeader('content-type', 'application/json');
      res.end('{"status":"ok"}');
    });
  });
  const authorityPort = await listen(authority);
  const gateway = createWebServer({ controlUrl: `http://127.0.0.1:${authorityPort}` });
  const gatewayPort = await listen(gateway);
  t.after(() => Promise.all([gateway, authority, unrelated].map(close)));
  for (const target of [
    `http://127.0.0.1:${unrelatedPort}/api/meta`,
    `//127.0.0.1:${unrelatedPort}/api/meta`,
    `/api/../..//127.0.0.1:${unrelatedPort}/meta`,
    `/api/\\127.0.0.1:${unrelatedPort}/meta`,
    `/api/%2f%2f127.0.0.1:${unrelatedPort}/meta`,
    `/api/meta?target=http://127.0.0.1:${unrelatedPort}/`,
    '/api/./meta',
    '/api//meta',
    '/api/meta#fragment',
  ])
    assert.equal((await raw(gatewayPort, target)).status, 400, target);
  assert.equal(externalHits, 0);
  assert.deepEqual(observed, []);
  assert.equal(
    (await raw(gatewayPort, '/api/objects/a-b_c/prepare', 'POST', '{"proof":{}}')).status,
    200,
  );
  assert.deepEqual(observed, [
    { path: '/api/objects/a-b_c/prepare', method: 'POST', body: '{"proof":{}}' },
  ]);
});

test('gateway refuses upstream redirects, oversized responses and timed-out requests', async (t) => {
  let externalHits = 0;
  const unrelated = createServer((_req, res) => {
    externalHits++;
    res.end('{}');
  });
  const externalPort = await listen(unrelated);
  const authority = createServer((req, res) => {
    if (req.url === '/api/redirect') {
      res.writeHead(302, { location: `http://127.0.0.1:${externalPort}/secret` });
      res.end();
    } else if (req.url === '/api/large') {
      res.writeHead(200, { 'content-length': '2048' });
      res.end('x'.repeat(2048));
    } else if (req.url === '/api/chunked') {
      res.write('x'.repeat(100));
      res.end('x'.repeat(100));
    }
    // /api/stall deliberately produces no response until the gateway deadline cancels it.
  });
  const authorityPort = await listen(authority);
  const gateway = createWebServer({
    controlUrl: `http://127.0.0.1:${authorityPort}`,
    maxResponseBytes: 128,
    upstreamTimeoutMs: 100,
  });
  const gatewayPort = await listen(gateway);
  t.after(() => Promise.all([gateway, authority, unrelated].map(close)));
  for (const route of ['/api/redirect', '/api/large', '/api/chunked', '/api/stall'])
    assert.equal((await raw(gatewayPort, route)).status, 503, route);
  assert.equal(externalHits, 0);
});
