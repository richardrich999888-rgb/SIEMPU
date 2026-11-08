import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IUDX_CONTRACT,
  prepareIudxEntityRequest,
  readIudxEntity,
} from '../integrations/india-dpi/iudx-resource-reader.mjs';

const resourceId = '123e4567-e89b-12d3-a456-426614174000';
const token = 'synthetic.JWT-like.token';
const baseUrl = 'https://iudx-mock.example.test/';
const config = { baseUrl, allowedOrigins: ['https://iudx-mock.example.test'], resourceId, token };
const mockResponse = (status, body = { results: [] }, contentType = 'application/json') => ({
  status,
  headers: { get: (n) => (n === 'content-type' ? contentType : null) },
  text: async () => JSON.stringify(body),
});

// No network and no external credentials are used by any test.
test('uses the published IUDX read-only query contract', () => {
  const req = prepareIudxEntityRequest(config);
  const url = new URL(req.url);
  assert.equal(IUDX_CONTRACT.apiVersion, '5.6.0');
  assert.equal(url.origin, 'https://iudx-mock.example.test');
  assert.equal(url.pathname, '/ngsi-ld/v1/entities');
  assert.deepEqual([...url.searchParams], [['id', resourceId]]);
  assert.equal(req.init.method, 'GET');
  assert.equal(req.init.redirect, 'error');
  assert.equal(req.init.headers.token, token);
  assert.equal(req.init.headers.authorization, undefined);
});

test('refuses insecure origins, authority changes, nonroot base paths and credentials', () => {
  for (const rejected of [
    { baseUrl: 'http://iudx-mock.example.test/' },
    { baseUrl: 'https://evil.example.test/' },
    { baseUrl: 'https://iudx-mock.example.test/other' },
    { baseUrl: 'https://user:pass@iudx-mock.example.test/' },
    { baseUrl: 'https://iudx-mock.example.test/?id=unexpected' },
    { allowedOrigins: ['https://another.example.test'] },
  ]) assert.throws(() => prepareIudxEntityRequest({ ...config, ...rejected }));
});

test('refuses missing tokens, header injection, invalid IDs and implicit access', () => {
  for (const rejected of [
    { token: '' }, { token: 'a\r\nX-Test: true' },
    { token: 'x'.repeat(513) }, { resourceId: 'x/../secrets' },
    { resourceId: 'not-a-uuid' }, { allowedOrigins: [] },
  ]) assert.throws(() => prepareIudxEntityRequest({ ...config, ...rejected }));
});

test('accepts a synthetic JSON result from an explicitly injected mock only', async () => {
  let count = 0;
  const received = await readIudxEntity({
    ...config,
    fetchFn: async (url, options) => {
      count += 1;
      assert.match(url, /ngsi-ld\/v1\/entities/);
      assert.equal(options.headers.token, token);
      assert.equal(options.redirect, 'error');
      return mockResponse(200, { results: [{ id: resourceId, synthetic: true }] });
    },
  });
  assert.equal(count, 1);
  assert.equal(received.status, 'RECEIVED_UNTRUSTED');
  assert.deepEqual(received.entity.results, [{ id: resourceId, synthetic: true }]);
});

test('refuses absent transport and propagates no sensitive upstream errors', async () => {
  await assert.rejects(readIudxEntity(config), { code: 'IUDX_TRANSPORT_REQUIRED' });
  await assert.rejects(readIudxEntity({
    ...config,
    fetchFn: async () => { throw new Error('secret ' + token); },
  }), (e) => e.code === 'IUDX_TRANSPORT_FAILED' && !e.message.includes(token));
});

test('rejects access denial, redirects, rate limits, upstream errors and malformed JSON', async () => {
  for (const status of [401, 403]) {
    await assert.rejects(readIudxEntity({ ...config, fetchFn: async () => mockResponse(status) }),
      { code: 'IUDX_ACCESS_DENIED' });
  }
  for (const status of [301, 302, 307, 429, 500]) {
    await assert.rejects(readIudxEntity({ ...config, fetchFn: async () => mockResponse(status) }),
      { code: 'IUDX_UPSTREAM_REJECTED' });
  }
  await assert.rejects(readIudxEntity({
    ...config, fetchFn: async () => ({ ...mockResponse(200), text: async () => '{bad' }),
  }), { code: 'IUDX_RESPONSE_INVALID' });
});

test('bounds response types, content types and JSON size; handles empty result explicitly', async () => {
  const empty = await readIudxEntity({ ...config, fetchFn: async () => mockResponse(204) });
  assert.deepEqual(empty, { status: 'EMPTY', entity: null });
  await assert.rejects(readIudxEntity({
    ...config, fetchFn: async () => mockResponse(200, { results: [] }, 'text/html'),
  }), { code: 'IUDX_CONTENT_TYPE' });
  await assert.rejects(readIudxEntity({
    ...config, maxResponseBytes: 32,
    fetchFn: async () => mockResponse(200, { raw: 'x'.repeat(1000) }),
  }), { code: 'IUDX_RESPONSE_LIMIT' });
  for (const body of [null, 'plain', [1, 2]]) {
    await assert.rejects(readIudxEntity({ ...config, fetchFn: async () => mockResponse(200, body) }),
      { code: 'IUDX_RESPONSE_INVALID' });
  }
  await assert.rejects(readIudxEntity({
    ...config, fetchFn: async () => ({ ...mockResponse(200), headers: {
      get: (n) => n === 'content-type' ? 'application/json' : n === 'content-length' ? '9999999' : null,
    } }),
  }), { code: 'IUDX_RESPONSE_LIMIT' });
});

test('refuses an oversized streamed response before buffering an entire payload', async () => {
  const chunks = [new Uint8Array(20), new Uint8Array(20)];
  let consumed = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (consumed === chunks.length) return controller.close();
      controller.enqueue(chunks[consumed++]);
    },
  });
  await assert.rejects(readIudxEntity({
    ...config,
    maxResponseBytes: 32,
    fetchFn: async () => ({
      status: 200,
      headers: { get: (n) => (n === 'content-type' ? 'application/json' : null) },
      body,
    }),
  }), { code: 'IUDX_RESPONSE_LIMIT' });
});
