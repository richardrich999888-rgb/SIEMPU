/** Endpoint-only, opt-in laboratory reader. No production route or authority mapping. */
import { createHash } from 'node:crypto';
import { requestBytes } from '../../packages/transport/tls.mjs';

export const IUDX_CONTRACT = Object.freeze({
  profile: 'SIEPMU_DX_READ_V1',
  apiVersion: '5.6.0',
  method: 'GET',
  path: '/ngsi-ld/v1/entities',
  upstreamCommit: 'a6d2bbb2199f1db65aa67e7b807c5241aea2895c',
  sourceSha256: '8e11d6138029dd94d3915472aa8bc46934fcc89f0a1b85a8a91b51315acf74c4',
  source:
    'https://github.com/datakaveri/dx-rs-proxy/blob/a6d2bbb2199f1db65aa67e7b807c5241aea2895c/docs/openapi.yaml',
});
const UUID = /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/;
const fail = (code) => Object.assign(new Error(code), { code });
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const codes = new Set([
  'IUDX_DEADLINE',
  'IUDX_RESPONSE_INVALID',
  'IUDX_RESPONSE_LIMIT',
  'IUDX_CONTENT_TYPE',
  'IUDX_ACCESS_DENIED',
  'IUDX_UPSTREAM_REJECTED',
  'IUDX_REDIRECT_DENIED',
  'IUDX_TRANSPORT_FAILED',
  'IUDX_SCHEMA',
]);
function origin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw fail('IUDX_ORIGIN_CONFIG');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    (value !== url.origin && value !== url.origin + '/')
  )
    throw fail('IUDX_ORIGIN_DENIED');
  return url.origin;
}
export function prepareIudxEntityRequest({ baseUrl, allowedOrigins, resourceId, token }) {
  if (
    !Array.isArray(allowedOrigins) ||
    !allowedOrigins.length ||
    !allowedOrigins.every((s) => typeof s === 'string' && origin(s) === s)
  )
    throw fail('IUDX_ORIGIN_CONFIG');
  const selected = origin(baseUrl);
  if (!allowedOrigins.includes(selected)) throw fail('IUDX_ORIGIN_DENIED');
  if (typeof resourceId !== 'string' || !UUID.test(resourceId)) throw fail('IUDX_RESOURCE_ID');
  // Conservative literal profile from the pinned specification; token authenticity belongs
  // to the provider. This is deliberately not a general JWT or personnel-identity validator.
  if (typeof token !== 'string' || token.length > 512 || !/^[a-zA-Z0-9/@.]+$/.test(token))
    throw fail('IUDX_TOKEN_REQUIRED');
  const url = new URL(IUDX_CONTRACT.path, selected);
  url.searchParams.set('id', resourceId);
  return Object.freeze({
    url: url.toString(),
    init: Object.freeze({
      method: 'GET',
      redirect: 'error',
      headers: Object.freeze({ accept: 'application/json', token }),
    }),
  });
}
function validateEntity(entity, resourceId) {
  const allowed = new Set(['type', 'title', 'results', 'limit', 'offset', 'totalHits']);
  if (
    !object(entity) ||
    Object.keys(entity).some((k) => !allowed.has(k)) ||
    entity.type !== 'urn:dx:rs:success' ||
    typeof entity.title !== 'string' ||
    entity.title.length > 256 ||
    !Array.isArray(entity.results) ||
    entity.results.length > 1000 ||
    !entity.results.every((r) => object(r) && r.id === resourceId)
  )
    throw fail('IUDX_SCHEMA');
  for (const k of ['limit', 'offset', 'totalHits'])
    if (k in entity && (!Number.isSafeInteger(entity[k]) || entity[k] < 0))
      throw fail('IUDX_SCHEMA');
  const stack = [[entity, 0]];
  let nodes = 0;
  while (stack.length) {
    const [value, depth] = stack.pop();
    if (++nodes > 20000 || depth > 32 || (typeof value === 'number' && !Number.isFinite(value)))
      throw fail('IUDX_SCHEMA');
    if (value && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        if (['__proto__', 'constructor', 'prototype'].includes(key)) throw fail('IUDX_SCHEMA');
        stack.push([child, depth + 1]);
      }
      Object.freeze(value);
    }
  }
  return entity;
}

/** Trusted injected transport for contract tests. Never grants local identity or release authority. */
export async function readIudxEntity({
  fetchFn,
  maxResponseBytes = 256 * 1024,
  timeoutMs = 2000,
  ...config
}) {
  if (typeof fetchFn !== 'function') throw fail('IUDX_TRANSPORT_REQUIRED');
  if (
    !Number.isSafeInteger(maxResponseBytes) ||
    maxResponseBytes < 1 ||
    maxResponseBytes > 1024 * 1024
  )
    throw fail('IUDX_RESPONSE_LIMIT');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 10000)
    throw fail('IUDX_DEADLINE_CONFIG');
  const request = prepareIudxEntityRequest(config);
  const controller = new AbortController();
  let reader, timer;
  const cancel = () => {
    try {
      void reader?.cancel().catch(() => {});
    } catch {}
  };
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      cancel();
      reject(fail('IUDX_DEADLINE'));
    }, timeoutMs);
  });
  const work = async () => {
    let response;
    try {
      response = await fetchFn(request.url, { ...request.init, signal: controller.signal });
    } catch {
      throw fail('IUDX_TRANSPORT_FAILED');
    }
    if (controller.signal.aborted) {
      try {
        void response?.body?.cancel?.().catch(() => {});
      } catch {}
      throw fail('IUDX_DEADLINE');
    }
    if (!response || !Number.isInteger(response.status)) throw fail('IUDX_RESPONSE_INVALID');
    if (response.body?.getReader) reader = response.body.getReader();
    if (response.redirected || (response.url && response.url !== request.url))
      throw fail('IUDX_REDIRECT_DENIED');
    if (response.status === 204) return Object.freeze({ status: 'EMPTY', entity: null });
    if ([401, 403].includes(response.status)) throw fail('IUDX_ACCESS_DENIED');
    if (response.status !== 200) throw fail('IUDX_UPSTREAM_REJECTED');
    const type = response.headers?.get?.('content-type');
    if (typeof type !== 'string' || !/^application\/json(?:\s*;|\s*$)/i.test(type))
      throw fail('IUDX_CONTENT_TYPE');
    const length = response.headers?.get?.('content-length');
    if (
      length !== null &&
      length !== undefined &&
      (!/^\d+$/.test(length) || Number(length) > maxResponseBytes)
    )
      throw fail('IUDX_RESPONSE_LIMIT');
    if (!reader) throw fail('IUDX_RESPONSE_INVALID');
    const chunks = [];
    let total = 0;
    while (true) {
      const part = await reader.read();
      if (controller.signal.aborted) throw fail('IUDX_DEADLINE');
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) throw fail('IUDX_RESPONSE_INVALID');
      total += part.value.byteLength;
      if (total > maxResponseBytes) throw fail('IUDX_RESPONSE_LIMIT');
      chunks.push(Buffer.from(part.value));
    }
    const bytes = Buffer.concat(chunks);
    const entity = validateEntity(
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
      config.resourceId,
    );
    return Object.freeze({
      status: 'RECEIVED_UNTRUSTED',
      entity,
      provenance: Object.freeze({
        profile: IUDX_CONTRACT.profile,
        origin: new URL(request.url).origin,
        resourceId: config.resourceId,
        sha256: createHash('sha256').update(bytes).digest('hex'),
      }),
    });
  };
  try {
    return await Promise.race([work(), deadline]);
  } catch (error) {
    throw fail(codes.has(error?.code) ? error.code : 'IUDX_RESPONSE_INVALID');
  } finally {
    clearTimeout(timer);
    controller.abort();
    cancel();
  }
}

/** Concrete TLS 1.3 lab interface: literal loopback only, private CA, no DNS or public network. */
export function createIudxLoopbackReader({
  enabled = false,
  baseUrl,
  ca,
  timeoutMs = 2000,
  maxResponseBytes = 256 * 1024,
}) {
  const selected = origin(baseUrl);
  if (
    enabled !== true ||
    !['127.0.0.1', '[::1]'].includes(new URL(selected).hostname) ||
    !Buffer.isBuffer(ca) ||
    ca.length === 0
  )
    throw fail('IUDX_LAB_CONFIG');
  const trust = Buffer.from(ca);
  return Object.freeze({
    read: ({ resourceId, token }) =>
      readIudxEntity({
        baseUrl: selected,
        allowedOrigins: [selected],
        resourceId,
        token,
        timeoutMs,
        maxResponseBytes,
        fetchFn: async (url, init) => {
          const response = await requestBytes(url, {
            method: 'GET',
            headers: init.headers,
            tls: { ca: trust },
            timeoutMs,
            maxBytes: maxResponseBytes,
          });
          return new Response(response.status === 204 ? null : response.body, {
            status: response.status,
            headers: response.headers,
          });
        },
      }),
  });
}
