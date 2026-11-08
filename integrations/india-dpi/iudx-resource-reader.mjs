/**
 * Read-only IUDX/DX public API interoperability candidate.
 * Public contract: https://github.com/datakaveri/dx-rs-proxy/blob/main/docs/openapi.yaml
 * OpenAPI 3.0.2, DX proxy v5.6.0. No IAF/DRDO/SAG endorsement.
 * No implicit network transport. All reads require an operator-pinned origin.
 */
export const IUDX_CONTRACT = Object.freeze({
  apiVersion: '5.6.0',
  method: 'GET',
  path: '/ngsi-ld/v1/entities',
  source: 'https://github.com/datakaveri/dx-rs-proxy/blob/main/docs/openapi.yaml',
});
const UUID = /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/;
const fail = (code) => Object.assign(new Error(code), { code });

/** Construct only the documented read-only query; never echo sensitive values on error. */
export function prepareIudxEntityRequest({ baseUrl, allowedOrigins, resourceId, token }) {
  if (!Array.isArray(allowedOrigins) || !allowedOrigins.length ||
      !allowedOrigins.every((s) => typeof s === 'string')) throw fail('IUDX_ORIGIN_CONFIG');
  let url;
  try { url = new URL(baseUrl); } catch { throw fail('IUDX_ORIGIN_CONFIG'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' ||
      url.search || url.hash || !allowedOrigins.includes(url.origin) ||
      url.href !== url.origin + '/') throw fail('IUDX_ORIGIN_DENIED');
  if (typeof resourceId !== 'string' || !UUID.test(resourceId)) throw fail('IUDX_RESOURCE_ID');
  if (typeof token !== 'string' || !token.length || token.length > 512 ||
      /[\x00-\x20\x7f]/.test(token)) throw fail('IUDX_TOKEN_REQUIRED');
  const requestUrl = new URL(IUDX_CONTRACT.path, url.origin);
  requestUrl.searchParams.set('id', resourceId);
  return Object.freeze({
    url: requestUrl.toString(),
    init: Object.freeze({
      method: 'GET',
      redirect: 'error',
      headers: Object.freeze({ accept: 'application/json', token }),
    }),
  });
}

/**
 * Injected transport may target only an operator-authorised IUDX proxy or a local mock.
 * Returned content remains UNTRUSTED and must not grant SIEPMU identity or access.
 */
export async function readIudxEntity({ fetchFn, maxResponseBytes = 256 * 1024, ...config }) {
  if (typeof fetchFn !== 'function') throw fail('IUDX_TRANSPORT_REQUIRED');
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 ||
      maxResponseBytes > 1024 * 1024) throw fail('IUDX_RESPONSE_LIMIT');
  const request = prepareIudxEntityRequest(config);
  let response;
  try { response = await fetchFn(request.url, request.init); }
  catch { throw fail('IUDX_TRANSPORT_FAILED'); }
  if (!response || !Number.isInteger(response.status)) throw fail('IUDX_RESPONSE_INVALID');
  if (response.status === 204) return Object.freeze({ status: 'EMPTY', entity: null });
  if (response.status === 401 || response.status === 403) throw fail('IUDX_ACCESS_DENIED');
  if (response.status !== 200) throw fail('IUDX_UPSTREAM_REJECTED');
  const contentType = response.headers?.get?.('content-type');
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;|\s*$)/i.test(contentType))
    throw fail('IUDX_CONTENT_TYPE');
  const announcedLength = response.headers?.get?.('content-length');
  if (announcedLength != null && (!/^\d+$/.test(announcedLength) ||
      Number(announcedLength) > maxResponseBytes)) throw fail('IUDX_RESPONSE_LIMIT');

  // Streamed production-style Fetch responses are bounded before buffering.
  // Text-only fallback is exclusively for synthetic contract-test mocks.
  let raw;
  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        if (!(part.value instanceof Uint8Array)) throw fail('IUDX_RESPONSE_INVALID');
        total += part.value.byteLength;
        if (total > maxResponseBytes) throw fail('IUDX_RESPONSE_LIMIT');
        chunks.push(Buffer.from(part.value));
      }
      raw = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    } catch (error) {
      if (error?.code === 'IUDX_RESPONSE_LIMIT') throw error;
      throw fail('IUDX_RESPONSE_INVALID');
    } finally {
      await reader.cancel().catch(() => {});
    }
  } else {
    try { raw = await response.text(); } catch { throw fail('IUDX_RESPONSE_INVALID'); }
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > maxResponseBytes)
      throw fail('IUDX_RESPONSE_LIMIT');
  }
  let entity;
  try { entity = JSON.parse(raw); } catch { throw fail('IUDX_RESPONSE_INVALID'); }
  if (entity === null || typeof entity !== 'object' || Array.isArray(entity))
    throw fail('IUDX_RESPONSE_INVALID');
  return { status: 'RECEIVED_UNTRUSTED', entity };
}
