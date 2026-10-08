import { relayHeaders, readRelaySecret, sha256 } from './auth.mjs';

/** @param {{baseUrl?: string, secret?: Uint8Array, secretFile?: string, maxBytes?: number, fetchImpl?: (input: URL, init: RequestInit) => Promise<Response>}} [options] */
export function createRelayClient({
  baseUrl = process.env.SIEPMU_RELAY_URL || 'http://127.0.0.1:8082',
  secret,
  secretFile = process.env.SIEPMU_RELAY_SECRET_FILE,
  maxBytes = 4 * 1024 * 1024,
  fetchImpl = fetch,
} = {}) {
  const key =
    secret ||
    readRelaySecret(secretFile || `${process.env.SIEPMU_DATA_DIR || '.data'}/relay.secret`);
  const url = new URL(baseUrl);
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/'
  )
    throw new Error('Invalid relay base URL');
  if (
    url.protocol !== 'https:' &&
    !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) &&
    process.env.SIEPMU_ALLOW_REMOTE_HTTP !== '1'
  )
    throw new Error('Remote relay requires TLS or explicit internal-network override');
  /** @param {'GET' | 'PUT'} method @param {string} hash @param {Buffer<ArrayBuffer>} [body] */
  async function request(method, hash, body = Buffer.alloc(0)) {
    if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error('Invalid ciphertext hash');
    const path = `/blobs/${hash}`;
    const response = await fetchImpl(new URL(path, url), {
      method,
      headers: {
        ...relayHeaders(key, method, path, body),
        ...(method === 'PUT' ? { 'content-type': 'application/octet-stream' } : {}),
      },
      ...(method === 'PUT' ? { body } : {}),
      signal: AbortSignal.timeout(10_000),
      redirect: 'error',
    });
    if (!response.ok)
      throw Object.assign(new Error('Ciphertext relay unavailable or request rejected'), {
        code: 'RELAY_ERROR',
        status: response.status,
      });
    if (method === 'PUT') {
      /** @type {unknown} */
      const result = await response.json();
      if (
        !result ||
        typeof result !== 'object' ||
        !('hash' in result) ||
        !('size' in result) ||
        result.hash !== hash ||
        result.size !== body.length
      )
        throw new Error('Invalid relay receipt');
      return { hash, size: body.length };
    }
    const length = Number(response.headers.get('content-length'));
    if (length > maxBytes) throw new Error('Relay response too large');
    if (!response.body) throw new Error('Relay response has no body');
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxBytes) {
        await response.body.cancel().catch(() => {});
        throw new Error('Relay response too large');
      }
      chunks.push(Buffer.from(chunk));
    }
    const ciphertext = Buffer.concat(chunks);
    if (sha256(ciphertext) !== hash) throw new Error('Relay ciphertext digest mismatch');
    return ciphertext;
  }
  return {
    /** @param {string} hash @param {Uint8Array} bytes */
    putBlob: async (hash, bytes) => {
      const result = await request('PUT', hash, Buffer.from(bytes));
      if (Buffer.isBuffer(result)) throw new Error('Unexpected blob receipt');
      return result;
    },
    /** @param {string} hash */
    getBlob: async (hash) => {
      const result = await request('GET', hash);
      if (!Buffer.isBuffer(result)) throw new Error('Unexpected blob body');
      return result;
    },
  };
}
