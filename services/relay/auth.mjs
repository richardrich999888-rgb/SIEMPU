import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

/** @param {string | Uint8Array} body */
export const sha256 = (body) => createHash('sha256').update(body).digest('hex');
/** @param {string} path */
export function readRelaySecret(path) {
  const value = readFileSync(path, 'utf8').trim();
  if (!/^[a-f0-9]{64}$/i.test(value))
    throw new Error('Relay secret must contain 32 bytes encoded as hex');
  return Buffer.from(value, 'hex');
}
/**
 * @param {Uint8Array} secret
 * @param {string} method
 * @param {string} path
 * @param {Uint8Array} body
 * @param {number | string} time
 * @param {string} nonce
 */
export function relaySignature(secret, method, path, body, time, nonce) {
  return createHmac('sha256', secret)
    .update([method, path, sha256(body), String(time), nonce].join('\n'))
    .digest('hex');
}
/**
 * @param {Uint8Array} secret
 * @param {string} method
 * @param {string} path
 * @param {Uint8Array} [body]
 * @param {number} [now]
 */
export function relayHeaders(secret, method, path, body = Buffer.alloc(0), now = Date.now()) {
  const nonce = randomBytes(16).toString('hex');
  return {
    'x-siepmu-time': String(now),
    'x-siepmu-nonce': nonce,
    'x-siepmu-signature': relaySignature(secret, method, path, body, now, nonce),
  };
}
/**
 * @param {Uint8Array} secret
 * @param {string} method
 * @param {string} path
 * @param {Uint8Array} body
 * @param {import('node:http').IncomingHttpHeaders} headers
 * @param {number} [now]
 */
export function validateRelayAuthentication(secret, method, path, body, headers, now = Date.now()) {
  const time = headers['x-siepmu-time'];
  const nonce = headers['x-siepmu-nonce'];
  const signature = headers['x-siepmu-signature'];
  if (
    typeof time !== 'string' ||
    !/^\d{13}$/.test(time) ||
    Math.abs(Number(time) - now) > 30_000 ||
    typeof nonce !== 'string' ||
    !/^[a-f0-9]{32}$/.test(nonce) ||
    typeof signature !== 'string' ||
    !/^[a-f0-9]{64}$/.test(signature)
  )
    return null;
  const expected = relaySignature(secret, method, path, body, time, nonce);
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'))
    ? { nonce, expiresAt: now + 60_000 }
    : null;
}
