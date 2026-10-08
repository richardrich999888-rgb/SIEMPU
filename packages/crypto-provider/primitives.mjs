import { createHash } from 'node:crypto';
import { canonical } from '../protocol/canonical.mjs';

export const utf8 = new TextEncoder();
export const digest = (value) =>
  createHash('sha256')
    .update(typeof value === 'string' ? value : canonical(value))
    .digest('hex');
export const copy = (value) => JSON.parse(canonical(value));
export const encode = (value) => Buffer.from(value).toString('base64url');

export function bytes(value, length, label = 'bytes') {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length))
    throw new TypeError(`Invalid ${label}`);
  return new Uint8Array(value);
}

export function decode(value, length, label = 'base64url') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value))
    throw new TypeError(`Invalid ${label}`);
  const result = Buffer.from(value, 'base64url');
  if (encode(result) !== value || (length !== undefined && result.length !== length))
    throw new TypeError(`Invalid ${label}`);
  return new Uint8Array(result);
}

export function members(value, keys) {
  canonical(value);
  if (
    !value ||
    Array.isArray(value) ||
    typeof value !== 'object' ||
    Object.keys(value).sort().join('|') !== [...keys].sort().join('|')
  )
    throw new TypeError('Unexpected or missing members');
}

export function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(value))
    throw new TypeError('Invalid identifier');
  return value;
}

export async function encryptAes(keyBytes, plaintext, aad) {
  const raw = bytes(keyBytes, 32);
  const plain = bytes(plaintext);
  try {
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: bytes(aad), tagLength: 128 },
      key,
      plain,
    );
    return { nonce: encode(nonce), ciphertext: encode(new Uint8Array(encrypted)) };
  } finally {
    raw.fill(0);
    plain.fill(0);
  }
}

export async function decryptAes(keyBytes, packet, aad) {
  members(packet, ['nonce', 'ciphertext']);
  const ciphertext = decode(packet.ciphertext);
  if (ciphertext.length < 16) throw new TypeError('Truncated authenticated ciphertext');
  const raw = bytes(keyBytes, 32);
  try {
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: decode(packet.nonce, 12),
          additionalData: bytes(aad),
          tagLength: 128,
        },
        key,
        ciphertext,
      ),
    );
  } finally {
    raw.fill(0);
  }
}

export async function deriveWrapKey(sharedSecret, salt, binding) {
  const secret = bytes(sharedSecret, 32, 'KEM shared secret');
  try {
    const input = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: bytes(salt, 32),
          info: utf8.encode(canonical({ domain: 'SIEPMU_PROVIDER_KEY_WRAP_V1', ...binding })),
        },
        input,
        256,
      ),
    );
  } finally {
    secret.fill(0);
  }
}
