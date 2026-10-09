// Implementation-under-test adapter: the same platform entry points the product calls.
// Pure functions of their inputs (no persistent state, no file or network IO). Any rejection by
// the primitive surfaces as a thrown error or `false`, which the suites map to a verdict.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify as nodeVerify,
  webcrypto,
} from 'node:crypto';

const { subtle } = webcrypto;
const P256_COORDINATE_BYTES = 32;

/** Left-pads a big-endian hex integer to `bytes` bytes (CAVP may drop leading zeros). */
export function fixedWidth(hex, bytes) {
  if (hex.length > bytes * 2) throw new RangeError('integer wider than field');
  return Buffer.from(hex.padStart(bytes * 2, '0'), 'hex');
}

const b64u = (buf) => Buffer.from(buf).toString('base64url');

export const platform = Object.freeze({
  /** SHA-256 via node:crypto (authority evidence hashing path). */
  sha256Node: async (msg) => new Uint8Array(createHash('sha256').update(msg).digest()),
  /** SHA-256 via WebCrypto (endpoint path). */
  sha256Web: async (msg) => new Uint8Array(await subtle.digest('SHA-256', msg)),

  /** AES-GCM encrypt via WebCrypto; returns ciphertext || tag. */
  async aesGcmEncrypt({ key, iv, aad, pt, tagBits }) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: tagBits }, k, pt),
    );
  },
  /** AES-GCM decrypt via WebCrypto; throws on authentication failure. */
  async aesGcmDecrypt({ key, iv, aad, ctAndTag, tagBits }) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: tagBits },
        k,
        ctAndTag,
      ),
    );
  },

  /** HKDF-SHA-256 via WebCrypto (the deriveWrapKey path). */
  async hkdfSha256({ ikm, salt, info, length }) {
    const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(
      await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, length * 8),
    );
  },

  /**
   * ECDSA P-256/SHA-256 verification via WebCrypto; an unimportable key counts as rejection.
   * @returns {Promise<boolean>}
   */
  async ecdsaVerifyWeb({ qx, qy, msg, r, s }) {
    let key;
    try {
      key = await subtle.importKey(
        'jwk',
        { kty: 'EC', crv: 'P-256', x: b64u(qx), y: b64u(qy), ext: true },
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
    } catch {
      return false;
    }
    return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.concat([r, s]), msg);
  },
  /** ECDSA P-256/SHA-256 verification via node:crypto (IEEE P1363), the authority path. */
  async ecdsaVerifyNode({ qx, qy, msg, r, s }) {
    try {
      const key = createPublicKey({
        key: { kty: 'EC', crv: 'P-256', x: b64u(qx), y: b64u(qy) },
        format: 'jwk',
      });
      return nodeVerify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, Buffer.concat([r, s]));
    } catch {
      return false;
    }
  },

  /** ML-KEM key generation from (d || z) via node:crypto; returns the encapsulation key. */
  async mlkemKeygen({ parameterSet, seed }) {
    const key = createPrivateKey({
      key: seed,
      format: 'raw-seed',
      asymmetricKeyType: parameterSet.toLowerCase(),
    });
    return new Uint8Array(createPublicKey(key).export({ format: 'raw-public' }));
  },
  /** ML-DSA-65 key generation from xi via node:crypto; returns the public key. */
  async mldsa65Keygen({ seed }) {
    const key = createPrivateKey({ key: seed, format: 'raw-seed', asymmetricKeyType: 'ml-dsa-65' });
    return new Uint8Array(createPublicKey(key).export({ format: 'raw-public' }));
  },
});

export { P256_COORDINATE_BYTES };
