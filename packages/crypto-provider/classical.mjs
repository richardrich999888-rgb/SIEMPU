import { bytes, decode, members } from './primitives.mjs';

export const CLASSICAL_PROVIDER_ID = 'siepmu-webcrypto-p256-v1';
export const CLASSICAL_SUITE_ID = 'P256-HKDF-SHA256-AES256GCM';

function suite(id) {
  if (id !== CLASSICAL_SUITE_ID) throw new Error('Unsupported classical suite');
}

function purpose(value) {
  if (!['sign', 'encapsulate'].includes(value)) throw new TypeError('Unsupported key purpose');
  return value === 'sign'
    ? { algorithm: { name: 'ECDSA', namedCurve: 'P-256' }, usages: ['sign', 'verify'] }
    : { algorithm: { name: 'ECDH', namedCurve: 'P-256' }, usages: ['deriveBits'] };
}

function publicJwk(key) {
  return { kty: 'EC', crv: 'P-256', x: key.x, y: key.y };
}

function validatePublic(key) {
  members(key, ['kty', 'crv', 'x', 'y']);
  if (key.kty !== 'EC' || key.crv !== 'P-256') throw new TypeError('Expected P-256 public key');
  decode(key.x, 32);
  decode(key.y, 32);
  return key;
}

async function importPublic(key, name, usages) {
  return crypto.subtle.importKey(
    'jwk',
    validatePublic(key),
    { name, namedCurve: 'P-256' },
    false,
    usages,
  );
}

function privateHandle(key, algorithm, usage) {
  if (
    !(key instanceof CryptoKey) ||
    key.type !== 'private' ||
    key.extractable ||
    key.algorithm.name !== algorithm ||
    key.algorithm.namedCurve !== 'P-256' ||
    !key.usages.includes(usage)
  )
    throw new TypeError('Invalid nonexportable private handle');
}

/** Existing P-256 wire keys/signatures, with nonextractable WebCrypto private handles. */
export function createClassicalProvider() {
  return {
    descriptor: {
      apiVersion: 1,
      id: CLASSICAL_PROVIDER_ID,
      keyCustody: 'software-webcrypto-nonextractable; not hardware attestation',
      suites: [
        {
          id: CLASSICAL_SUITE_ID,
          signature: 'ECDSA-P256-SHA256',
          establishment: 'ECDH-P256',
          contentEncryption: 'AES-256-GCM',
          laboratory: false,
        },
      ],
    },
    async generateKey({ suiteId, purpose: use }) {
      suite(suiteId);
      const { algorithm, usages } = purpose(use);
      const pair = await crypto.subtle.generateKey(algorithm, false, usages);
      return {
        publicKey: publicJwk(await crypto.subtle.exportKey('jwk', pair.publicKey)),
        privateKey: pair.privateKey,
      };
    },
    async importKey({ suiteId, purpose: use, key }) {
      suite(suiteId);
      members(key, ['kty', 'crv', 'x', 'y', 'd']);
      const publicKey = validatePublic(publicJwk(key));
      decode(key.d, 32);
      const { algorithm, usages } = purpose(use);
      return {
        publicKey,
        privateKey: await crypto.subtle.importKey(
          'jwk',
          key,
          algorithm,
          false,
          usages.filter((u) => u !== 'verify'),
        ),
      };
    },
    async sign({ suiteId, privateKey, data }) {
      suite(suiteId);
      privateHandle(privateKey, 'ECDSA', 'sign');
      return new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes(data)),
      );
    },
    async verify({ suiteId, publicKey, data, signature }) {
      suite(suiteId);
      const key = await importPublic(publicKey, 'ECDSA', ['verify']);
      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        bytes(signature, 64),
        bytes(data),
      );
    },
    async encapsulate({ suiteId, publicKey }) {
      suite(suiteId);
      const recipient = await importPublic(publicKey, 'ECDH', []);
      const ephemeral = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits'],
      );
      return {
        sharedSecret: new Uint8Array(
          await crypto.subtle.deriveBits(
            { name: 'ECDH', public: recipient },
            ephemeral.privateKey,
            256,
          ),
        ),
        encapsulation: {
          ephemeralPublicKey: publicJwk(await crypto.subtle.exportKey('jwk', ephemeral.publicKey)),
        },
      };
    },
    async decapsulate({ suiteId, privateKey, encapsulation }) {
      suite(suiteId);
      privateHandle(privateKey, 'ECDH', 'deriveBits');
      members(encapsulation, ['ephemeralPublicKey']);
      const ephemeral = await importPublic(encapsulation.ephemeralPublicKey, 'ECDH', []);
      return new Uint8Array(
        await crypto.subtle.deriveBits({ name: 'ECDH', public: ephemeral }, privateKey, 256),
      );
    },
  };
}
