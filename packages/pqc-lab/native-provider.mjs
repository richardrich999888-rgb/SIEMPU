import {
  createPublicKey,
  decapsulate,
  encapsulate,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

export const NATIVE_PQC_PROVIDER_ID = 'node-openssl-pqc-lab';
export const NATIVE_MLKEM768_SUITE = 'ML-KEM-768-ML-DSA-65-AES-256-GCM-v1';
export const NATIVE_MLKEM1024_SUITE = 'ML-KEM-1024-ML-DSA-65-AES-256-GCM-v1';
const SUITES = new Map([
  [NATIVE_MLKEM768_SUITE, { kem: 'ml-kem-768', publicBytes: 1184, ciphertextBytes: 1088 }],
  [NATIVE_MLKEM1024_SUITE, { kem: 'ml-kem-1024', publicBytes: 1568, ciphertextBytes: 1568 }],
]);

export function exactObject(value, fields) {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== fields.length ||
    !fields.every((field) => Object.hasOwn(value, field))
  ) {
    throw new Error('Invalid public cryptographic encoding');
  }
}

export function decodeBytes(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid cryptographic byte encoding');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || bytes.toString('base64url') !== value) {
    throw new Error('Invalid cryptographic byte length or encoding');
  }
  return bytes;
}

export function requireBytes(value) {
  if (!(value instanceof Uint8Array)) throw new TypeError('Expected cryptographic bytes');
  return Buffer.from(value);
}

function suiteFor(suiteId) {
  const suite = SUITES.get(suiteId);
  if (!suite) throw new Error('Unsupported laboratory cryptographic suite');
  return suite;
}

function readPublic(publicKey, algorithm, length) {
  exactObject(publicKey, ['algorithm', 'format', 'bytes']);
  if (publicKey.algorithm !== algorithm || publicKey.format !== 'raw-public') {
    throw new Error('Public key algorithm or format mismatch');
  }
  return createPublicKey({
    key: decodeBytes(publicKey.bytes, length),
    format: 'raw-public',
    asymmetricKeyType: algorithm,
  });
}

/** Endpoint-only native laboratory provider. No recipient private handle crosses its caller boundary. */
export function createNativePqcProvider() {
  const handles = new WeakMap();
  const descriptor = Object.freeze({
    apiVersion: 1,
    id: NATIVE_PQC_PROVIDER_ID,
    keyCustody: 'software-nonexportable-handle',
    assurance: 'laboratory; no module certification or independent integration review claimed',
    runtime: Object.freeze({ node: process.versions.node, openssl: process.versions.openssl }),
    suites: Object.freeze(
      [...SUITES].map(([id, suite]) =>
        Object.freeze({
          id,
          signature: 'ML-DSA-65',
          establishment: suite.kem.toUpperCase(),
          contentEncryption: 'AES-256-GCM',
          laboratory: true,
        }),
      ),
    ),
  });
  function privateEntry(handle, suiteId, purpose) {
    suiteFor(suiteId);
    const entry = handles.get(handle);
    if (!entry || entry.suiteId !== suiteId || entry.purpose !== purpose) {
      throw new Error('Unknown or incompatible private key handle');
    }
    return entry.key;
  }
  return Object.freeze({
    descriptor,
    async generateKey({ suiteId, purpose }) {
      const suite = suiteFor(suiteId);
      if (!['sign', 'encapsulate'].includes(purpose)) throw new Error('Unsupported key purpose');
      const algorithm = purpose === 'sign' ? 'ml-dsa-65' : suite.kem;
      const pair = generateKeyPairSync(algorithm);
      const privateKey = Object.freeze({});
      handles.set(privateKey, { key: pair.privateKey, suiteId, purpose });
      return {
        privateKey,
        publicKey: Object.freeze({
          algorithm,
          format: 'raw-public',
          bytes: pair.publicKey.export({ format: 'raw-public' }).toString('base64url'),
        }),
      };
    },
    async sign({ suiteId, privateKey, data }) {
      return sign(null, requireBytes(data), privateEntry(privateKey, suiteId, 'sign'));
    },
    async verify({ suiteId, publicKey, data, signature }) {
      suiteFor(suiteId);
      const key = readPublic(publicKey, 'ml-dsa-65', 1952);
      const message = requireBytes(data);
      const sig = requireBytes(signature);
      if (sig.length !== 3309) return false;
      return verify(null, message, key, sig);
    },
    async encapsulate({ suiteId, publicKey }) {
      const suite = suiteFor(suiteId);
      const key = readPublic(publicKey, suite.kem, suite.publicBytes);
      const result = encapsulate(key);
      return {
        sharedSecret: result.sharedKey,
        encapsulation: {
          algorithm: suite.kem,
          ciphertext: result.ciphertext.toString('base64url'),
        },
      };
    },
    async decapsulate({ suiteId, privateKey, encapsulation }) {
      const suite = suiteFor(suiteId);
      const key = privateEntry(privateKey, suiteId, 'encapsulate');
      exactObject(encapsulation, ['algorithm', 'ciphertext']);
      if (encapsulation.algorithm !== suite.kem)
        throw new Error('Encapsulation algorithm mismatch');
      return decapsulate(key, decodeBytes(encapsulation.ciphertext, suite.ciphertextBytes));
    },
  });
}
