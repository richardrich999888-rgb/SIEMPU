import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import {
  createNativePqcProvider,
  decodeBytes,
  exactObject,
  NATIVE_MLKEM768_SUITE,
} from './native-provider.mjs';

export const XWING_PROVIDER_ID = 'noble-xwing-lab';
export const XWING_SUITE = 'X-WING-ML-DSA-65-AES-256-GCM-v1';

function requireSuite(suiteId) {
  if (suiteId !== XWING_SUITE) throw new Error('Unsupported X-Wing laboratory suite');
}

/** Published X-Wing preset. Upstream JS implementation is unaudited and not constant-time. */
export function createXwingLabProvider() {
  const handles = new WeakMap();
  const signatures = createNativePqcProvider();
  return Object.freeze({
    descriptor: Object.freeze({
      apiVersion: 1,
      id: XWING_PROVIDER_ID,
      keyCustody: 'software-nonexportable-handle',
      assurance: 'isolated laboratory only; Noble 0.7.1 unaudited; JavaScript not constant-time',
      suites: Object.freeze([
        Object.freeze({
          id: XWING_SUITE,
          signature: 'ML-DSA-65',
          establishment: 'X-Wing draft-11 candidate',
          contentEncryption: 'AES-256-GCM',
          laboratory: true,
        }),
      ]),
    }),
    async generateKey({ suiteId, purpose }) {
      requireSuite(suiteId);
      if (purpose === 'sign') {
        return signatures.generateKey({ suiteId: NATIVE_MLKEM768_SUITE, purpose });
      }
      if (purpose !== 'encapsulate') throw new Error('Unsupported key purpose');
      const pair = ml_kem768_x25519.keygen();
      const privateKey = Object.freeze({});
      handles.set(privateKey, pair.secretKey);
      return {
        privateKey,
        publicKey: Object.freeze({
          algorithm: 'x-wing',
          format: 'raw-public',
          bytes: Buffer.from(pair.publicKey).toString('base64url'),
        }),
      };
    },
    async sign({ suiteId, ...input }) {
      requireSuite(suiteId);
      return signatures.sign({ ...input, suiteId: NATIVE_MLKEM768_SUITE });
    },
    async verify({ suiteId, ...input }) {
      requireSuite(suiteId);
      return signatures.verify({ ...input, suiteId: NATIVE_MLKEM768_SUITE });
    },
    async encapsulate({ suiteId, publicKey }) {
      requireSuite(suiteId);
      exactObject(publicKey, ['algorithm', 'format', 'bytes']);
      if (publicKey.algorithm !== 'x-wing' || publicKey.format !== 'raw-public') {
        throw new Error('Public key algorithm or format mismatch');
      }
      const key = decodeBytes(publicKey.bytes, 1216);
      const result = ml_kem768_x25519.encapsulate(key);
      return {
        sharedSecret: result.sharedSecret,
        encapsulation: {
          algorithm: 'x-wing',
          ciphertext: Buffer.from(result.cipherText).toString('base64url'),
        },
      };
    },
    async decapsulate({ suiteId, privateKey, encapsulation }) {
      requireSuite(suiteId);
      const key = handles.get(privateKey);
      if (!key) throw new Error('Unknown or incompatible private key handle');
      exactObject(encapsulation, ['algorithm', 'ciphertext']);
      if (encapsulation.algorithm !== 'x-wing') throw new Error('Encapsulation algorithm mismatch');
      return ml_kem768_x25519.decapsulate(decodeBytes(encapsulation.ciphertext, 1120), key);
    },
  });
}
