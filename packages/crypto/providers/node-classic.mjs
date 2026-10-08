import { createCipheriv, createDecipheriv, sign, verify, createHash, KeyObject } from 'node:crypto';
import { createWebCryptoProvider } from './webcrypto.mjs';
// Independent public Node cipher/signature API, with WebCrypto key generation,
// derivation and non-extractable key containers. Both use the runtime's OpenSSL.
// This is a software conformance provider, not an HSM or distinct validated module.
export function createNodeClassicProvider() {
  const native = globalThis.crypto.subtle;
  const overrides = {
    async digest(algorithm, bytes) {
      if (algorithm !== 'SHA-256') throw new Error('UNSUPPORTED_DIGEST');
      return Uint8Array.from(createHash('sha256').update(bytes).digest()).buffer;
    },
    async sign(algorithm, key, bytes) {
      if (algorithm.name !== 'ECDSA' || algorithm.hash !== 'SHA-256')
        throw new Error('UNSUPPORTED_SIGNATURE');
      if (!key.usages.includes('sign')) throw new Error('KEY_USAGE_DENIED');
      return Uint8Array.from(
        sign('sha256', bytes, { key: KeyObject.from(key), dsaEncoding: 'ieee-p1363' }),
      ).buffer;
    },
    async verify(algorithm, key, signature, bytes) {
      if (algorithm.name !== 'ECDSA' || algorithm.hash !== 'SHA-256')
        throw new Error('UNSUPPORTED_SIGNATURE');
      if (!key.usages.includes('verify')) throw new Error('KEY_USAGE_DENIED');
      return verify(
        'sha256',
        bytes,
        { key: KeyObject.from(key), dsaEncoding: 'ieee-p1363' },
        signature,
      );
    },
    async encrypt(algorithm, key, bytes) {
      if (algorithm.name !== 'AES-GCM' || algorithm.tagLength !== 128 || algorithm.iv.length !== 12)
        throw new Error('UNSUPPORTED_CIPHER');
      if (!key.usages.includes('encrypt')) throw new Error('KEY_USAGE_DENIED');
      const c = createCipheriv('aes-256-gcm', KeyObject.from(key), algorithm.iv);
      c.setAAD(algorithm.additionalData);
      return Uint8Array.from(Buffer.concat([c.update(bytes), c.final(), c.getAuthTag()])).buffer;
    },
    async decrypt(algorithm, key, bytes) {
      if (algorithm.name !== 'AES-GCM' || algorithm.tagLength !== 128 || algorithm.iv.length !== 12)
        throw new Error('UNSUPPORTED_CIPHER');
      if (!key.usages.includes('decrypt')) throw new Error('KEY_USAGE_DENIED');
      bytes = Buffer.from(bytes);
      const c = createDecipheriv('aes-256-gcm', KeyObject.from(key), algorithm.iv);
      c.setAAD(algorithm.additionalData);
      c.setAuthTag(bytes.subarray(-16));
      return Uint8Array.from(Buffer.concat([c.update(bytes.subarray(0, -16)), c.final()])).buffer;
    },
  };
  const subtle = new Proxy(native, {
    get: (target, name) =>
      name in overrides
        ? overrides[name]
        : typeof target[name] === 'function'
          ? target[name].bind(target)
          : target[name],
  });
  return createWebCryptoProvider({ id: 'node-classic-software-v1', subtle });
}
