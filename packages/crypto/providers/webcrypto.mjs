// Versioned software-provider port. Opaque means non-exportable through this API,
// not resistance to a compromised process, debugger, browser, or OS.
export const DEMO_SUITE = 'P256-HKDF-SHA256-AES256GCM';
/** @param {{version:number,id:string,suites:readonly string[]}} provider @param {string[]} offered @param {string[]} approved */
export function negotiateSuite(provider, offered, approved) {
  if (provider.version !== 1 || !provider.id) throw new Error('PROVIDER_VERSION_UNSUPPORTED');
  const match = approved.find(
    (suite) => offered.includes(suite) && provider.suites.includes(suite),
  );
  if (!match) throw new Error('NO_APPROVED_CRYPTO_SUITE');
  return match;
}
/** @param {{id?:string,subtle?:SubtleCrypto}} [options] */
export function createWebCryptoProvider({
  id = 'webcrypto-software-v1',
  subtle = globalThis.crypto.subtle,
} = {}) {
  /** @type {WeakMap<object,{key:CryptoKey,publicKey:JsonWebKey,usage:string}>} */
  const handles = new WeakMap();
  /** @param {unknown} value */
  const isHandle = (value) => !!value && typeof value === 'object' && 'handleVersion' in value;
  /** @param {JsonWebKey} value */
  function entry(value) {
    const result = handles.get(value);
    if (!result) throw new Error('KEY_HANDLE_UNKNOWN_OR_DESTROYED');
    return result;
  }
  /** @param {'ECDSA'|'ECDH'} name @param {'sign'|'deriveBits'} usage */
  async function generate(name, usage) {
    const keys = await subtle.generateKey(
      { name, namedCurve: 'P-256' },
      false,
      usage === 'sign' ? ['sign', 'verify'] : ['deriveBits'],
    );
    const p = await subtle.exportKey('jwk', keys.publicKey);
    const publicKey = Object.freeze({ kty: p.kty, crv: p.crv, x: p.x, y: p.y });
    const handle = Object.freeze({
      ...publicKey,
      handleVersion: 1,
      providerId: id,
      handleId: crypto.randomUUID(),
    });
    handles.set(handle, { key: keys.privateKey, publicKey, usage });
    return { publicKey, privateKey: handle };
  }
  return Object.freeze({
    version: 1,
    id,
    suites: Object.freeze([DEMO_SUITE]),
    subtle,
    capabilities: Object.freeze({
      opaquePrivateKeys: true,
      hardwareBacked: false,
      pqc: false,
      sagGraded: false,
    }),
    /** @param {Uint8Array<ArrayBuffer>} bytes */
    random: (bytes) => crypto.getRandomValues(bytes),
    isHandle,
    /** @param {JsonWebKey} handle */
    publicKey: (handle) => entry(handle).publicKey,
    /** @param {JsonWebKey} handle @param {string} usage */
    resolve: (handle, usage) => {
      const value = entry(handle);
      if (value.usage !== usage) throw new Error('KEY_USAGE_DENIED');
      return value.key;
    },
    /** @param {JsonWebKey} handle */
    destroy: (handle) => {
      entry(handle);
      handles.delete(handle);
    },
    async generateDeviceHandles() {
      return {
        signing: await generate('ECDSA', 'sign'),
        encryption: await generate('ECDH', 'deriveBits'),
      };
    },
  });
}
