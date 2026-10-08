import { canonical } from '../protocol/canonical.mjs';

// INVARIANT: this browser module statically imports ONLY canonical.mjs.
// Deployed service workers intercept only the paths in their own ASSETS list; a
// new module imported from here is never cached by an older worker, and offline
// start-up then fails after an interrupted upgrade (tests/browser/shell-upgrade.mjs).
// The wire contract and default provider therefore live in this file.
// object-format/schema.mjs, mission/policy.mjs and providers/webcrypto.mjs re-export
// them so that server modules keep stable import paths and one source of truth.

// ---- Mission labels (DISC-14 PS-69 filed vocabulary; synthetic laboratory policy) ----
export const MESSAGE_PRIORITIES = Object.freeze(['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE']);
export const MESSAGE_DOMAINS = Object.freeze(['GENERAL', 'INTEL']);
/** @param {unknown} priority @param {unknown} domain */
export function validMissionProfile(priority, domain) {
  return (
    typeof priority === 'string' &&
    typeof domain === 'string' &&
    MESSAGE_PRIORITIES.includes(priority) &&
    MESSAGE_DOMAINS.includes(domain)
  );
}

// ---- Versioned object wire contract ----
// Shared wire-field contract for client encryption, submission and persisted-state checks.
// Version selection is exact: an unknown version never falls back to another schema.
const v1 = Object.freeze([
  'schemaVersion',
  'objectId',
  'senderUserId',
  'senderDeviceId',
  'senderUnitId',
  'recipientUserId',
  'recipientDeviceId',
  'recipientUnitId',
  'recipientKeyId',
  'missionId',
  'classification',
  'action',
  'createdAt',
  'expiresAt',
  'creationGrant',
  'cryptoSuite',
  'keyVersion',
]);
const v2 = Object.freeze([...v1, 'messagePriority', 'messageDomain']);
// v3 is the laboratory provider envelope: it names the provider, the suite version, the
// sender's provider signing key and the suite-policy revision in force at creation.
const v3 = Object.freeze([
  ...v2,
  'providerId',
  'suiteVersion',
  'senderCryptoKeyId',
  'suitePolicyRevision',
]);
const classicalEnvelope = Object.freeze(['ciphertextHash', 'nonce', 'wrappedKey']);

/** Classical schema versions accepted by the browser endpoint and classical admission. */
export const CLASSICAL_SCHEMA_VERSIONS = Object.freeze([1, 2]);
/** Laboratory provider schema version; accepted only when the authority enables the lab gate. */
export const PROVIDER_SCHEMA_VERSION = 3;

/** @param {unknown} version @returns {readonly string[]} empty when unsupported */
export function contextFields(version) {
  if (version === 1) return v1;
  if (version === 2) return v2;
  if (version === 3) return v3;
  return [];
}
/** @param {unknown} version @returns {string[] | null} null when unsupported */
export function envelopeFieldsFor(version) {
  const fields = contextFields(version);
  if (!fields.length) return null;
  // The provider signature covers every other v3 member, so it is appended last.
  return version === 3
    ? [...fields, ...classicalEnvelope, 'providerSignature']
    : [...fields, ...classicalEnvelope];
}
/**
 * True when the exact member set of `value` matches its declared schema version.
 * @param {unknown} value
 */
export function hasEnvelopeShape(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const envelope = /** @type {Record<string, unknown>} */ (value);
  const fields = envelopeFieldsFor(envelope.schemaVersion);
  return (
    !!fields &&
    Object.keys(envelope).length === fields.length &&
    fields.every((field) => Object.hasOwn(envelope, field))
  );
}
/**
 * Every schema from v2 onward carries sender-signed priority and domain labels.
 * Policy that depends on labels (duty roles, FLASH dual control) must use this
 * predicate instead of comparing against one version number.
 * @param {{schemaVersion?: unknown} | null | undefined} envelope
 */
export function hasMissionLabels(envelope) {
  return envelope?.schemaVersion === 2 || envelope?.schemaVersion === 3;
}
/** @param {{schemaVersion?: number, messagePriority?: string, messageDomain?: string} | null} envelope */
export function validEnvelopeVersion(envelope) {
  return (
    envelope?.schemaVersion === 1 ||
    (hasMissionLabels(envelope) &&
      validMissionProfile(envelope?.messagePriority, envelope?.messageDomain))
  );
}

// ---- Default software provider (versioned provider port) ----
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

/** @typedef {import('../object-format/types.js').PublicP256Jwk} PublicP256Jwk */
/** @typedef {import('../object-format/types.js').PrivateP256Jwk} PrivateP256Jwk */
/** @typedef {import('../object-format/types.js').ObjectContext} ObjectContext */
/** @typedef {import('../object-format/types.js').Payload} Payload */
/** @typedef {import('../object-format/types.js').EncryptedObject} EncryptedObject */
/** @typedef {ArrayBuffer | ArrayBufferView<ArrayBuffer>} ByteInput */

const utf8 = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const VAULT_ITERATIONS = 600000;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;
const SUITE = 'P256-HKDF-SHA256-AES256GCM';
const WRAP_INFO = utf8.encode('SIEPMU_WRAP_V1');

/** A provider instance is selected explicitly at construction. No retry/fallback provider exists.
 * @param {ReturnType<typeof createWebCryptoProvider>} [provider]
 */
export function createObjectCryptography(provider = createWebCryptoProvider()) {
  negotiateSuite(provider, [SUITE], [SUITE]);
  const subtle = provider.subtle;
  /** @param {ByteInput} value @returns {string} */
  function b64(value) {
    const bytes = asBytes(value);
    let s = '';
    for (let i = 0; i < bytes.length; i += 16384)
      s += String.fromCharCode(...bytes.subarray(i, i + 16384));
    return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  }
  /** @param {unknown} value @returns {Uint8Array<ArrayBuffer>} */
  function unb64(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1)
      throw new TypeError('Invalid base64url');
    const raw = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    if (b64(bytes) !== value) throw new TypeError('Noncanonical base64url');
    return bytes;
  }
  /** @param {ByteInput} value @returns {Uint8Array<ArrayBuffer>} */
  function asBytes(value) {
    if (value instanceof Uint8Array) return /** @type {Uint8Array<ArrayBuffer>} */ (value);
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value))
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    throw new TypeError('Expected bytes');
  }
  /** @param {number} size @returns {Uint8Array<ArrayBuffer>} */
  function random(size) {
    return provider.random(new Uint8Array(size));
  }
  /** @param {unknown} value @param {readonly string[]} names */
  function sameKeys(value, names) {
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      Object.keys(value).sort().join('|') !== [...names].sort().join('|')
    )
      throw new TypeError('Unexpected or missing object members');
  }
  /** @param {unknown} value @param {number} size @param {string} label */
  function sized(value, size, label) {
    const bytes = unb64(value);
    if (bytes.length !== size) throw new TypeError(`Invalid ${label} size`);
    return bytes;
  }
  /** @param {string | ByteInput} value @returns {Promise<string>} */
  async function sha256(value) {
    const bytes = typeof value === 'string' ? utf8.encode(value) : asBytes(value);
    return Array.from(new Uint8Array(await subtle.digest('SHA-256', bytes)), (n) =>
      n.toString(16).padStart(2, '0'),
    ).join('');
  }

  /** Minimal JWKs are the generated wire format. Use this before provisioning keys.
   * keyId hashes the exact supplied public JWK, so provision it consistently.
   */
  /** @param {JsonWebKey} jwk @returns {PublicP256Jwk} */
  function publicJwk(jwk) {
    if (provider.isHandle(jwk)) {
      const value = provider.publicKey(jwk);
      validateJwk(value);
      return { kty: 'EC', crv: 'P-256', x: value.x, y: value.y };
    }
    validateJwk(jwk, 'd' in (jwk || {}));
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }
  /** @param {JsonWebKey} jwk @param {boolean} [privateRequired] @returns {asserts jwk is PublicP256Jwk & { d?: string }} */
  function validateJwk(jwk, privateRequired = false) {
    if (
      !jwk ||
      typeof jwk !== 'object' ||
      Array.isArray(jwk) ||
      jwk.kty !== 'EC' ||
      jwk.crv !== 'P-256'
    )
      throw new TypeError('Only P-256 EC keys are accepted');
    sized(jwk.x, 32, 'P-256 x');
    sized(jwk.y, 32, 'P-256 y');
    if (privateRequired) sized(jwk.d, 32, 'P-256 private key');
    else if ('d' in jwk) throw new TypeError('Public key must not contain private material');
    canonical(jwk);
  }
  /** @param {JsonWebKey} jwk @param {"sign" | "verify" | "deriveBits" | "ecdhPublic"} usage @returns {Promise<CryptoKey>} */
  function importJwk(jwk, usage) {
    if (provider.isHandle(jwk)) return Promise.resolve(provider.resolve(jwk, usage));
    const isPrivate = usage === 'sign' || usage === 'deriveBits';
    validateJwk(jwk, isPrivate);
    const alg = {
      name: usage === 'sign' || usage === 'verify' ? 'ECDSA' : 'ECDH',
      namedCurve: 'P-256',
    };
    const minimal = {
      kty: 'EC',
      crv: 'P-256',
      x: jwk.x,
      y: jwk.y,
      ...(isPrivate ? { d: jwk.d } : {}),
    };
    return subtle.importKey('jwk', minimal, alg, false, usage === 'ecdhPublic' ? [] : [usage]);
  }
  async function generateDeviceKeys() {
    /** @param {"ECDSA" | "ECDH"} name @param {KeyUsage[]} usages */
    async function generate(name, usages) {
      const keys = await subtle.generateKey({ name, namedCurve: 'P-256' }, true, usages);
      const pub = publicJwk(await subtle.exportKey('jwk', keys.publicKey));
      const priv = await subtle.exportKey('jwk', keys.privateKey);
      return { publicKey: pub, privateKey: { ...pub, d: priv.d } };
    }
    return {
      signing: await generate('ECDSA', ['sign', 'verify']),
      encryption: await generate('ECDH', ['deriveBits']),
    };
  }
  /** @param {JsonWebKey} privateJwk @param {unknown} value @returns {Promise<string>} */
  async function sign(privateJwk, value) {
    const key = await importJwk(privateJwk, 'sign');
    return b64(
      await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, utf8.encode(canonical(value))),
    );
  }
  /** @param {JsonWebKey} publicKey @param {unknown} value @param {unknown} signature @returns {Promise<boolean>} */
  async function verify(publicKey, value, signature) {
    try {
      const key = await importJwk(publicKey, 'verify');
      return await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        sized(signature, 64, 'signature'),
        utf8.encode(canonical(value)),
      );
    } catch {
      return false;
    }
  }
  /** @param {JsonWebKey} publicKey @returns {Promise<string>} */
  async function keyId(publicKey) {
    validateJwk(publicKey);
    return sha256(canonical(publicKey));
  }
  /** @template T @param {JsonWebKey} privateJwk @param {T} payload @returns {Promise<import("../object-format/types.js").SignedPacket<T>>} */
  async function signPacket(privateJwk, payload) {
    return {
      payload,
      signature: await sign(privateJwk, payload),
      keyId: await keyId(publicJwk(privateJwk)),
    };
  }
  /** @param {JsonWebKey} publicKey @param {import("../object-format/types.js").SignedPacket<unknown>} packet @returns {Promise<boolean>} */
  async function verifyPacket(publicKey, packet) {
    try {
      sameKeys(packet, ['payload', 'signature', 'keyId']);
      return (
        packet.keyId === (await keyId(publicKey)) &&
        (await verify(publicKey, packet.payload, packet.signature))
      );
    } catch {
      return false;
    }
  }
  /** @param {ObjectContext} context */
  function validateContext(context) {
    negotiateSuite(provider, [context.cryptoSuite], [SUITE]);
    sameKeys(context, contextFields(context.schemaVersion));
    canonical(context);
    if (
      ![1, 2].includes(context.schemaVersion) ||
      (context.schemaVersion === 2 &&
        !validMissionProfile(context.messagePriority, context.messageDomain)) ||
      context.keyVersion !== 1 ||
      context.cryptoSuite !== SUITE ||
      context.classification !== 'DEMO' ||
      context.action !== 'deliver'
    )
      throw new TypeError('Unsupported object context');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(context.objectId))
      throw new TypeError('Object ID must be a UUID');
    /** @type {(keyof Pick<ObjectContext, 'senderUserId' | 'senderDeviceId' | 'senderUnitId' | 'recipientUserId' | 'recipientDeviceId' | 'recipientUnitId' | 'missionId'>)[]} */
    const identifiers = [
      'senderUserId',
      'senderDeviceId',
      'senderUnitId',
      'recipientUserId',
      'recipientDeviceId',
      'recipientUnitId',
      'missionId',
    ];
    for (const k of identifiers) {
      if (typeof context[k] !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(context[k]))
        throw new TypeError(`Invalid ${k}`);
    }
    if (
      typeof context.recipientKeyId !== 'string' ||
      !/^[0-9a-f]{64}$/.test(context.recipientKeyId)
    )
      throw new TypeError('Invalid recipient key ID');
    if (
      !Number.isSafeInteger(context.createdAt) ||
      context.createdAt < 0 ||
      !Number.isSafeInteger(context.expiresAt) ||
      context.expiresAt <= context.createdAt
    )
      throw new TypeError('Invalid object validity interval');
    sameKeys(context.creationGrant, ['payload', 'signature', 'keyId']);
    sized(context.creationGrant.signature, 64, 'grant signature');
    if (
      !context.creationGrant.payload ||
      typeof context.creationGrant.payload !== 'object' ||
      Array.isArray(context.creationGrant.payload)
    )
      throw new TypeError('Invalid creation grant');
    if (!/^[0-9a-f]{64}$/.test(context.creationGrant.keyId))
      throw new TypeError('Invalid grant key ID');
  }
  /** @param {JsonWebKey} privateKey @param {JsonWebKey} publicKey @param {Uint8Array<ArrayBuffer>} salt @returns {Promise<CryptoKey>} */
  async function wrappingKey(privateKey, publicKey, salt) {
    const privateCrypto = await importJwk(privateKey, 'deriveBits');
    const publicCrypto = await importJwk(publicKey, 'ecdhPublic');
    const secret = new Uint8Array(
      await subtle.deriveBits({ name: 'ECDH', public: publicCrypto }, privateCrypto, 256),
    );
    try {
      const key = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
      return await subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info: WRAP_INFO },
        key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      );
    } finally {
      secret.fill(0);
    }
  }
  /** @param {Payload} payload @returns {Payload} */
  function validatePayload(payload) {
    sameKeys(payload, ['kind', 'name', 'mime', 'data']);
    if (!['text', 'file'].includes(payload.kind)) throw new TypeError('Unsupported payload kind');
    if (
      typeof payload.name !== 'string' ||
      payload.name.length < 1 ||
      payload.name.length > 180 ||
      /[\\/\x00-\x1f\x7f]/.test(payload.name) ||
      ['.', '..'].includes(payload.name)
    )
      throw new TypeError('Unsafe file name');
    if (
      typeof payload.mime !== 'string' ||
      payload.mime.length > 120 ||
      !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:;charset=utf-8)?$/.test(payload.mime)
    )
      throw new TypeError('Invalid MIME type');
    const bytes = unb64(payload.data);
    if (bytes.length > MAX_CONTENT_BYTES) throw new TypeError('Payload exceeds size limit');
    if (payload.kind === 'text') {
      if (!['text/plain', 'text/plain;charset=utf-8'].includes(payload.mime))
        throw new TypeError('Text messages must use text/plain');
      decoder.decode(bytes);
    }
    return payload;
  }
  /** @param {string} text @returns {Payload} */
  function createTextPayload(text) {
    if (typeof text !== 'string') throw new TypeError('Expected text');
    return validatePayload({
      kind: 'text',
      name: 'message.txt',
      mime: 'text/plain',
      data: b64(utf8.encode(text)),
    });
  }
  /** @param {string} name @param {string} mime @param {ByteInput} bytes @returns {Payload} */
  function createFilePayload(name, mime, bytes) {
    return validatePayload({
      kind: 'file',
      name,
      mime: mime || 'application/octet-stream',
      data: b64(bytes),
    });
  }
  /** @param {Payload} payload */
  function unpackPayload(payload) {
    validatePayload(payload);
    const bytes = unb64(payload.data);
    return {
      kind: payload.kind,
      name: payload.name,
      mime: payload.mime,
      bytes,
      ...(payload.kind === 'text' ? { text: decoder.decode(bytes) } : {}),
    };
  }
  /** @param {ObjectContext} context @param {Payload} payload @param {JsonWebKey} recipientPublicJwk @param {JsonWebKey} senderPrivateJwk @returns {Promise<EncryptedObject>} */
  async function encryptObject(context, payload, recipientPublicJwk, senderPrivateJwk) {
    validateContext(context);
    validatePayload(payload);
    if (context.recipientKeyId !== (await keyId(recipientPublicJwk)))
      throw new Error('Recipient key ID mismatch');
    const aad = utf8.encode(canonical(context));
    const contentBytes = random(32),
      nonce = random(12),
      salt = random(32),
      iv = random(12);
    try {
      const contentKey = await subtle.importKey('raw', contentBytes, 'AES-GCM', false, ['encrypt']);
      const ciphertext = new Uint8Array(
        await subtle.encrypt(
          { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
          contentKey,
          utf8.encode(canonical(payload)),
        ),
      );
      const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveBits',
      ]);
      const ephemeralPrivate = await subtle.exportKey('jwk', ephemeral.privateKey);
      const ephemeralPublic = publicJwk(await subtle.exportKey('jwk', ephemeral.publicKey));
      const wrapKey = await wrappingKey(ephemeralPrivate, recipientPublicJwk, salt);
      const wrapped = await subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        wrapKey,
        contentBytes,
      );
      const envelope = {
        ...context,
        ciphertextHash: await sha256(ciphertext),
        nonce: b64(nonce),
        wrappedKey: {
          ephemeralPublicKey: ephemeralPublic,
          salt: b64(salt),
          iv: b64(iv),
          ciphertext: b64(wrapped),
        },
      };
      return {
        envelope,
        signature: await sign(senderPrivateJwk, envelope),
        ciphertext: b64(ciphertext),
      };
    } finally {
      contentBytes.fill(0);
    }
  }
  /** @param {EncryptedObject} submission @param {JsonWebKey} recipientPrivateJwk @param {JsonWebKey} senderPublicJwk @returns {Promise<Payload>} */
  async function decryptObject(submission, recipientPrivateJwk, senderPublicJwk) {
    if (!submission || typeof submission !== 'object')
      throw new TypeError('Invalid encrypted object');
    const { envelope, signature, ciphertext: encoded } = submission;
    sameKeys(envelope, [
      ...contextFields(envelope.schemaVersion),
      'ciphertextHash',
      'nonce',
      'wrappedKey',
    ]);
    const { ciphertextHash, nonce, wrappedKey, ...context } = envelope;
    validateContext(context);
    if (!(await verify(senderPublicJwk, envelope, signature)))
      throw new Error('Object signature invalid');
    if (context.recipientKeyId !== (await keyId(publicJwk(recipientPrivateJwk))))
      throw new Error('Recipient key ID mismatch');
    const ciphertext = unb64(encoded);
    if (
      ciphertext.length > MAX_CONTENT_BYTES * 2 ||
      ciphertext.length < 16 ||
      ciphertextHash !== (await sha256(ciphertext))
    )
      throw new Error('Ciphertext integrity mismatch');
    sameKeys(wrappedKey, ['ephemeralPublicKey', 'salt', 'iv', 'ciphertext']);
    const wrapKey = await wrappingKey(
      recipientPrivateJwk,
      wrappedKey.ephemeralPublicKey,
      sized(wrappedKey.salt, 32, 'salt'),
    );
    const aad = utf8.encode(canonical(context));
    let contentBytes;
    try {
      contentBytes = new Uint8Array(
        await subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: sized(wrappedKey.iv, 12, 'wrap IV'),
            additionalData: aad,
            tagLength: 128,
          },
          wrapKey,
          sized(wrappedKey.ciphertext, 48, 'wrapped content key'),
        ),
      );
      const key = await subtle.importKey('raw', contentBytes, 'AES-GCM', false, ['decrypt']);
      const plain = await subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: sized(nonce, 12, 'content nonce'),
          additionalData: aad,
          tagLength: 128,
        },
        key,
        ciphertext,
      );
      return validatePayload(JSON.parse(decoder.decode(plain)));
    } catch {
      throw new Error('Encrypted payload authentication failed');
    } finally {
      if (contentBytes) contentBytes.fill(0);
    }
  }
  /** @param {string} passphrase @param {Uint8Array<ArrayBuffer>} salt @param {KeyUsage[]} usages @returns {Promise<CryptoKey>} */
  async function vaultKey(passphrase, salt, usages) {
    if (typeof passphrase !== 'string' || passphrase.length < 12 || passphrase.length > 1024)
      throw new TypeError('Vault passphrase must contain 12–1024 characters');
    const key = await subtle.importKey('raw', utf8.encode(passphrase), 'PBKDF2', false, [
      'deriveKey',
    ]);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: VAULT_ITERATIONS, hash: 'SHA-256' },
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      usages,
    );
  }
  /** @param {unknown} value @param {string} passphrase @returns {Promise<import("../object-format/types.js").VaultPacket>} */
  async function sealVault(value, passphrase) {
    const salt = random(32),
      iv = random(12);
    const metadata = {
      version: 1,
      kdf: 'PBKDF2-SHA256',
      iterations: VAULT_ITERATIONS,
      salt: b64(salt),
      iv: b64(iv),
    };
    const key = await vaultKey(passphrase, salt, ['encrypt']);
    const ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: utf8.encode(canonical(metadata)), tagLength: 128 },
      key,
      utf8.encode(canonical(value)),
    );
    return { ...metadata, ciphertext: b64(ciphertext) };
  }
  /** @param {import("../object-format/types.js").VaultPacket} packet @param {string} passphrase @returns {Promise<unknown>} */
  async function openVault(packet, passphrase) {
    sameKeys(packet, ['version', 'kdf', 'iterations', 'salt', 'iv', 'ciphertext']);
    const { ciphertext, ...metadata } = packet;
    if (
      metadata.version !== 1 ||
      metadata.kdf !== 'PBKDF2-SHA256' ||
      metadata.iterations !== VAULT_ITERATIONS
    )
      throw new TypeError('Unsupported vault format');
    const salt = sized(metadata.salt, 32, 'vault salt'),
      iv = sized(metadata.iv, 12, 'vault IV');
    const key = await vaultKey(passphrase, salt, ['decrypt']);
    try {
      const plaintext = await subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: utf8.encode(canonical(metadata)), tagLength: 128 },
        key,
        unb64(ciphertext),
      );
      const value = JSON.parse(decoder.decode(plaintext));
      canonical(value);
      return value;
    } catch {
      throw new Error('Vault unlock failed');
    }
  }

  return Object.freeze({
    b64,
    unb64,
    sha256,
    publicJwk,
    generateDeviceKeys,
    sign,
    verify,
    keyId,
    signPacket,
    verifyPacket,
    validatePayload,
    createTextPayload,
    createFilePayload,
    unpackPayload,
    encryptObject,
    decryptObject,
    sealVault,
    openVault,
    provider,
    generateOpaqueDeviceKeys: () => provider.generateDeviceHandles(),
  });
}

export const {
  b64,
  unb64,
  sha256,
  publicJwk,
  generateDeviceKeys,
  sign,
  verify,
  keyId,
  signPacket,
  verifyPacket,
  validatePayload,
  createTextPayload,
  createFilePayload,
  unpackPayload,
  encryptObject,
  decryptObject,
  sealVault,
  openVault,
} = createObjectCryptography();
