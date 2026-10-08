import { canonical } from '../protocol/canonical.mjs';
/** @typedef {import('../object-format/types.js').PublicP256Jwk} PublicP256Jwk */
/** @typedef {import('../object-format/types.js').PrivateP256Jwk} PrivateP256Jwk */
/** @typedef {import('../object-format/types.js').ObjectContext} ObjectContext */
/** @typedef {import('../object-format/types.js').Payload} Payload */
/** @typedef {import('../object-format/types.js').EncryptedObject} EncryptedObject */
/** @typedef {ArrayBuffer | ArrayBufferView<ArrayBuffer>} ByteInput */

const utf8 = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const subtle = globalThis.crypto.subtle;
const VAULT_ITERATIONS = 600000;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;
const SUITE = 'P256-HKDF-SHA256-AES256GCM';
const WRAP_INFO = utf8.encode('SIEPMU_WRAP_V1');

// The shared wire contract stays in this already-cached browser asset. Older
// network-first service workers may mix asset generations during an interrupted
// upgrade; crypto must therefore depend only on the stable canonical() export.
// Server admission and mission policy use these same pure contract helpers.
// Do not import mission policy or provider implementations here (would cycle).
const CONTEXT_V1 = Object.freeze([
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
const CONTEXT_V2 = Object.freeze([...CONTEXT_V1, 'messagePriority', 'messageDomain']);
const CONTEXT_V3 = Object.freeze([
  ...CONTEXT_V2,
  'providerId',
  'suiteVersion',
  'senderCryptoKeyId',
  'suitePolicyRevision',
]);
const ENVELOPE_V1 = Object.freeze([...CONTEXT_V1, 'ciphertextHash', 'nonce', 'wrappedKey']);
const ENVELOPE_V2 = Object.freeze([...CONTEXT_V2, 'ciphertextHash', 'nonce', 'wrappedKey']);
const ENVELOPE_V3 = Object.freeze([
  ...CONTEXT_V3,
  'ciphertextHash',
  'nonce',
  'wrappedKey',
  'providerSignature',
]);

/** Exact version selection: an unknown version never falls back to a legacy schema.
 * @param {unknown} version @returns {readonly string[]}
 */
export function contextFields(version) {
  if (version === 1) return CONTEXT_V1;
  if (version === 2) return CONTEXT_V2;
  if (version === 3) return CONTEXT_V3;
  throw new TypeError('Unsupported envelope schema version');
}

/** @param {unknown} version @returns {readonly string[]} */
export function envelopeFields(version) {
  if (version === 1) return ENVELOPE_V1;
  if (version === 2) return ENVELOPE_V2;
  if (version === 3) return ENVELOPE_V3;
  throw new TypeError('Unsupported envelope schema version');
}

/** @param {unknown} value @returns {boolean} */
export function hasEnvelopeShape(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const envelope = /** @type {Record<string, unknown>} */ (value);
  try {
    const expected = envelopeFields(envelope.schemaVersion);
    return (
      Object.keys(envelope).length === expected.length &&
      expected.every((field) => Object.hasOwn(envelope, field))
    );
  } catch {
    return false;
  }
}

export const MESSAGE_PRIORITIES = Object.freeze(['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE']);
export const MESSAGE_DOMAINS = Object.freeze(['GENERAL', 'INTEL']);

/** @param {unknown} priority @param {unknown} domain @returns {boolean} */
export function validMissionProfile(priority, domain) {
  return (
    typeof priority === 'string' &&
    MESSAGE_PRIORITIES.includes(priority) &&
    typeof domain === 'string' &&
    MESSAGE_DOMAINS.includes(domain)
  );
}

/** @param {ByteInput} value @returns {string} */
export function b64(value) {
  const bytes = asBytes(value);
  let s = '';
  for (let i = 0; i < bytes.length; i += 16384)
    s += String.fromCharCode(...bytes.subarray(i, i + 16384));
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
/** @param {unknown} value @returns {Uint8Array<ArrayBuffer>} */
export function unb64(value) {
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
  return crypto.getRandomValues(new Uint8Array(size));
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
export async function sha256(value) {
  const bytes = typeof value === 'string' ? utf8.encode(value) : asBytes(value);
  return Array.from(new Uint8Array(await subtle.digest('SHA-256', bytes)), (n) =>
    n.toString(16).padStart(2, '0'),
  ).join('');
}

/** Minimal JWKs are the generated wire format. Use this before provisioning keys.
 * keyId hashes the exact supplied public JWK, so provision it consistently.
 */
/** @param {JsonWebKey} jwk @returns {PublicP256Jwk} */
export function publicJwk(jwk) {
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
export async function generateDeviceKeys() {
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
export async function sign(privateJwk, value) {
  const key = await importJwk(privateJwk, 'sign');
  return b64(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, utf8.encode(canonical(value))),
  );
}
/** @param {JsonWebKey} publicKey @param {unknown} value @param {unknown} signature @returns {Promise<boolean>} */
export async function verify(publicKey, value, signature) {
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
export async function keyId(publicKey) {
  validateJwk(publicKey);
  return sha256(canonical(publicKey));
}
/** @template T @param {JsonWebKey} privateJwk @param {T} payload @returns {Promise<import("../object-format/types.js").SignedPacket<T>>} */
export async function signPacket(privateJwk, payload) {
  return {
    payload,
    signature: await sign(privateJwk, payload),
    keyId: await keyId(publicJwk(privateJwk)),
  };
×İø¶‰Ëkºwµçl(€ÑÉäì(€€€½¹ÍĞ½¹Ñ•¹Ñ-•ä€ô…İ…¥ĞÍÕ‰Ñ±”¹¥µÁ½ÉÑ-•ä É…Üœ°½¹Ñ•¹Ñ	åÑ•Ì°€Lµ4œ°™…±Í”°l•¹ÉåÁĞt¤ì(€€€½¹ÍĞ¥Á¡•ÉÑ•áĞ€ô¹•ÜU¥¹ĞáÉÉ…ä (€€€€€…İ…¥ĞÍÕ‰Ñ±”¹•¹ÉåÁĞ (€€€€€€€ì¹…µ”è€Lµ4œ°¥Øè¹½¹”°…‘‘¥Ñ¥½¹…±…Ñ„è……°Ñ…1•¹Ñ è€ÄÈàô°(€€€€€€€½¹Ñ•¹Ñ-•ä°(€€€€€€€ÕÑ˜à¹•¹½‘”¡…¹½¹¥…°¡Á…å±½…¤¤°(€€€€€€¤°(€€€€¤ì(€€€½¹ÍĞ•Á¡•µ•É…°€ô…İ…¥ĞÍÕ‰Ñ±”¹•¹•É…Ñ•-•ä¡ì¹…µ”è€ œ°¹…µ•‘ÕÉÙ”è€@´ÈÔØœô°ÑÉÕ”°l(€€€€€€‘•É¥Ù•	¥ÑÌœ°(€€€t¤ì(€€€½¹ÍĞ•Á¡•µ•É…±AÉ¥Ù…Ñ”€ô…İ…¥ĞÍÕ‰Ñ±”¹•áÁ½ÉÑ-•ä ©İ¬œ°•Á¡•µ•É…°¹ÁÉ¥Ù…Ñ•-•ä¤ì(€€€½¹ÍĞ•Á¡•µ•É…±AÕ‰±¥Œ€ôÁÕ‰±¥)İ¬¡…İ…¥ĞÍÕ‰Ñ±”¹•áÁ½ÉÑ-•ä ©İ¬œ°•Á¡•µ•É…°¹ÁÕ‰±¥-•ä¤¤ì(€€€½¹ÍĞİÉ…Á-•ä€ô…İ…¥ĞİÉ…ÁÁ¥¹-•ä¡•Á¡•µ•É…±AÉ¥Ù…Ñ”°É•¥Á¥•¹ÑAÕ‰±¥)İ¬°Í…±Ğ¤ì(€€€½¹ÍĞİÉ…ÁÁ•€ô…İ…¥ĞÍÕ‰Ñ±”¹•¹ÉåÁĞ (€€€€€ì¹…µ”è€Lµ4œ°¥Ø°…‘‘¥Ñ¥½¹…±…Ñ„è……°Ñ…1•¹Ñ è€ÄÈàô°(€€€€€İÉ…Á-•ä°(€€€€€½¹Ñ•¹Ñ	åÑ•Ì°(€€€€¤ì(€€€½¹ÍĞ•¹Ù•±½Á”€ôì(€€€€€€¸¸¹½¹Ñ•áĞ°(€€€€€¥Á¡•ÉÑ•áÑ!…Í è…İ…¥ĞÍ¡„ÈÔØ¡¥Á¡•ÉÑ•áĞ¤°(€€€€€¹½¹”èˆØĞ¡¹½¹”¤°(€€€€€İÉ…ÁÁ•‘-•äèì(€€€€€€€•Á¡•µ•É…±AÕ‰±¥-•äè•Á¡•µ•É…±AÕ‰±¥Œ°(€€€€€€€Í…±ĞèˆØĞ¡Í…±Ğ¤°(€€€€€€€¥ØèˆØĞ¡¥Ø¤°(€€€€€€€¥Á¡•ÉÑ•áĞèˆØĞ¡İÉ…ÁÁ•¤°(€€€€€ô°(€€€ôì(€€€É•ÑÕÉ¸ì(€€€€€•¹Ù•±½Á”°(€€€€€Í¥¹…ÑÕÉ”è…İ…¥ĞÍ¥¸¡Í•¹‘•ÉAÉ¥Ù…Ñ•)İ¬°•¹Ù•±½Á”¤°(€€€€€¥Á¡•ÉÑ•áĞèˆØĞ¡¥Á¡•ÉÑ•áĞ¤°(€€€ôì(€ô™¥¹…±±äì(€€€½¹Ñ•¹Ñ	åÑ•Ì¹™¥±° À¤ì(€ô)ô(¼¨¨Á…É…´í¹ÉåÁÑ•‘=‰©•ÑôÍÕ‰µ¥ÍÍ¥½¸Á…É…´í)Í½¹]•‰-•åôÉ•¥Á¥•¹ÑAÉ¥Ù…Ñ•)İ¬Á…É…´í)Í½¹]•‰-•åôÍ•¹‘•ÉAÕ‰±¥)İ¬É•ÑÕÉ¹ÌíAÉ½µ¥Í”ñA…å±½…ùô€¨¼)•áÁ½ÉĞ…Íå¹Œ™Õ¹Ñ¥½¸‘•ÉåÁÑ=‰©•Ğ¡ÍÕ‰µ¥ÍÍ¥½¸°É•¥Á¥•¹ÑAÉ¥Ù…Ñ•)İ¬°Í•¹‘•ÉAÕ‰±¥)İ¬¤ì(€¥˜€ …ÍÕ‰µ¥ÍÍ¥½¸ñğÑåÁ•½˜ÍÕ‰µ¥ÍÍ¥½¸€„ôô€½‰©•Ğœ¤(€€€Ñ¡É½Ü¹•ÜQåÁ•ÉÉ½È %¹Ù…±¥•¹ÉåÁÑ•½‰©•Ğœ¤ì(€½¹ÍĞì•¹Ù•±½Á”°Í¥¹…ÑÕÉ”°¥Á¡•ÉÑ•áĞè•¹½‘•ô€ôÍÕ‰µ¥ÍÍ¥½¸ì(€Í…µ•-•åÌ¡•¹Ù•±½Á”°•¹Ù•±½Á•¥•±‘Ì¡•¹Ù•±½Á”¹Í¡•µ…Y•ÉÍ¥½¸¤¤ì(€½¹ÍĞì¥Á¡•ÉÑ•áÑ!…Í °¹½¹”°İÉ…ÁÁ•‘-•ä°€¸¸¹½¹Ñ•áĞô€ô•¹Ù•±½Á”ì(€Ù…±¥‘…Ñ•½¹Ñ•áĞ¡½¹Ñ•áĞ¤ì(€¥˜€ „¡…İ…¥ĞÙ•É¥™ä¡Í•¹‘•ÉAÕ‰±¥)İ¬°•¹Ù•±½Á”°Í¥¹…ÑÕÉ”¤¤¤(€€€Ñ¡É½Ü¹•ÜÉÉ½È =‰©•ĞÍ¥¹…ÑÕÉ”¥¹Ù…±¥œ¤ì(€¥˜€¡½¹Ñ•áĞ¹É•¥Á¥•¹Ñ-•å%€„ôô€¡…İ…¥Ğ­•å%¡ÁÕ‰±¥)İ¬¡É•¥Á¥•¹ÑAÉ¥Ù…Ñ•)İ¬¤¤¤¤(€€€Ñ¡É½Ü¹•ÜÉÉ½È I•¥Á¥•¹Ğ­•ä%µ¥Íµ…Ñ œ¤ì(€½¹ÍĞ¥Á¡•ÉÑ•áĞ€ôÕ¹ˆØĞ¡•¹½‘•¤ì(€¥˜€ (€€€¥Á¡•ÉÑ•áĞ¹±•¹Ñ €ø5a}=9Q9Q}	eQL€¨€Èñğ(€€€¥Á¡•ÉÑ•áĞ¹±•¹Ñ €ğ€ÄØñğ(€€€¥Á¡•ÉÑ•áÑ!…Í €„ôô€¡…İ…¥ĞÍ¡„ÈÔØ¡¥Á¡•ÉÑ•áĞ¤¤(€€¤(€€€Ñ¡É½Ü¹•ÜÉÉ½È ¥Á¡•ÉÑ•áĞ¥¹Ñ•É¥Ñäµ¥Íµ…Ñ œ¤ì(€Í…µ•-•åÌ¡İÉ…ÁÁ•‘-•ä°l•Á¡•µ•É…±AÕ‰±¥-•äœ°€Í…±Ğœ°€¥Øœ°€¥Á¡•ÉÑ•áĞt¤ì(€½¹ÍĞİÉ…Á-•ä€ô…İ…¥ĞİÉ…ÁÁ¥¹-•ä (€€€É•¥Á¥•¹ÑAÉ¥Ù…Ñ•)İ¬°(€€€İÉ…ÁÁ•‘-•ä¹•Á¡•µ•É…±AÕ‰±¥-•ä°(€€€Í¥é•¡İÉ…ÁÁ•‘-•ä¹Í…±Ğ°€ÌÈ°€Í…±Ğœ¤°(€€¤ì(€½¹ÍĞ……€ôÕÑ˜à¹•¹½‘”¡…¹½¹¥…°¡½¹Ñ•áĞ¤¤ì(€±•Ğ½¹Ñ•¹Ñ	åÑ•Ìì(€ÑÉäì(€€€½¹Ñ•¹Ñ	åÑ•Ì€ô¹•ÜU¥¹ĞáÉÉ…ä (€€€€€…İ…¥ĞÍÕ‰Ñ±”¹‘•ÉåÁĞ (€€€€€€€ì(€€€€€€€€€¹…µ”è€Lµ4œ°(€€€€€€€€€¥ØèÍ¥é•¡İÉ…ÁÁ•‘-•ä¹¥Ø°€ÄÈ°€İÉ…À%Xœ¤°(€€€€€€€€€…‘‘¥Ñ¥½¹…±…Ñ„è……°(€€€€€€€€€Ñ…1•¹Ñ è€ÄÈà°(€€€€€€€ô°(€€€€€€€İÉ…Á-•ä°(€€€€€€€Í¥é•¡İÉ…ÁÁ•‘-•ä¹¥Á¡•ÉÑ•áĞ°€Ğà°€İÉ…ÁÁ•½¹Ñ•¹Ğ­•äœ¤°(€€€€€€¤°(€€€€¤ì(€€€½¹ÍĞ­•ä€ô…İ…¥ĞÍÕ‰Ñ±”¹¥µÁ½ÉÑ-•ä É…Üœ°½¹Ñ•¹Ñ	åÑ•Ì°€Lµ4œ°™…±Í”°l‘•ÉåÁĞt¤ì(€€€½¹ÍĞÁ±…¥¸€ô…İ…¥ĞÍÕ‰Ñ±”¹‘•ÉåÁĞ (€€€€€ì(€€€€€€€¹…µ”è€Lµ4œ°(€€€€€€€¥ØèÍ¥é•¡¹½¹”°€ÄÈ°€½¹Ñ•¹Ğ¹½¹”œ¤°(€€€€€€€…‘‘¥Ñ¥½¹…±…Ñ„è……°(€€€€€€€Ñ…1•¹Ñ è€ÄÈà°(€€€€€ô°(€€€€€­•ä°(€€€€€¥Á¡•ÉÑ•áĞ°(€€€€¤ì(€€€É•ÑÕÉ¸Ù…±¥‘…Ñ•A…å±½…¡)M=8¹Á…ÉÍ”¡‘•½‘•È¹‘•½‘”¡Á±…¥¸¤¤¤ì(€ô…Ñ ì(€€€Ñ¡É½Ü¹•ÜÉÉ½È ¹ÉåÁÑ•Á…å±½……ÕÑ¡•¹Ñ¥…Ñ¥½¸™…¥±•œ¤ì(€ô™¥¹…±±äì(€€€¥˜€¡½¹Ñ•¹Ñ	åÑ•Ì¤½¹Ñ•¹Ñ	åÑ•Ì¹™¥±° À¤ì(€ô)ô(¼¨¨Á…É…´íÍÑÉ¥¹ôÁ…ÍÍÁ¡É…Í”Á…É…´íU¥¹ĞáÉÉ…äñÉÉ…å	Õ™™•ÈùôÍ…±ĞÁ…É…´í-•åUÍ…•muôÕÍ…•ÌÉ•ÑÕÉ¹ÌíAÉ½µ¥Í”ñÉåÁÑ½-•äùô€¨¼)…Íå¹Œ™Õ¹Ñ¥½¸Ù…Õ±Ñ-•ä¡Á…ÍÍÁ¡É…Í”°Í…±Ğ°ÕÍ…•Ì¤ì(€¥˜€¡ÑåÁ•½˜Á…ÍÍÁ¡É…Í”€„ôô€ÍÑÉ¥¹œœñğÁ…ÍÍÁ¡É…Í”¹±•¹Ñ €ğ€ÄÈñğÁ…ÍÍÁ¡É…Í”¹±•¹Ñ €ø€ÄÀÈĞ¤(€€€Ñ¡É½Ü¹•ÜQåÁ•ÉÉ½È Y…Õ±ĞÁ…ÍÍÁ¡É…Í”µÕÍĞ½¹Ñ…¥¸€ÄËŠLÄÀÈĞ¡…É…Ñ•ÉÌœ¤ì(€½¹ÍĞ­•ä€ô…İ…¥ĞÍÕ‰Ñ±”¹¥µÁ½ÉÑ-•ä É…Üœ°ÕÑ˜à¹•¹½‘”¡Á…ÍÍÁ¡É…Í”¤°€A	-Èœ°™…±Í”°l(€€€€‘•É¥Ù•-•äœ°(€t¤ì(€É•ÑÕÉ¸ÍÕ‰Ñ±”¹‘•É¥Ù•-•ä (€€€ì¹…µ”è€A	-Èœ°Í…±Ğ°¥Ñ•É…Ñ¥½¹ÌèYU1Q}%QIQ%=9L°¡…Í è€M!´ÈÔØœô°(€€€­•ä°(€€€ì¹…µ”è€Lµ4œ°±•¹Ñ è€ÈÔØô°(€€€™…±Í”°(€€€ÕÍ…•Ì°(€€¤ì)ô(¼¨¨Á…É…´íÕ¹­¹½İ¹ôÙ…±Õ”Á…É…´íÍÑÉ¥¹ôÁ…ÍÍÁ¡É…Í”É•ÑÕÉ¹ÌíAÉ½µ¥Í”ñ¥µÁ½ÉĞ ˆ¸¸½½‰©•Ğµ™½Éµ…Ğ½ÑåÁ•Ì¹©Ìˆ¤¹Y…Õ±ÑA…­•Ğùô€¨¼)•áÁ½ÉĞ…Íå¹Œ™Õ¹Ñ¥½¸Í•…±Y…Õ±Ğ¡Ù…±Õ”°Á…ÍÍÁ¡É…Í”¤ì(€½¹ÍĞÍ…±Ğ€ôÉ…¹‘½´ ÌÈ¤°(€€€¥Ø€ôÉ…¹‘½´ ÄÈ¤ì(€½¹ÍĞµ•Ñ…‘…Ñ„€ôì(€€€Ù•ÉÍ¥½¸è€Ä°(€€€­‘˜è€A	-ÈµM!ÈÔØœ°(€€€¥Ñ•É…Ñ¥½¹ÌèYU1Q}%QIQ%=9L°(€€€Í…±ĞèˆØĞ¡Í…±Ğ¤°(€€€¥ØèˆØĞ¡¥Ø¤°(€ôì(€½¹ÍĞ­•ä€ô…İ…¥ĞÙ…Õ±Ñ-•ä¡Á…ÍÍÁ¡É…Í”°Í…±Ğ°l•¹ÉåÁĞt¤ì(€½¹ÍĞ¥Á¡•ÉÑ•áĞ€ô…İ…¥ĞÍÕ‰Ñ±”¹•¹ÉåÁĞ (€€€ì¹…µ”è€Lµ4œ°¥Ø°…‘‘¥Ñ¥½¹…±…Ñ„èÕÑ˜à¹•¹½‘”¡…¹½¹¥…°¡µ•Ñ…‘…Ñ„¤¤°Ñ…1•¹Ñ è€ÄÈàô°(€€€­•ä°(€€€ÕÑ˜à¹•¹½‘”¡…¹½¹¥…°¡Ù…±Õ”¤¤°(€€¤ì(€É•ÑÕÉ¸ì€¸¸¹µ•Ñ…‘…Ñ„°¥Á¡•ÉÑ•áĞèˆØĞ¡¥Á¡•ÉÑ•áĞ¤ôì)ô(¼¨¨Á…É…´í¥µÁ½ÉĞ ˆ¸¸½½‰©•Ğµ™½Éµ…Ğ½ÑåÁ•Ì¹©Ìˆ¤¹Y…Õ±ÑA…­•ÑôÁ…­•ĞÁ…É…´íÍÑÉ¥¹ôÁ…ÍÍÁ¡É…Í”É•ÑÕÉ¹ÌíAÉ½µ¥Í”ñÕ¹­¹½İ¸ùô€¨¼)•áÁ½ÉĞ…Íå¹Œ™Õ¹Ñ¥½¸½Á•¹Y…Õ±Ğ¡Á…­•Ğ°Á…ÍÍÁ¡É…Í”¤ì(€Í…µ•-•åÌ¡Á…­•Ğ°lÙ•ÉÍ¥½¸œ°€­‘˜œ°€¥Ñ•É…Ñ¥½¹Ìœ°€Í…±Ğœ°€¥Øœ°€¥Á¡•ÉÑ•áĞt¤ì(€½¹ÍĞì¥Á¡•ÉÑ•áĞ°€¸¸¹µ•Ñ…‘…Ñ„ô€ôÁ…­•Ğì(€¥˜€ (€€€µ•Ñ…‘…Ñ„¹Ù•ÉÍ¥½¸€„ôô€Äñğ(€€€µ•Ñ…‘…Ñ„¹­‘˜€„ôô€A	-ÈµM!ÈÔØœñğ(€€€µ•Ñ…‘…Ñ„¹¥Ñ•É…Ñ¥½¹Ì€„ôôYU1Q}%QIQ%=9L(€€¤(€€€Ñ¡É½Ü¹•ÜQåÁ•ÉÉ½È U¹ÍÕÁÁ½ÉÑ•Ù…Õ±Ğ™½Éµ…Ğœ¤ì(€½¹ÍĞÍ…±Ğ€ôÍ¥é•¡µ•Ñ…‘…Ñ„¹Í…±Ğ°€ÌÈ°€Ù…Õ±ĞÍ…±Ğœ¤°(€€€¥Ø€ôÍ¥é•¡µ•Ñ…‘…Ñ„¹¥Ø°€ÄÈ°€Ù…Õ±Ğ%Xœ¤ì(€½¹ÍĞ­•ä€ô…İ…¥ĞÙ…Õ±Ñ-•ä¡Á…ÍÍÁ¡É…Í”°Í…±Ğ°l‘•ÉåÁĞt¤ì(€ÑÉäì(€€€½¹ÍĞÁ±…¥¹Ñ•áĞ€ô…İ…¥ĞÍÕ‰Ñ±”¹‘•ÉåÁĞ (€€€€€ì¹…µ”è€Lµ4œ°¥Ø°…‘‘¥Ñ¥½¹…±…Ñ„èÕÑ˜à¹•¹½‘”¡…¹½¹¥…°¡µ•Ñ…‘…Ñ„¤¤°Ñ…1•¹Ñ è€ÄÈàô°(€€€€€­•ä°(€€€€€Õ¹ˆØĞ¡¥Á¡•ÉÑ•áĞ¤°(€€€€¤ì(€€€½¹ÍĞÙ…±Õ”€ô)M=8¹Á…ÉÍ”¡‘•½‘•È¹‘•½‘”¡Á±…¥¹Ñ•áĞ¤¤ì(€€€…¹½¹¥…°¡Ù…±Õ”¤ì(€€€É•ÑÕÉ¸Ù…±Õ”ì(€ô…Ñ ì(€€€Ñ¡É½Ü¹•ÜÉÉ½È Y…Õ±ĞÕ¹±½¬™…¥±•œ¤ì(€ô)ô(