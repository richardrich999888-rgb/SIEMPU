// Laboratory schema-v3 object envelope for endpoint PQC providers.
//
// ENDPOINT ONLY. Never import this module from the authority, relay, gateway, adapter,
// collector or custodian: it drives a CryptoEngine that holds recipient private handles.
// It replaces the a4abc80 version, which was published corrupted and never imported.
//
// Construction (no new primitive or combiner; every step is an existing reviewed component):
//   1. contentKey  <- 32 random bytes (CSPRNG).
//   2. ciphertext  <- AES-256-GCM(contentKey, plaintext = canonical(payload),
//                                  AAD = canonical({domain, context})).
//   3. wrappedKey  <- engine.wrapKey(recipient KEM key, contentKey, binding context):
//                     KEM (ML-KEM-768/1024 or X-Wing) -> HKDF-SHA256 (salt, domain-separated
//                     info naming provider, suite, recipient key ID and context) -> AES-256-GCM.
//   4. providerSignature <- ML-DSA-65 over canonical(envelope without providerSignature).
//   5. identity signature <- ECDSA P-256 (device identity key) over canonical(full envelope);
//                     this is the signature the authority already verifies for v1/v2.
// Both signatures are required independently (conjunction); neither substitutes for the other.

import { createHash, randomBytes } from 'node:crypto';
import { canonical } from '../protocol/canonical.mjs';
import {
  b64,
  unb64,
  contextFields,
  validatePayload,
  validMissionProfile,
  sign,
  verify,
} from '../crypto/crypto.mjs';
import { validateProviderPublicKey } from '../crypto-provider/engine.mjs';
import { MLDSA65_SIGNATURE_BYTES, decodeBytes } from '../crypto-provider/pqc-identifiers.mjs';

export const PROVIDER_ENVELOPE_VERSION = 3;
const CONTENT_AAD_DOMAIN = 'SIEPMU_PROVIDER_CONTENT_AAD_V3';
const CONTENT_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
/** Matches the authority's 1 MiB ciphertext ceiling (1048576 + GCM tag). */
const MAX_CIPHERTEXT_BYTES = 1048576 + GCM_TAG_BYTES;
/** Matches the authority's maximum object lifetime. */
const MAX_LIFETIME_MS = 3600000;

const utf8 = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIGEST = /^[a-f0-9]{64}$/;
const MISSION = /^[A-Za-z0-9._:-]{1,80}$/;

/** @param {unknown} condition @param {string} message @returns {asserts condition} */
function require_(condition, message) {
  if (!condition) throw new TypeError(message);
}

/**
 * Validates the exact v3 context: member set, identifiers, labels, provider fields and lifetime.
 * @param {Record<string, any>} context
 */
export function validateProviderContext(context) {
  require_(
    context?.schemaVersion === PROVIDER_ENVELOPE_VERSION,
    'A provider object requires schema v3',
  );
  const fields = contextFields(PROVIDER_ENVELOPE_VERSION);
  require_(
    Object.keys(context).length === fields.length && fields.every((k) => Object.hasOwn(context, k)),
    'Invalid provider context members',
  );
  canonical(context);
  for (const field of [
    'objectId',
    'senderUserId',
    'senderDeviceId',
    'senderUnitId',
    'recipientUserId',
    'recipientDeviceId',
    'recipientUnitId',
  ])
    require_(typeof context[field] === 'string' && UUID.test(context[field]), `Invalid ${field}`);
  require_(
    DIGEST.test(context.recipientKeyId) &&
      DIGEST.test(context.senderCryptoKeyId) &&
      context.suiteVersion === 1 &&
      context.keyVersion === 1 &&
      Number.isSafeInteger(context.suitePolicyRevision) &&
      context.suitePolicyRevision > 0 &&
      context.classification === 'DEMO' &&
      context.action === 'deliver' &&
      typeof context.missionId === 'string' &&
      MISSION.test(context.missionId) &&
      validMissionProfile(context.messagePriority, context.messageDomain) &&
      Number.isSafeInteger(context.createdAt) &&
      Number.isSafeInteger(context.expiresAt) &&
      context.createdAt >= 0 &&
      context.expiresAt > context.createdAt &&
      context.expiresAt <= context.createdAt + MAX_LIFETIME_MS,
    'Invalid provider context',
  );
}

/** Binds both public descriptors to the context and checks their identity hashes. */
function bindPublicKeys(context, senderKey, recipientKey) {
  for (const [key, purpose, keyId] of [
    [senderKey, 'sign', context.senderCryptoKeyId],
    [recipientKey, 'encapsulate', context.recipientKeyId],
  ]) {
    const checked = validateProviderPublicKey(key);
    require_(
      checked.purpose === purpose &&
        checked.keyId === keyId &&
        checked.providerId === context.providerId &&
        checked.suiteId === context.cryptoSuite,
      'Provider key/context binding mismatch',
    );
  }
}

/** AAD for the content ciphertext: the whole signed context under a fixed domain label. */
const contentAad = (context) => utf8.encode(canonical({ domain: CONTENT_AAD_DOMAIN, context }));
/** Context bound into the key wrap: the signed context plus the ciphertext digest. */
const wrapContext = (context, ciphertextHash) => ({ ...context, ciphertextHash });
/** Bytes covered by the ML-DSA provider signature. */
const providerSigned = (envelope) => {
  const { providerSignature: _omitted, ...rest } = envelope;
  return utf8.encode(canonical(rest));
};

/**
 * Sender endpoint: encrypts, wraps, and signs a v3 object. Returns the same submission shape as
 * classical objects: { envelope, signature, ciphertext } (ciphertext base64url).
 * @param {{engine: import('../crypto-provider/engine.mjs').CryptoEngine, context: Record<string, any>,
 *   payload: import('../object-format/types.js').Payload, recipientKey: object, senderKey: object,
 *   identitySigningKey: JsonWebKey}} input
 */
export async function createProviderObject({
  engine,
  context,
  payload,
  recipientKey,
  senderKey,
  identitySigningKey,
}) {
  validateProviderContext(context);
  validatePayload(payload);
  bindPublicKeys(context, senderKey, recipientKey);
  const selection = { providerId: context.providerId, suiteId: context.cryptoSuite };
  engine.assertAllowed(selection);
  const contentKey = randomBytes(CONTENT_KEY_BYTES);
  try {
    const plaintext = utf8.encode(canonical(payload));
    const sealed = await engine.encrypt({
      ...selection,
      key: new Uint8Array(contentKey),
      plaintext,
      aad: contentAad(context),
    });
    const ciphertext = unb64(sealed.ciphertext);
    require_(ciphertext.length <= MAX_CIPHERTEXT_BYTES, 'Payload exceeds the object size limit');
    const ciphertextHash = sha256Hex(ciphertext);
    const wrappedKey = await engine.wrapKey({
      key: recipientKey,
      contentKey: new Uint8Array(contentKey),
      context: wrapContext(context, ciphertextHash),
    });
    const unsigned = { ...context, ciphertextHash, nonce: sealed.nonce, wrappedKey };
    const providerSignature = b64(
      await engine.sign({ keyId: senderKey.keyId, data: providerSigned(unsigned) }),
    );
    const envelope = { ...unsigned, providerSignature };
    return {
      envelope,
      signature: await sign(identitySigningKey, envelope),
      ciphertext: sealed.ciphertext,
    };
  } finally {
    contentKey.fill(0);
  }
}

/**
 * Recipient endpoint: verifies both signatures, the key binding, the ciphertext digest and the
 * authenticated wrap before decrypting. Any mismatch throws; nothing partial is returned.
 * @param {{engine: import('../crypto-provider/engine.mjs').CryptoEngine,
 *   claim: {envelope: Record<string, any>, signature: string, ciphertext: string},
 *   senderKey: object, senderIdentityPublicKey: JsonWebKey, expected?: {suiteId?: string}}} input
 */
export async function openProviderObject({
  engine,
  claim,
  senderKey,
  senderIdentityPublicKey,
  expected = {},
}) {
  const { envelope, signature, ciphertext } = claim;
  const { ciphertextHash, nonce, wrappedKey, providerSignature, ...context } = envelope;
  validateProviderContext(context);
  // Downgrade guard: a recipient that expects a specific suite refuses any other.
  if (expected.suiteId !== undefined)
    require_(context.cryptoSuite === expected.suiteId, 'Unexpected cryptographic suite');
  require_(
    await verify(senderIdentityPublicKey, envelope, signature),
    'Identity signature invalid',
  );
  const checkedSender = validateProviderPublicKey(senderKey);
  require_(
    checkedSender.purpose === 'sign' &&
      checkedSender.keyId === context.senderCryptoKeyId &&
      checkedSender.providerId === context.providerId &&
      checkedSender.suiteId === context.cryptoSuite,
    'Sender provider key binding mismatch',
  );
  require_(
    await engine.verify({
      key: checkedSender,
      data: providerSigned(envelope),
      signature: decodeBytes(providerSignature, MLDSA65_SIGNATURE_BYTES),
    }),
    'Provider signature invalid',
  );
  const bytes = unb64(ciphertext);
  require_(bytes.length <= MAX_CIPHERTEXT_BYTES, 'Ciphertext exceeds the object size limit');
  require_(sha256Hex(bytes) === ciphertextHash, 'Ciphertext digest mismatch');
  decodeBytes(nonce, NONCE_BYTES);
  require_(wrappedKey?.recipientKeyId === context.recipientKeyId, 'Wrapped key recipient mismatch');
  const contentKey = await engine.unwrapKey({
    keyId: context.recipientKeyId,
    packet: wrappedKey,
    context: wrapContext(context, ciphertextHash),
  });
  try {
    const plaintext = await engine.decrypt({
      providerId: context.providerId,
      suiteId: context.cryptoSuite,
      key: contentKey,
      packet: { nonce, ciphertext },
      aad: contentAad(context),
    });
    const payload = JSON.parse(decoder.decode(plaintext));
    return validatePayload(payload);
  } finally {
    contentKey.fill(0);
  }
}
