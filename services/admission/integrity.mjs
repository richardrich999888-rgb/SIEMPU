import { canonical, decode, validateKey, verify } from '../control/primitives.mjs';

import {
  PROVIDER_SCHEMA_VERSION,
  envelopeFieldsFor,
  validEnvelopeVersion,
} from '../../packages/object-format/schema.mjs';
import { validatePqcEnvelope } from '../crypto-policy/registry.mjs';
export { envelopeFieldsFor };

const CLASSICAL_SUITE = 'P256-HKDF-SHA256-AES256GCM';
const CLASSICAL_WRAP_FIELDS = 'ciphertext,ephemeralPublicKey,iv,salt';

/** Classical P-256 key wrap: exact members and sizes; throws on malformed key material. */
function classicalWrapValid(w) {
  if (
    !w ||
    Object.keys(w).sort().join(',') !== CLASSICAL_WRAP_FIELDS ||
    decode(w.salt).length !== 32 ||
    decode(w.iv).length !== 12 ||
    decode(w.ciphertext).length !== 48
  )
    return false;
  validateKey(w.ephemeralPublicKey);
  return true;
}

// Corrupt persistence must produce a durable HOLD, including when JSON is unreadable.
export function storedEnvelope(row) {
  try {
    const value = JSON.parse(row.envelope);
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

// Called under the same write transaction as the authority decision and issuance.
// Submission-time verification is insufficient: storage may change while queued.
export function storedObjectIntegrityReason(row, signingKey) {
  const e = storedEnvelope(row);
  const envelopeFields = envelopeFieldsFor(e?.schemaVersion);
  if (
    !e ||
    !envelopeFields ||
    Object.keys(e).length !== envelopeFields.length ||
    !envelopeFields.every((field) => Object.hasOwn(e, field))
  )
    return 'OBJECT_ENVELOPE_SCHEMA';
  // Submission persists canonical JSON. Preserve that invariant so the evidence
  // digest covers exactly the envelope representation used by the recipient.
  try {
    if (row.envelope !== canonical(e)) return 'OBJECT_ENVELOPE_NONCANONICAL';
  } catch {
    return 'OBJECT_ENVELOPE_NONCANONICAL';
  }
  if (
    e.objectId !== row.id ||
    e.senderUserId !== row.sender_id ||
    e.recipientUserId !== row.recipient_id ||
    e.senderDeviceId !== row.sender_device ||
    e.recipientDeviceId !== row.recipient_device ||
    e.ciphertextHash !== row.digest
  )
    return 'OBJECT_BINDING_MISMATCH';
  if (!verify(signingKey, e, row.signature)) return 'OBJECT_SIGNATURE_INVALID';
  try {
    if (
      !validEnvelopeVersion(e) ||
      e.classification !== 'DEMO' ||
      e.action !== 'deliver' ||
      (e.schemaVersion !== PROVIDER_SCHEMA_VERSION && e.cryptoSuite !== CLASSICAL_SUITE) ||
      e.keyVersion !== 1 ||
      !Number.isSafeInteger(e.createdAt) ||
      !Number.isSafeInteger(e.expiresAt) ||
      e.createdAt > Date.now() + 30000 ||
      e.expiresAt <= e.createdAt ||
      e.expiresAt > e.createdAt + 3600000 ||
      !/^[a-f0-9]{64}$/.test(e.ciphertextHash) ||
      !/^[a-f0-9]{64}$/.test(e.recipientKeyId) ||
      typeof e.missionId !== 'string' ||
      !/^[A-Za-z0-9._:-]{1,80}$/.test(e.missionId) ||
      decode(e.nonce).length !== 12
    )
      return 'OBJECT_ENVELOPE_INVALID';
    // Each schema accepts only its own wrap format; v3 structure is checked here, while
    // provider policy, key status and the ML-DSA signature are checked by the registry.
    if (e.schemaVersion === PROVIDER_SCHEMA_VERSION) validatePqcEnvelope(e);
    else if (!classicalWrapValid(e.wrappedKey)) return 'OBJECT_ENVELOPE_INVALID';
  } catch {
    return 'OBJECT_ENVELOPE_INVALID';
  }
  return null;
}
