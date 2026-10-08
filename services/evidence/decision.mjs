import { randomUUID } from 'node:crypto';
import { hash } from '../control/primitives.mjs';
import { storedEnvelope } from '../admission/integrity.mjs';
import { PQC_SUITES } from '../../packages/crypto-provider/pqc-identifiers.mjs';

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const digest = /^[a-f0-9]{64}$/;
const mission = /^[A-Za-z0-9._:-]{1,80}$/;
const reference = (value, pattern) =>
  typeof value === 'string' && pattern.test(value) ? value : null;

// Ported from a4abc80; suite table now comes from the shared identifier module.
function validatedCryptoEvidence(value) {
  const fields = [
    'envelopeVersion',
    'providerId',
    'suiteId',
    'suiteVersion',
    'senderKeyId',
    'recipientKeyId',
    'creationPolicyRevision',
    'currentPolicyRevision',
    'policyDigest',
  ];
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    !fields.every((field) => Object.hasOwn(value, field))
  )
    return null;
  const knownSuite = PQC_SUITES.get(value.suiteId)?.providerId === value.providerId;
  if (
    !knownSuite ||
    value.envelopeVersion !== 3 ||
    value.suiteVersion !== 1 ||
    !reference(value.senderKeyId, digest) ||
    !reference(value.recipientKeyId, digest) ||
    !reference(value.policyDigest, digest) ||
    !Number.isSafeInteger(value.creationPolicyRevision) ||
    value.creationPolicyRevision < 1 ||
    !Number.isSafeInteger(value.currentPolicyRevision) ||
    value.currentPolicyRevision < value.creationPolicyRevision
  )
    return null;
  return Object.fromEntries(fields.map((field) => [field, value[field]]));
}

// One schema for ALLOW/READY, HOLD, and release/retry decisions. The caller signs
// and persists these fields in its existing transaction with the state update.
export function decisionEvidence({ row, authority, policyDigest, session, state, reason, extra }) {
  const e = storedEnvelope(row) ?? {};
  const { crypto: rawCrypto, ...additionalDetails } = extra ?? {};
  const cryptoEvidence = validatedCryptoEvidence(rawCrypto);
  // A successful v3 issuance cannot lose its cryptographic provenance. A corrupt HOLD may
  // omit unusable metadata while retaining the rejected envelope digest.
  if (
    ['RELEASED', 'DELIVERED'].includes(state) &&
    (e.schemaVersion === 3 || rawCrypto !== undefined) &&
    !cryptoEvidence
  )
    throw new Error('V3 release requires valid cryptographic evidence');
  // HOLD evidence must remain signable even when the stored envelope is corrupt.
  // Copy only expected scalars; the raw-byte digest preserves the rejected input.
  const senderUnitId = reference(e.senderUnitId, uuid);
  const destinationUnitId = reference(e.recipientUnitId, uuid);
  const missionId = reference(e.missionId, mission);
  const creation = e.creationGrant?.payload;
  const creationEpoch =
    Number.isSafeInteger(creation?.creationEpoch) && creation.creationEpoch > 0
      ? creation.creationEpoch
      : null;
  return {
    decisionId: randomUUID(),
    objectId: row.id,
    decision: state,
    releaseState: state,
    reason: reason ?? 'CURRENT_AUTHORITY_VALID',
    details: {
      objectDigest: row.digest,
      envelopeDigest: hash(row.envelope),
      objectSchemaVersion: [1, 2, 3].includes(e.schemaVersion) ? e.schemaVersion : null,
      senderUserId: row.sender_id,
      senderDeviceId: row.sender_device,
      recipientUserId: row.recipient_id,
      recipientDeviceId: row.recipient_device,
      destinationUnitId,
      missionId,
      action: e.action === 'deliver' ? e.action : null,
      creationGrantId: reference(creation?.grantId, uuid),
      creationEpoch,
      creationPolicyDigest: reference(creation?.policyDigest, digest),
      policyReference: {
        fromUnitId: senderUnitId,
        toUnitId: destinationUnitId,
        missionId,
      },
      policyDigest,
      revocationVersion: authority.revocation_version,
      authorityEpoch: authority.epoch,
      deviceEvidence: 'software-proof-of-possession',
      proofEvidence: session.proofEvidence ?? { source: 'internal-call-no-http-proof' },
      ...additionalDetails,
      ...(cryptoEvidence ? { crypto: cryptoEvidence } : {}),
    },
  };
}
