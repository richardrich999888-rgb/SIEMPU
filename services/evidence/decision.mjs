import { randomUUID } from 'node:crypto';
import { hash } from '../control/primitives.mjs';
import { storedEnvelope } from '../admission/integrity.mjs';

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const digest = /^[a-f0-9]{64}$/;
const mission = /^[A-Za-z0-9._:-]{1,80}$/;
const reference = (value, pattern) =>
  typeof value === 'string' && pattern.test(value) ? value : null;

// One schema for ALLOW/READY, HOLD, and release/retry decisions. The caller signs
// and persists these fields in its existing transaction with the state update.
export function decisionEvidence({ row, authority, policyDigest, session, state, reason, extra }) {
  const e = storedEnvelope(row) ?? {};
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
      objectSchemaVersion: [1, 2].includes(e.schemaVersion) ? e.schemaVersion : null,
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
      ...extra,
    },
  };
}
