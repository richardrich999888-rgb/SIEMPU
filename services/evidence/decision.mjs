import { randomUUID } from 'node:crypto';
import { hash } from '../control/primitives.mjs';
import { storedEnvelope } from '../admission/integrity.mjs';

// One schema for ALLOW/READY, HOLD, and release/retry decisions. The caller signs
// and persists these fields in its existing transaction with the state update.
export function decisionEvidence({ row, authority, policyDigest, session, state, reason, extra }) {
  const e = storedEnvelope(row) ?? {};
  return {
    decisionId: randomUUID(),
    objectId: row.id,
    decision: state,
    releaseState: state,
    reason: reason ?? 'CURRENT_AUTHORITY_VALID',
    details: {
      objectDigest: row.digest,
      envelopeDigest: hash(row.envelope),
      senderUserId: row.sender_id,
      senderDeviceId: row.sender_device,
      recipientUserId: row.recipient_id,
      recipientDeviceId: row.recipient_device,
      destinationUnitId: e.recipientUnitId ?? null,
      missionId: e.missionId ?? null,
      action: e.action ?? null,
      creationGrantId: e.creationGrant?.payload?.grantId ?? null,
      creationEpoch: e.creationGrant?.payload?.creationEpoch ?? null,
      creationPolicyDigest: e.creationGrant?.payload?.policyDigest ?? null,
      policyReference: {
        fromUnitId: e.senderUnitId ?? null,
        toUnitId: e.recipientUnitId ?? null,
        missionId: e.missionId ?? null,
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
