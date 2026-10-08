import { validMissionProfile } from '../mission/policy.mjs';

// Shared wire-field contract for client encryption, submission and persisted-state checks.
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
/** @param {number} version */
export function contextFields(version) {
  if (version === 1) return v1;
  if (version === 2) return v2;
  return [];
}
/** @param {number} version */
export function envelopeFieldsFor(version) {
  const fields = contextFields(version);
  return fields.length ? [...fields, 'ciphertextHash', 'nonce', 'wrappedKey'] : null;
}
/** @param {{schemaVersion?: number, messagePriority?: string, messageDomain?: string} | null} envelope */
export function validEnvelopeVersion(envelope) {
  return (
    envelope?.schemaVersion === 1 ||
    (envelope?.schemaVersion === 2 &&
      validMissionProfile(envelope.messagePriority, envelope.messageDomain))
  );
}
