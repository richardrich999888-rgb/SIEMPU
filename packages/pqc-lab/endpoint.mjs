// Laboratory endpoint wiring: one CryptoEngine per endpoint, holding that endpoint's private
// handles. ENDPOINT ONLY; never instantiate in a service. Lab policy is explicit and local.

import { CryptoEngine } from '../crypto-provider/engine.mjs';
import { PROVIDER_ENVELOPE_VERSION } from './envelope.mjs';

/**
 * Creates an endpoint engine restricted to exactly one laboratory suite and generates the
 * endpoint's ML-DSA signing key and KEM encapsulation key inside it.
 * @param {{provider: object, providerId: string, suiteId: string}} input
 */
export async function createLabEndpoint({ provider, providerId, suiteId }) {
  const selection = { providerId, suiteId };
  const engine = new CryptoEngine({
    providers: [provider],
    policy: {
      schemaVersion: 1,
      revision: 1,
      mode: 'laboratory',
      newSuites: [selection],
      legacySuites: [selection],
    },
  });
  const signingKey = await engine.generateKey({ ...selection, purpose: 'sign' });
  const encapsulationKey = await engine.generateKey({ ...selection, purpose: 'encapsulate' });
  return { engine, selection, signingKey, encapsulationKey };
}

/**
 * Builds a schema-v3 context from the classical identity fields plus provider binding.
 * @param {{sender: {userId: string, deviceId: string, unitId: string},
 *   recipient: {userId: string, deviceId: string, unitId: string},
 *   creationGrant: object, selection: {providerId: string, suiteId: string},
 *   senderCryptoKeyId: string, recipientKeyId: string, suitePolicyRevision: number,
 *   objectId: string, now: number, lifetimeMs?: number, missionId?: string,
 *   messagePriority?: string, messageDomain?: string}} input
 */
export function labContext({
  sender,
  recipient,
  creationGrant,
  selection,
  senderCryptoKeyId,
  recipientKeyId,
  suitePolicyRevision,
  objectId,
  now,
  lifetimeMs = 10 * 60 * 1000,
  missionId = 'DEMO-MISSION',
  messagePriority = 'ROUTINE',
  messageDomain = 'GENERAL',
}) {
  return {
    schemaVersion: PROVIDER_ENVELOPE_VERSION,
    objectId,
    senderUserId: sender.userId,
    senderDeviceId: sender.deviceId,
    senderUnitId: sender.unitId,
    recipientUserId: recipient.userId,
    recipientDeviceId: recipient.deviceId,
    recipientUnitId: recipient.unitId,
    recipientKeyId,
    missionId,
    classification: 'DEMO',
    action: 'deliver',
    createdAt: now,
    expiresAt: now + lifetimeMs,
    creationGrant,
    cryptoSuite: selection.suiteId,
    keyVersion: 1,
    messagePriority,
    messageDomain,
    providerId: selection.providerId,
    suiteVersion: 1,
    senderCryptoKeyId,
    suitePolicyRevision,
  };
}
