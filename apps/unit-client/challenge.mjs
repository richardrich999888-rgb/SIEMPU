const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest = /^[0-9a-f]{64}$/;

/** Never let the authority turn a device challenge into an arbitrary signing request. */
export function validateDeviceChallenge(reply, expected, now = Date.now()) {
  const invalid = () => {
    throw new Error('Device challenge does not match the locally intended operation.');
  };
  if (
    !reply ||
    Object.keys(reply).sort().join(',') !== 'challenge,challengeId' ||
    !uuid.test(reply.challengeId)
  )
    invalid();
  const c = reply.challenge;
  const fields = ['domain', 'nonce', 'sessionId', 'purpose', 'expiresAt'];
  if (expected.purpose === 'bind') fields.push('deviceId');
  else if (expected.purpose === 'enroll') fields.push('requestHash');
  else if (expected.purpose === 'operation') fields.push('deviceId', 'operation', 'requestHash');
  else invalid();
  if (!c || Object.keys(c).sort().join(',') !== fields.sort().join(',')) invalid();
  if (
    c.domain !== 'SIEPMU_DEVICE_PROOF_V1' ||
    c.purpose !== expected.purpose ||
    !uuid.test(c.sessionId) ||
    !/^[A-Za-z0-9_-]{43}$/.test(c.nonce)
  )
    invalid();
  if (!Number.isSafeInteger(c.expiresAt) || c.expiresAt <= now || c.expiresAt > now + 90000)
    invalid();
  if ('deviceId' in c && (!uuid.test(c.deviceId) || c.deviceId !== expected.deviceId)) invalid();
  if ('operation' in c && c.operation !== expected.operation) invalid();
  if ('requestHash' in c && (!digest.test(c.requestHash) || c.requestHash !== expected.requestHash))
    invalid();
  return c;
}

export function validateReleaseScope(receipt, expected) {
  if (
    receipt.eventType !== 'RELEASE_ISSUED' ||
    receipt.decision !== 'RELEASED' ||
    receipt.actorId !== expected.userId ||
    receipt.objectId !== expected.objectId ||
    receipt.details?.recipientUserId !== expected.userId ||
    receipt.details?.recipientDeviceId !== expected.deviceId ||
    receipt.details?.action !== 'deliver'
  )
    throw new Error('Signed receipt is not a release for this recipient and device.');
}
