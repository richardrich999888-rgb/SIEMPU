import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { validateDeviceChallenge, validateReleaseScope } from './challenge.mjs';

function example(purpose = 'operation') {
  const expected = {
    purpose,
    requestHash: 'a'.repeat(64),
    deviceId: randomUUID(),
    operation: 'submit',
  };
  const challenge = {
    domain: 'SIEPMU_DEVICE_PROOF_V1',
    nonce: 'A'.repeat(43),
    sessionId: randomUUID(),
    purpose,
    expiresAt: Date.now() + 60000,
  };
  if (purpose !== 'bind') challenge.requestHash = expected.requestHash;
  if (purpose !== 'enroll') challenge.deviceId = expected.deviceId;
  if (purpose === 'operation') challenge.operation = expected.operation;
  return { reply: { challengeId: randomUUID(), challenge }, expected };
}
test('device challenge permits only the exact intended bind, enroll or operation transcript', () => {
  for (const purpose of ['bind', 'enroll', 'operation']) {
    const { reply, expected } = example(purpose);
    assert.equal(validateDeviceChallenge(reply, expected), reply.challenge);
  }
});
test('device refuses arbitrary signing messages, wrong scope, changed body, expiry and extra fields', () => {
  const { reply, expected } = example();
  for (const change of [
    { domain: 'OTHER_DOMAIN' },
    { purpose: 'bind' },
    { operation: 'admin:PUT:/api/admin/policies' },
    { requestHash: 'b'.repeat(64) },
    { deviceId: randomUUID() },
    { expiresAt: Date.now() - 1 },
    { expiresAt: Date.now() + 120000 },
    { objectId: randomUUID() },
  ]) {
    assert.throws(
      () =>
        validateDeviceChallenge(
          { ...reply, challenge: { ...reply.challenge, ...change } },
          expected,
        ),
      /locally intended/,
    );
  }
  assert.throws(
    () =>
      validateDeviceChallenge(
        { ...reply, challenge: { schemaVersion: 1, objectId: randomUUID(), action: 'deliver' } },
        expected,
      ),
    /locally intended/,
  );
});
test('a signed admission receipt is not accepted as a release; recipient and device must match', () => {
  const expected = { userId: randomUUID(), deviceId: randomUUID(), objectId: randomUUID() };
  const receipt = {
    eventType: 'RELEASE_ISSUED',
    decision: 'RELEASED',
    actorId: expected.userId,
    objectId: expected.objectId,
    details: {
      recipientUserId: expected.userId,
      recipientDeviceId: expected.deviceId,
      action: 'deliver',
    },
  };
  validateReleaseScope(receipt, expected);
  for (const change of [
    { eventType: 'SUBMITTED' },
    { decision: 'HELD' },
    { actorId: randomUUID() },
    { details: { ...receipt.details, recipientDeviceId: randomUUID() } },
  ])
    assert.throws(() => validateReleaseScope({ ...receipt, ...change }, expected), /not a release/);
});
