import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { coreFixture } from './helpers/fixture.mjs';
import { canonical, createObject, hash, sign, verify } from './helpers/client.mjs';

async function submitted(t) {
  const f = await coreFixture(t);
  await f.clients.alice.authenticate();
  await f.clients.bob.authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  await f.clients.alice.submit(object);
  const id = object.envelope.objectId;
  const epoch = f.authority.epoch().epoch;
  return { ...f, object, id, epoch };
}

function noDisclosure(result) {
  assert.equal(result.body.object.state, 'HELD');
  assert.equal(result.body.envelope, undefined);
  assert.equal(result.body.signature, undefined);
  assert.equal(result.body.ciphertext, undefined);
  assert.ok(!JSON.stringify(result.body).includes('wrappedKey'));
}

function noIssuance(f) {
  assert.equal(f.authority.get('SELECT COUNT(*) AS n FROM issuances').n, 0);
}

function fullEvidence(f, receipt, state) {
  const p = receipt.payload;
  const e = f.object.envelope;
  const a = f.authority.epoch();
  assert.match(p.decisionId, /^[a-f0-9-]{36}$/);
  assert.match(p.eventId, /^[a-f0-9-]{36}$/);
  assert.equal(p.objectId, f.id);
  assert.equal(p.decision, state);
  assert.equal(p.releaseState, state);
  assert.equal(p.epoch, a.epoch);
  assert.ok(Number.isSafeInteger(p.timestamp));
  assert.equal(p.details.objectDigest, e.ciphertextHash);
  assert.equal(p.details.envelopeDigest, hash(canonical(e)));
  assert.equal(p.details.senderUserId, e.senderUserId);
  assert.equal(p.details.senderDeviceId, e.senderDeviceId);
  assert.equal(p.details.recipientUserId, e.recipientUserId);
  assert.equal(p.details.recipientDeviceId, e.recipientDeviceId);
  assert.equal(p.details.destinationUnitId, e.recipientUnitId);
  assert.equal(p.details.missionId, e.missionId);
  assert.equal(p.details.action, e.action);
  assert.equal(p.details.creationGrantId, e.creationGrant.payload.grantId);
  assert.equal(p.details.creationEpoch, e.creationGrant.payload.creationEpoch);
  assert.equal(p.details.creationPolicyDigest, e.creationGrant.payload.policyDigest);
  assert.deepEqual(p.details.policyReference, {
    fromUnitId: e.senderUnitId,
    toUnitId: e.recipientUnitId,
    missionId: e.missionId,
  });
  assert.equal(p.details.policyDigest, f.authority.policyDigest());
  assert.equal(p.details.revocationVersion, a.revocation_version);
  assert.equal(p.details.authorityEpoch, a.epoch);
  assert.equal(p.details.deviceEvidence, 'software-proof-of-possession');
  assert.match(p.details.proofEvidence.challengeDigest, /^[a-f0-9]{64}$/);
  assert.ok(verify(p, receipt.signature, f.provisioned.serverPublicKey));
  const persisted = JSON.parse(
    f.authority.get('SELECT record FROM evidence WHERE sequence=?', p.sequence).record,
  );
  assert.deepEqual(persisted, receipt);
}

test('corrupt persisted sender signature is held before prepare and claim with durable scoped evidence', async (t) => {
  const f = await submitted(t);
  f.authority.run('UPDATE objects SET signature=? WHERE id=?', 'A'.repeat(86), f.id);
  const prepared = await f.clients.alice.prepare(f.id);
  assert.equal(prepared.status, 200);
  assert.equal(prepared.body.object.reason, 'OBJECT_SIGNATURE_INVALID');
  noDisclosure(prepared);
  fullEvidence(f, prepared.body.receipt, 'HELD');
  const claimed = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(claimed.status, 409);
  assert.equal(claimed.body.code, 'OBJECT_SIGNATURE_INVALID');
  noDisclosure(claimed);
  fullEvidence(f, claimed.body.receipt, 'HELD');
  assert.notEqual(
    prepared.body.receipt.payload.decisionId,
    claimed.body.receipt.payload.decisionId,
  );
  noIssuance(f);
});

test('claim revalidates integrity after a previously valid READY decision', async (t) => {
  const f = await submitted(t);
  const prepared = await f.clients.alice.prepare(f.id);
  assert.equal(prepared.body.object.state, 'READY');
  f.authority.run('UPDATE objects SET signature=? WHERE id=?', 'not-a-signature', f.id);
  const claimed = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(claimed.status, 409);
  assert.equal(claimed.body.code, 'OBJECT_SIGNATURE_INVALID');
  noDisclosure(claimed);
  noIssuance(f);
});

test('signed envelope substitutions cannot bypass persisted identity, destination, device or digest bindings', async (t) => {
  const f = await submitted(t);
  for (const [field, replacement] of [
    ['objectId', randomUUID()],
    ['senderUserId', f.profiles.admin.userId],
    ['senderDeviceId', f.profiles.admin.deviceId],
    ['recipientUserId', f.profiles.eve.userId],
    ['recipientDeviceId', f.profiles.eve.deviceId],
    ['ciphertextHash', '0'.repeat(64)],
  ]) {
    await t.test(field, async () => {
      const envelope = { ...f.object.envelope, [field]: replacement };
      f.authority.run(
        'UPDATE objects SET envelope=?,signature=? WHERE id=?',
        canonical(envelope),
        sign(envelope, f.profiles.alice.keys.signing.privateKey),
        f.id,
      );
      const prepared = await f.clients.alice.prepare(f.id);
      assert.equal(prepared.body.object.reason, 'OBJECT_BINDING_MISMATCH');
      const claimed = await f.clients.bob.claim(f.id, f.epoch);
      assert.equal(claimed.status, 409);
      assert.equal(claimed.body.code, 'OBJECT_BINDING_MISMATCH');
      noDisclosure(claimed);
      noIssuance(f);
    });
  }
});

test('noncanonical persisted envelope JSON is held despite its valid sender signature', async (t) => {
  const f = await submitted(t);
  const canonicalEnvelope = canonical(f.object.envelope);
  for (const envelope of [
    JSON.stringify(JSON.parse(canonicalEnvelope), null, 2),
    JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(canonicalEnvelope)).reverse())),
  ]) {
    assert.notEqual(envelope, canonicalEnvelope);
    assert.ok(
      verify(JSON.parse(envelope), f.object.signature, f.profiles.alice.keys.signing.publicKey),
    );
    f.authority.run('UPDATE objects SET envelope=? WHERE id=?', envelope, f.id);
    const prepared = await f.clients.alice.prepare(f.id);
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.object.reason, 'OBJECT_ENVELOPE_NONCANONICAL');
    noDisclosure(prepared);
    const claimed = await f.clients.bob.claim(f.id, f.epoch);
    assert.equal(claimed.status, 409);
    assert.equal(claimed.body.code, 'OBJECT_ENVELOPE_NONCANONICAL');
    noDisclosure(claimed);
    assert.equal(claimed.body.receipt.payload.details.envelopeDigest, hash(envelope));
    noIssuance(f);
  }
});

test('unreadable and schema-corrupt persisted envelopes fail closed with signed evidence', async (t) => {
  const f = await submitted(t);
  for (const envelope of ['{', 'null', '[]', '{}']) {
    f.authority.run('UPDATE objects SET envelope=? WHERE id=?', envelope, f.id);
    const prepared = await f.clients.alice.prepare(f.id);
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.object.reason, 'OBJECT_ENVELOPE_SCHEMA');
    const claimed = await f.clients.bob.claim(f.id, f.epoch);
    assert.equal(claimed.status, 409);
    assert.equal(claimed.body.code, 'OBJECT_ENVELOPE_SCHEMA');
    noDisclosure(claimed);
    const receipt = claimed.body.receipt;
    assert.equal(receipt.payload.details.envelopeDigest, hash(envelope));
    assert.equal(receipt.payload.details.destinationUnitId, null);
    assert.equal(receipt.payload.releaseState, 'HELD');
    assert.ok(verify(receipt.payload, receipt.signature, f.provisioned.serverPublicKey));
    noIssuance(f);
  }
});

test('corrupt envelope evidence fields cannot prevent durable signed HOLD decisions', async (t) => {
  const f = await submitted(t);
  const cases = [
    ['senderUnitId', ['policyReference.fromUnitId']],
    ['recipientUnitId', ['destinationUnitId', 'policyReference.toUnitId']],
    ['missionId', ['missionId', 'policyReference.missionId']],
    ['action', ['action']],
    ['creationGrant.payload.grantId', ['creationGrantId']],
    ['creationGrant.payload.creationEpoch', ['creationEpoch']],
    ['creationGrant.payload.policyDigest', ['creationPolicyDigest']],
  ];
  for (const [field, evidenceFields] of cases) {
    await t.test(field, async () => {
      for (const value of [
        0.5,
        0,
        -1,
        Number.MAX_SAFE_INTEGER + 1,
        [],
        { corrupt: 0.5 },
        'invalid value',
        null,
      ]) {
        const envelope = structuredClone(f.object.envelope);
        const path = field.split('.');
        const target = path.slice(0, -1).reduce((object, key) => object[key], envelope);
        target[path.at(-1)] = value;
        // Deliberately bypass canonical serialization, as corrupted storage can.
        const raw = JSON.stringify(envelope);
        f.authority.run(
          'UPDATE objects SET envelope=?,state=?,reason=NULL WHERE id=?',
          raw,
          'PENDING',
          f.id,
        );
        const prepared = await f.clients.alice.prepare(f.id);
        assert.equal(prepared.status, 200, JSON.stringify(prepared));
        const claimed = await f.clients.bob.claim(f.id, f.epoch);
        assert.equal(claimed.status, 409, JSON.stringify(claimed));
        for (const result of [prepared, claimed]) {
          noDisclosure(result);
          const receipt = result.body.receipt;
          assert.equal(receipt.payload.decision, 'HELD');
          assert.equal(receipt.payload.releaseState, 'HELD');
          assert.equal(receipt.payload.details.envelopeDigest, hash(raw));
          for (const evidenceField of evidenceFields) {
            const copied = evidenceField
              .split('.')
              .reduce((object, key) => object[key], receipt.payload.details);
            assert.equal(copied, null, `${field} must not enter ${evidenceField}`);
          }
          assert.ok(verify(receipt.payload, receipt.signature, f.provisioned.serverPublicKey));
          assert.deepEqual(
            JSON.parse(
              f.authority.get(
                'SELECT record FROM evidence WHERE sequence=?',
                receipt.payload.sequence,
              ).record,
            ),
            receipt,
          );
        }
        assert.equal(f.authority.get('SELECT state FROM objects WHERE id=?', f.id).state, 'HELD');
        noIssuance(f);
      }
    });
  }
});

test('valid signatures do not authorize unsupported actions, invalid crypto material or malformed time bounds', async (t) => {
  const f = await submitted(t);
  const replacements = [
    [
      'unsupported action',
      (e) => {
        e.action = 'admin';
      },
    ],
    [
      'unsupported crypto suite',
      (e) => {
        e.cryptoSuite = 'unknown';
      },
    ],
    [
      'invalid time bounds',
      (e) => {
        e.expiresAt = e.createdAt;
      },
    ],
    [
      'malformed nonce',
      (e) => {
        e.nonce = '!';
      },
    ],
    [
      'short nonce',
      (e) => {
        e.nonce = 'AQ';
      },
    ],
    [
      'missing wrapped key',
      (e) => {
        e.wrappedKey = null;
      },
    ],
    [
      'short wrapped ciphertext',
      (e) => {
        e.wrappedKey.ciphertext = 'AQ';
      },
    ],
    [
      'invalid ephemeral key',
      (e) => {
        e.wrappedKey.ephemeralPublicKey = {};
      },
    ],
  ];
  for (const [label, mutate] of replacements) {
    await t.test(label, async () => {
      const envelope = structuredClone(f.object.envelope);
      mutate(envelope);
      f.authority.run(
        'UPDATE objects SET envelope=?,signature=? WHERE id=?',
        canonical(envelope),
        sign(envelope, f.profiles.alice.keys.signing.privateKey),
        f.id,
      );
      const claimed = await f.clients.bob.claim(f.id, f.epoch);
      assert.equal(claimed.status, 409);
      assert.equal(claimed.body.code, 'OBJECT_ENVELOPE_INVALID');
      noDisclosure(claimed);
      noIssuance(f);
    });
  }
});

test('policy and epoch holds carry the complete decision schema with the current revocation version', async (t) => {
  const f = await submitted(t);
  await f.clients.admin.authenticate();
  const policy = {
    fromUnit: f.object.envelope.senderUnitId,
    toUnit: f.object.envelope.recipientUnitId,
    missionId: f.object.envelope.missionId,
  };
  assert.equal(
    (await f.clients.admin.admin('PUT', '/api/admin/policies', { ...policy, allow: false })).status,
    200,
  );
  const prepared = await f.clients.alice.prepare(f.id);
  assert.equal(prepared.body.object.reason, 'POLICY_DENIED');
  fullEvidence(f, prepared.body.receipt, 'HELD');
  const denied = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(denied.status, 409);
  assert.equal(denied.body.code, 'POLICY_DENIED');
  fullEvidence(f, denied.body.receipt, 'HELD');
  assert.equal(
    (await f.clients.admin.admin('PUT', '/api/admin/policies', { ...policy, allow: true })).status,
    200,
  );
  const stale = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(stale.body.code, 'EPOCH_MISMATCH');
  fullEvidence(f, stale.body.receipt, 'HELD');
  assert.equal(stale.body.receipt.payload.details.expectedEpoch, f.epoch);
  assert.ok(stale.body.receipt.payload.details.authorityEpoch > f.epoch);
  noIssuance(f);
});

test('READY, RELEASED and release retry decisions bind the same complete evidence schema', async (t) => {
  const f = await submitted(t);
  const prepared = await f.clients.alice.prepare(f.id);
  fullEvidence(f, prepared.body.receipt, 'READY');
  const claimed = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(claimed.status, 200);
  fullEvidence(f, claimed.body.receipt, 'RELEASED');
  const retry = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(retry.status, 200);
  assert.deepEqual(retry.body.receipt, claimed.body.receipt);
  const retryEvidence = f.authority.findReceipt(f.id, 'RELEASE_RETRY');
  fullEvidence(f, retryEvidence, 'RELEASED');
  assert.equal(retryEvidence.payload.details.issuanceEventId, claimed.body.receipt.payload.eventId);
  assert.equal(f.authority.get('SELECT COUNT(*) AS n FROM issuances').n, 1);
});

test('a corrupt relay adapter cannot return ciphertext or wrapped keys through the control API', async (t) => {
  const f = await submitted(t);
  const getBlob = f.authority.relay.getBlob;
  f.authority.relay.getBlob = async () => Buffer.from('corrupt ciphertext');
  const corrupt = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(corrupt.status, 502);
  assert.equal(corrupt.body.code, 'CIPHERTEXT_DIGEST');
  assert.equal(corrupt.body.envelope, undefined);
  assert.equal(corrupt.body.ciphertext, undefined);
  // Issuance is durable before transport. An intact retry must reuse its receipt.
  const issuance = f.authority.get('SELECT * FROM issuances WHERE object_id=?', f.id);
  f.authority.relay.getBlob = getBlob;
  const retry = await f.clients.bob.claim(f.id, f.epoch);
  assert.equal(retry.status, 200);
  assert.equal(retry.body.receipt.payload.eventId, JSON.parse(issuance.receipt).payload.eventId);
});
