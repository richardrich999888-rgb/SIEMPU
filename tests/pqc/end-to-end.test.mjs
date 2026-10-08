// Laboratory schema-v3 (ML-KEM-768 + ML-DSA-65 + AES-256-GCM) through the real authority:
// device key registration, admin activation, suite policy, submission, transactional release,
// signed provenance, independent verification, and the fail-closed cases around them.
// Synthetic data only. This is engineering evidence, not cryptographic approval.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { coreFixture, openAuthority } from '../helpers/fixture.mjs';
import { ApiClient, coreTransport, createObject, sign, verify } from '../helpers/client.mjs';
import { createNativePqcProvider } from '../../packages/pqc-lab/native-provider.mjs';
import { createProviderObject, openProviderObject } from '../../packages/pqc-lab/envelope.mjs';
import { createLabEndpoint, labContext } from '../../packages/pqc-lab/endpoint.mjs';
import {
  NATIVE_PQC_PROVIDER_ID,
  NATIVE_MLKEM768_SUITE,
  NATIVE_MLKEM1024_SUITE,
} from '../../packages/crypto-provider/pqc-identifiers.mjs';
import {
  CLASSICAL_PROVIDER_ID,
  CLASSICAL_SUITE_ID,
} from '../../packages/crypto-provider/classical.mjs';
import { createFilePayload, unpackPayload } from '../../packages/crypto/crypto.mjs';
import { verifyReleaseReceipt } from '../../apps/verifier/verify.mjs';

const CLASSICAL = { providerId: CLASSICAL_PROVIDER_ID, suiteId: CLASSICAL_SUITE_ID };
const MLKEM768 = { providerId: NATIVE_PQC_PROVIDER_ID, suiteId: NATIVE_MLKEM768_SUITE };
const SYNTHETIC_BYTES = Buffer.from(Array.from({ length: 4099 }, (_, i) => (i * 31) % 256));

async function registerKey(client, key) {
  return client.request('POST', '/api/crypto/keys', {
    key,
    proof: await client.proof('crypto-key:register', { key }),
  });
}

async function setPolicy(admin, { newSuites, legacySuites }) {
  const current = (await admin.ok('GET', '/api/admin/crypto')).policy;
  const policy = {
    schemaVersion: 1,
    revision: current.revision + 1,
    mode: 'laboratory',
    newSuites,
    legacySuites,
  };
  const result = await admin.admin('PUT', '/api/admin/crypto/policy', { policy });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  return policy;
}

/** Lab-enabled authority with Alice (sender) and Bob (recipient) PQC keys registered and active. */
async function labFixture(t) {
  const f = await coreFixture(t, {}, { allowPqcLab: true });
  for (const name of ['alice', 'bob', 'admin', 'eve']) await f.clients[name].authenticate();
  const alice = await createLabEndpoint({ provider: createNativePqcProvider(), ...MLKEM768 });
  const bob = await createLabEndpoint({ provider: createNativePqcProvider(), ...MLKEM768 });
  for (const [client, key] of [
    [f.clients.alice, alice.signingKey],
    [f.clients.bob, bob.encapsulationKey],
  ]) {
    const registered = await registerKey(client, key);
    assert.equal(registered.status, 200, JSON.stringify(registered.body));
    assert.equal(registered.body.status, 'pending');
    const activated = await f.clients.admin.admin('PATCH', `/api/admin/crypto/keys/${key.keyId}`, {
      status: 'active',
    });
    assert.equal(activated.status, 200, JSON.stringify(activated.body));
  }
  const policy = await setPolicy(f.clients.admin, {
    newSuites: [CLASSICAL, MLKEM768],
    legacySuites: [CLASSICAL, MLKEM768],
  });
  return { ...f, alice, bob, policy };
}

async function v3Object(f, overrides = {}) {
  const context = labContext({
    sender: f.profiles.alice,
    recipient: f.profiles.bob,
    creationGrant: await f.clients.alice.grant(),
    selection: MLKEM768,
    senderCryptoKeyId: f.alice.signingKey.keyId,
    recipientKeyId: f.bob.encapsulationKey.keyId,
    suitePolicyRevision: f.policy.revision,
    objectId: randomUUID(),
    now: Date.now(),
    ...overrides,
  });
  return createProviderObject({
    engine: f.alice.engine,
    context,
    payload: createFilePayload('synthetic.bin', 'application/octet-stream', SYNTHETIC_BYTES),
    recipientKey: f.bob.encapsulationKey,
    senderKey: f.alice.signingKey,
    identitySigningKey: f.profiles.alice.keys.signing.privateKey,
  });
}

async function submitAndPrepare(f, object) {
  await f.clients.alice.submit(object);
  return f.clients.alice.prepare(object.envelope.objectId);
}

function assertSignedDenial(f, result, reason) {
  assert.equal(result.status, 409, JSON.stringify(result.body));
  assert.equal(result.body.code, reason);
  assert.equal(result.body.receipt.payload.eventType, 'RELEASE_DENIED');
  assert.ok(
    verify(
      result.body.receipt.payload,
      result.body.receipt.signature,
      f.provisioned.serverPublicKey,
    ),
  );
  assert.equal(JSON.stringify(result.body).includes('wrappedKey'), false);
}

test('v3 lab object: endpoint-only keys, transactional release, exact bytes and verified provenance', async (t) => {
  const f = await labFixture(t);
  const object = await v3Object(f);
  const prepared = await submitAndPrepare(f, object);
  assert.equal(prepared.body.object.state, 'READY', JSON.stringify(prepared.body));
  // The authority stores only public descriptors and opaque wraps; nothing private.
  const stored = f.authority.get(
    'SELECT envelope FROM objects WHERE id=?',
    object.envelope.objectId,
  );
  for (const forbidden of ['privateKey', '"d":'])
    assert.equal(stored.envelope.includes(forbidden), false);
  const epoch = f.authority.epoch().epoch;
  const claim = await f.clients.bob.claim(object.envelope.objectId, epoch);
  assert.equal(claim.status, 200, JSON.stringify(claim.body));
  assert.equal(claim.body.senderCryptoKey.keyId, f.alice.signingKey.keyId);
  const payload = await openProviderObject({
    engine: f.bob.engine,
    claim: claim.body,
    senderKey: claim.body.senderCryptoKey,
    senderIdentityPublicKey: claim.body.senderSigningPublicKey,
    expected: { suiteId: NATIVE_MLKEM768_SUITE },
  });
  assert.deepEqual(Buffer.from(unpackPayload(payload).bytes), SYNTHETIC_BYTES);
  const crypto = claim.body.receipt.payload.details.crypto;
  assert.deepEqual(
    {
      envelopeVersion: crypto.envelopeVersion,
      providerId: crypto.providerId,
      suiteId: crypto.suiteId,
      senderKeyId: crypto.senderKeyId,
      recipientKeyId: crypto.recipientKeyId,
      creationPolicyRevision: crypto.creationPolicyRevision,
    },
    {
      envelopeVersion: 3,
      providerId: NATIVE_PQC_PROVIDER_ID,
      suiteId: NATIVE_MLKEM768_SUITE,
      senderKeyId: f.alice.signingKey.keyId,
      recipientKeyId: f.bob.encapsulationKey.keyId,
      creationPolicyRevision: f.policy.revision,
    },
  );
  assert.equal(claim.body.receipt.payload.details.objectSchemaVersion, 3);
  // Independent verifier, strict release mode with a durable replay store.
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-v3-verify-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const verified = await verifyReleaseReceipt(claim.body.receipt, f.provisioned.serverPublicKey, {
    objectDigest: claim.body.object.ciphertextHash,
    epoch,
    objectId: object.envelope.objectId,
    replayStore: join(dir, 'replay.sqlite'),
  });
  assert.equal(verified.strictReleaseVerified, true);
  // A release receipt whose provenance is removed or altered is not accepted.
  for (const mutate of [
    (r) => delete r.payload.details.crypto,
    // A suite that does not belong to the named provider.
    (r) => (r.payload.details.crypto.suiteId = 'X-WING-ML-DSA-65-AES-256-GCM-v1'),
    // Provenance on a receipt that claims a classical object.
    (r) => (r.payload.details.objectSchemaVersion = 2),
  ]) {
    const forged = structuredClone(claim.body.receipt);
    mutate(forged);
    forged.signature = sign(forged.payload, f.authority.key);
    await assert.rejects(
      verifyReleaseReceipt(forged, f.provisioned.serverPublicKey, {
        objectDigest: claim.body.object.ciphertextHash,
        epoch,
        objectId: object.envelope.objectId,
        replayStore: join(dir, 'replay-forged.sqlite'),
      }),
    );
  }
});

test('lab gate closed: key registration and v3 submission are refused', async (t) => {
  const f = await coreFixture(t);
  for (const name of ['alice', 'admin']) await f.clients[name].authenticate();
  const alice = await createLabEndpoint({ provider: createNativePqcProvider(), ...MLKEM768 });
  const refused = await registerKey(f.clients.alice, alice.signingKey);
  assert.equal(refused.status, 403);
  assert.equal(refused.body.code, 'PQC_LAB_DISABLED');
  const object = await createProviderObject({
    engine: alice.engine,
    context: labContext({
      sender: f.profiles.alice,
      recipient: f.profiles.bob,
      creationGrant: await f.clients.alice.grant(),
      selection: MLKEM768,
      senderCryptoKeyId: alice.signingKey.keyId,
      recipientKeyId: alice.encapsulationKey.keyId,
      suitePolicyRevision: 1,
      objectId: randomUUID(),
      now: Date.now(),
    }),
    payload: createFilePayload('x.bin', 'application/octet-stream', Buffer.from([1])),
    recipientKey: alice.encapsulationKey,
    senderKey: alice.signingKey,
    identitySigningKey: f.profiles.alice.keys.signing.privateKey,
  });
  const submitted = await f.clients.alice.request('POST', '/api/objects', {
    ...object,
    proof: await f.clients.alice.proof('submit', object),
  });
  assert.equal(submitted.status, 403);
  assert.equal(submitted.body.code, 'PQC_LAB_DISABLED');
  // Lab suites cannot even be written into the policy while the gate is closed.
  const policy = await f.clients.admin.request('GET', '/api/admin/crypto');
  assert.equal(policy.body.allowPqcLab, false);
  const update = await f.clients.admin.admin('PUT', '/api/admin/crypto/policy', {
    policy: {
      ...policy.body.policy,
      revision: policy.body.policy.revision + 1,
      mode: 'laboratory',
      newSuites: [CLASSICAL, MLKEM768],
    },
  });
  assert.equal(update.status, 403);
  assert.equal(update.body.code, 'PQC_LAB_DISABLED');
});

test('a persisted v3 object is held when the authority restarts with the lab gate closed', async (t) => {
  const f = await labFixture(t);
  const object = await v3Object(f);
  await submitAndPrepare(f, object);
  const closed = await openAuthority(f.dir, {}, { allowPqcLab: false });
  t.after(() => closed.close());
  // Same database, so Bob's bound session survives the restart. A fresh login inside the same
  // TOTP window is correctly refused by the durable replay floor.
  const bob = new ApiClient(coreTransport(closed), f.profiles.bob);
  bob.token = f.clients.bob.token;
  const denied = await bob.claim(object.envelope.objectId, closed.epoch().epoch);
  assertSignedDenial({ ...f, authority: closed }, denied, 'PQC_LAB_DISABLED');
  assert.equal(closed.get('SELECT COUNT(*) AS n FROM issuances').n, 0);
});

test('recipient PQC key revocation committed before claim blocks release with signed evidence', async (t) => {
  const f = await labFixture(t);
  const object = await v3Object(f);
  await submitAndPrepare(f, object);
  const revoked = await f.clients.admin.admin(
    'PATCH',
    `/api/admin/crypto/keys/${f.bob.encapsulationKey.keyId}`,
    { status: 'revoked' },
  );
  assert.equal(revoked.status, 200, JSON.stringify(revoked.body));
  const denied = await f.clients.bob.claim(object.envelope.objectId, f.authority.epoch().epoch);
  assertSignedDenial(f, denied, 'CRYPTO_KEY_REVOKED');
  // A stale epoch from before the revocation cannot be used either.
  const stale = await f.clients.bob.claim(object.envelope.objectId, f.authority.epoch().epoch - 1);
  assert.equal(stale.status, 409);
  assert.equal(f.authority.get('SELECT COUNT(*) AS n FROM issuances').n, 0);
  // Revocation is terminal.
  const reactivate = await f.clients.admin.admin(
    'PATCH',
    `/api/admin/crypto/keys/${f.bob.encapsulationKey.keyId}`,
    { status: 'active' },
  );
  assert.equal(reactivate.status, 409);
});

test('suite policy prevents classical downgrade at creation and at release', async (t) => {
  const f = await labFixture(t);
  // Created while classical is allowed for new objects.
  const early = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  await submitAndPrepare(f, early);
  await setPolicy(f.clients.admin, {
    newSuites: [MLKEM768],
    legacySuites: [CLASSICAL, MLKEM768],
  });
  const late = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  const refused = await f.clients.alice.request('POST', '/api/objects', {
    ...late,
    proof: await f.clients.alice.proof('submit', late),
  });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.code, 'CRYPTO_SUITE_FORBIDDEN');
  // Historical classical objects stay releasable only while listed as legacy.
  await setPolicy(f.clients.admin, { newSuites: [MLKEM768], legacySuites: [MLKEM768] });
  const denied = await f.clients.bob.claim(early.envelope.objectId, f.authority.epoch().epoch);
  assertSignedDenial(f, denied, 'CRYPTO_SUITE_FORBIDDEN');
  // A v3 object created under an older policy revision is refused at creation.
  const stale = await v3Object(f, { suitePolicyRevision: f.policy.revision });
  const staleResult = await f.clients.alice.request('POST', '/api/objects', {
    ...stale,
    proof: await f.clients.alice.proof('submit', stale),
  });
  assert.equal(staleResult.status, 403);
  assert.equal(staleResult.body.code, 'CRYPTO_POLICY_REVISION');
});

test('suite substitution and provider-signature forgery are rejected even with a valid identity signature', async (t) => {
  const f = await labFixture(t);
  const object = await v3Object(f);
  const resign = (envelope) => ({
    ...object,
    envelope,
    signature: sign(envelope, f.profiles.alice.keys.signing.privateKey),
  });
  const forgedSignatureBytes = Buffer.from(object.envelope.providerSignature, 'base64url');
  forgedSignatureBytes[10] ^= 1;
  for (const [label, candidate, codes] of [
    [
      'suite substitution',
      resign({ ...object.envelope, cryptoSuite: NATIVE_MLKEM1024_SUITE }),
      [
        'PQC_ENVELOPE_INVALID',
        'CRYPTO_SUITE_FORBIDDEN',
        'CRYPTO_KEY_BINDING',
        'CRYPTO_CONTEXT_INVALID',
      ],
    ],
    [
      'forged provider signature',
      resign({ ...object.envelope, providerSignature: forgedSignatureBytes.toString('base64url') }),
      ['PROVIDER_SIGNATURE_INVALID'],
    ],
    [
      'provider identity substitution',
      resign({ ...object.envelope, providerId: 'noble-xwing-lab' }),
      ['PQC_ENVELOPE_INVALID', 'CRYPTO_SUITE_FORBIDDEN', 'CRYPTO_CONTEXT_INVALID'],
    ],
  ]) {
    const result = await f.clients.alice.request('POST', '/api/objects', {
      ...candidate,
      proof: await f.clients.alice.proof('submit', candidate),
    });
    assert.ok(result.status === 400 || result.status === 403, `${label}: ${result.status}`);
    assert.ok(codes.includes(result.body.code), `${label}: ${result.body.code}`);
  }
  assert.equal(f.authority.get('SELECT COUNT(*) AS n FROM objects').n, 0);
});

test('only the intended recipient endpoint can decrypt, and tampering is detected at the endpoint', async (t) => {
  const f = await labFixture(t);
  const object = await v3Object(f);
  await submitAndPrepare(f, object);
  // Another user never receives the wrapped key from the authority.
  const eve = await f.clients.eve.claim(object.envelope.objectId, f.authority.epoch().epoch);
  assert.equal(eve.status, 404);
  const claim = await f.clients.bob.claim(object.envelope.objectId, f.authority.epoch().epoch);
  assert.equal(claim.status, 200);
  const open = (engine, overrides = {}, expected = {}) =>
    openProviderObject({
      engine,
      claim: { ...claim.body, ...overrides },
      senderKey: claim.body.senderCryptoKey,
      senderIdentityPublicKey: claim.body.senderSigningPublicKey,
      expected,
    });
  // A different endpoint engine (even holding keys for the same suite) has no recipient handle.
  const other = await createLabEndpoint({ provider: createNativePqcProvider(), ...MLKEM768 });
  await assert.rejects(open(other.engine));
  const flipped = Buffer.from(claim.body.ciphertext, 'base64url');
  flipped[0] ^= 1;
  await assert.rejects(open(f.bob.engine, { ciphertext: flipped.toString('base64url') }), /digest/);
  await assert.rejects(open(f.bob.engine, {}, { suiteId: NATIVE_MLKEM1024_SUITE }), /suite/);
  assert.ok(await open(f.bob.engine));
});

test('v3 FLASH objects still require dual-control approval', async (t) => {
  const f = await labFixture(t);
  const object = await v3Object(f, { messagePriority: 'FLASH' });
  await submitAndPrepare(f, object);
  const held = await f.clients.bob.claim(object.envelope.objectId, f.authority.epoch().epoch);
  assertSignedDenial(f, held, 'FLASH_APPROVAL_REQUIRED');
});
