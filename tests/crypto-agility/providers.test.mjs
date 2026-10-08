import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createPublicKey, verify as nativeVerify } from 'node:crypto';
import {
  CryptoEngine,
  providerKeyId,
  validateProviderPublicKey,
  verifyCryptoEvidence,
} from '../../packages/crypto-provider/engine.mjs';
import {
  createClassicalProvider,
  CLASSICAL_PROVIDER_ID as providerId,
  CLASSICAL_SUITE_ID as suiteId,
} from '../../packages/crypto-provider/classical.mjs';
import { createLegacyAdapter } from '../../packages/crypto-provider/legacy.mjs';
import { ProviderRegistry } from '../../packages/crypto-provider/registry.mjs';
import {
  bytes,
  decode,
  deriveWrapKey,
  members,
} from '../../packages/crypto-provider/primitives.mjs';
import { canonical } from '../../packages/protocol/canonical.mjs';
import {
  b64,
  unb64,
  generateDeviceKeys,
  sign,
  verify,
  signPacket,
  keyId,
  createTextPayload,
  encryptObject,
  decryptObject,
} from '../../packages/crypto/crypto.mjs';

const selection = { providerId, suiteId };
const data = new TextEncoder().encode('Synthetic provider interoperability test');
const context = { objectId: 'synthetic-object', policyEpoch: 7, recipientDevice: 'unit-b-device' };
const policy = (overrides = {}) => ({
  schemaVersion: 1,
  revision: 1,
  mode: 'laboratory',
  newSuites: [selection],
  legacySuites: [selection],
  ...overrides,
});
const engine = (options = {}) =>
  new CryptoEngine({ providers: [createClassicalProvider()], policy: policy(), ...options });

test('provider discovery is immutable, versioned, and never exposes private key handles', async () => {
  const e = engine();
  const descriptors = e.discover();
  assert.equal(descriptors[0].apiVersion, 1);
  assert.match(descriptors[0].keyCustody, /not hardware/);
  descriptors[0].suites[0].id = 'tampered';
  assert.equal(e.discover()[0].suites[0].id, suiteId);
  const key = await e.generateKey({
    ...selection,
    purpose: 'sign',
    accidentalSecret: 'must-not-be-logged',
  });
  assert.equal(key.keyId, providerKeyId(key));
  assert.deepEqual(Object.keys(key).sort(), [
    'keyId',
    'providerId',
    'publicKey',
    'purpose',
    'suiteId',
  ]);
  assert.equal(e.keyInventory()[0].status, 'active');
  assert.deepEqual(e.health(), [
    { providerId, status: 'registered', failures: 0, lastFailure: null },
  ]);
  assert.ok(!JSON.stringify(e.evidence()).includes('must-not-be-logged'));
  assert.equal(verifyCryptoEvidence(e.evidence(), e.evidenceHead()), true);
});

test('classical signatures interoperate with existing browser crypto and node native crypto', async () => {
  const e = engine();
  const device = await generateDeviceKeys();
  const key = await e.importKey({ ...selection, purpose: 'sign', key: device.signing.privateKey });
  const value = { v: 1, nested: { synthetic: true } };
  const encoded = new TextEncoder().encode(canonical(value));
  const signature = await e.sign({ keyId: key.keyId, data: encoded });
  assert.equal(await verify(device.signing.publicKey, value, b64(signature)), true);
  assert.equal(
    nativeVerify(
      'sha256',
      encoded,
      {
        key: createPublicKey({ key: device.signing.publicKey, format: 'jwk' }),
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    ),
    true,
  );
  assert.equal(
    await e.verify({
      key,
      data: encoded,
      signature: unb64(await sign(device.signing.privateKey, value)),
    }),
    true,
  );
  assert.equal(await e.verify({ key, data, signature }), false);
  await assert.rejects(e.sign({ keyId: key.keyId, data: 'not bytes' }), /Invalid bytes/);
  await assert.rejects(
    e.importKey({ ...selection, purpose: 'sign', key: device.signing.privateKey }),
    /reuse/,
  );
  assert.ok(!JSON.stringify(e.evidence()).includes(device.signing.privateKey.d));
});

test('generated classical handles are software nonextractable and preserve purpose separation', async () => {
  const provider = createClassicalProvider();
  const pair = await provider.generateKey({ suiteId, purpose: 'sign' });
  assert.equal(pair.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('jwk', pair.privateKey));
  await assert.rejects(
    provider.decapsulate({ suiteId, privateKey: pair.privateKey, encapsulation: {} }),
    /private handle/,
  );
  await assert.rejects(
    provider.generateKey({ suiteId: 'unknown', purpose: 'sign' }),
    /Unsupported/,
  );
  await assert.rejects(provider.generateKey({ suiteId, purpose: 'encrypt' }), /purpose/);
  const e = engine();
  const signing = await e.generateKey({ ...selection, purpose: 'sign' });
  await assert.rejects(e.encapsulate({ key: signing }), /purpose/);
  await assert.rejects(e.decapsulate({ keyId: signing.keyId, encapsulation: {} }), /purpose/);
});

test('ECDH encapsulation works between independent endpoint engines', async () => {
  const sender = engine(),
    recipient = engine();
  const key = await recipient.generateKey({ ...selection, purpose: 'encapsulate' });
  const result = await sender.encapsulate({ key });
  const recovered = await recipient.decapsulate({
    keyId: key.keyId,
    encapsulation: result.encapsulation,
  });
  assert.equal(result.sharedSecret.length, 32);
  assert.deepEqual(recovered, result.sharedSecret);
  const other = await recipient.generateKey({ ...selection, purpose: 'encapsulate' });
  assert.notDeepEqual(
    await recipient.decapsulate({ keyId: other.keyId, encapsulation: result.encapsulation }),
    recovered,
  );
  result.sharedSecret.fill(0);
  recovered.fill(0);
});

test('AES-256-GCM interop and published empty-message vector retain exact bytes', async () => {
  const e = engine();
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const aad = new TextEncoder().encode(canonical(context));
  const packet = await e.encrypt({ ...selection, key: raw, plaintext: data, aad });
  assert.deepEqual(await e.decrypt({ ...selection, key: raw, packet, aad }), data);
  const combined = Buffer.from(packet.ciphertext, 'base64url');
  const decipher = createDecipheriv('aes-256-gcm', raw, Buffer.from(packet.nonce, 'base64url'));
  decipher.setAAD(aad);
  decipher.setAuthTag(combined.subarray(-16));
  assert.deepEqual(
    Buffer.concat([decipher.update(combined.subarray(0, -16)), decipher.final()]),
    Buffer.from(data),
  );
  // NIST GCMVS AES-256, zero key/IV, zero-length plaintext and AAD.
  const vector = {
    nonce: Buffer.alloc(12).toString('base64url'),
    ciphertext: Buffer.from('530f8afbc74536b9a963b4f1c4cb738b', 'hex').toString('base64url'),
  };
  assert.equal(
    (
      await e.decrypt({
        ...selection,
        key: new Uint8Array(32),
        packet: vector,
        aad: new Uint8Array(),
      })
    ).length,
    0,
  );
  await assert.rejects(e.decrypt({ ...selection, key: raw, packet, aad: data }));
  await assert.rejects(
    e.decrypt({ ...selection, key: raw, packet: { ...packet, ciphertext: 'AA' }, aad }),
    /Truncated/,
  );
  await assert.rejects(
    e.encrypt({ ...selection, key: new Uint8Array(16), plaintext: data, aad }),
    /Invalid bytes/,
  );
});

test('wrapping authenticates all metadata, scope, selected suite and recipient identity', async () => {
  const sender = engine(),
    recipient = engine();
  const key = await recipient.generateKey({ ...selection, purpose: 'encapsulate' });
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const packet = await sender.wrapKey({ key, contentKey, context });
  assert.deepEqual(await recipient.unwrapKey({ keyId: key.keyId, packet, context }), contentKey);
  for (const [field, value] of [
    // Wrap v1 (context inlined in HKDF info) is retired; unknown versions never fall back.
    ['schemaVersion', 1],
    ['schemaVersion', 3],
    ['providerId', 'other-provider'],
    ['suiteId', 'unknown-suite'],
    ['recipientKeyId', '0'.repeat(64)],
    ['salt', Buffer.alloc(32).toString('base64url')],
    ['nonce', Buffer.alloc(12).toString('base64url')],
    ['ciphertext', Buffer.alloc(48).toString('base64url')],
  ]) {
    await assert.rejects(
      recipient.unwrapKey({ keyId: key.keyId, packet: { ...packet, [field]: value }, context }),
    );
  }
  const changed = structuredClone(packet);
  changed.encapsulation.ephemeralPublicKey.x = Buffer.alloc(32).toString('base64url');
  await assert.rejects(recipient.unwrapKey({ keyId: key.keyId, packet: changed, context }));
  await assert.rejects(
    recipient.unwrapKey({ keyId: key.keyId, packet, context: { ...context, policyEpoch: 8 } }),
  );
  await assert.rejects(
    recipient.unwrapKey({ keyId: key.keyId, packet: { ...packet, extra: true }, context }),
    /members/,
  );
  await assert.rejects(sender.wrapKey({ key, contentKey: new Uint8Array(31), context }));
});

test('retirement requires explicit legacy policy; revocation denies even historical use', async () => {
  const e = engine();
  const key = await e.generateKey({ ...selection, purpose: 'encapsulate' });
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const packet = await e.wrapKey({ key, contentKey: raw, context });
  e.retireKey({ keyId: key.keyId, reason: 'planned replacement' });
  await assert.rejects(e.unwrapKey({ keyId: key.keyId, packet, context }), /retired/);
  assert.deepEqual(await e.unwrapKey({ keyId: key.keyId, packet, context, legacy: true }), raw);
  await assert.rejects(e.wrapKey({ key, contentKey: raw, context }), /retired/);
  e.revokeKey({ keyId: key.keyId, reason: 'suspected compromise' });
  await assert.rejects(e.unwrapKey({ keyId: key.keyId, packet, context, legacy: true }), /revoked/);
  assert.throws(() => e.retireKey({ keyId: key.keyId, reason: 'undo revocation' }), /reversed/);
  assert.equal(e.keyInventory()[0].status, 'revoked');
});

test('rotation preserves explicit historical signature verification without retired signing', async () => {
  const e = engine();
  const old = await e.generateKey({ ...selection, purpose: 'sign' });
  const signature = await e.sign({ keyId: old.keyId, data });
  const next = await e.rotateKey({ keyId: old.keyId, reason: 'scheduled rotation' });
  assert.notEqual(next.keyId, old.keyId);
  await assert.rejects(e.sign({ keyId: old.keyId, data }), /retired/);
  await assert.rejects(e.verify({ key: old, data, signature }), /retired/);
  assert.equal(await e.verify({ key: old, data, signature, legacy: true }), true);
  assert.equal(
    await e.verify({ key: next, data, signature: await e.sign({ keyId: next.keyId, data }) }),
    true,
  );
  assert.equal(e.evidence().at(-1).data.historicalCiphertextReprotected, false);
});

test('deprecated suites cannot generate/rotate/sign; legacy access is deliberate and auditable', async () => {
  const e = engine();
  const key = await e.generateKey({ ...selection, purpose: 'encapsulate' });
  const capsule = await e.encapsulate({ key });
  const previousDigest = e.policy().digest;
  const changed = e.updatePolicy({
    policy: policy({ revision: 2, newSuites: [] }),
    actor: 'lab-admin',
    reason: 'retire classical new use',
  });
  assert.notEqual(changed.digest, previousDigest);
  assert.equal(e.evidence().at(-1).data.previousDigest, previousDigest);
  await assert.rejects(e.generateKey({ ...selection, purpose: 'sign' }), /new-use policy/);
  await assert.rejects(
    e.rotateKey({ keyId: key.keyId, reason: 'cannot reuse deprecated suite' }),
    /new-use policy/,
  );
  await assert.rejects(
    e.decapsulate({ keyId: key.keyId, encapsulation: capsule.encapsulation }),
    /new-use policy/,
  );
  assert.deepEqual(
    await e.decapsulate({ keyId: key.keyId, encapsulation: capsule.encapsulation, legacy: true }),
    capsule.sharedSecret,
  );
  e.updatePolicy({
    policy: policy({ revision: 3, newSuites: [], legacySuites: [] }),
    actor: 'lab-admin',
    reason: 'disallow historical decrypt',
  });
  await assert.rejects(
    e.decapsulate({ keyId: key.keyId, encapsulation: capsule.encapsulation, legacy: true }),
    /legacy policy/,
  );
  assert.throws(
    () =>
      e.updatePolicy({ policy: policy({ revision: 3 }), actor: 'lab-admin', reason: 'rollback' }),
    /revision/,
  );
  assert.equal(verifyCryptoEvidence(e.evidence(), e.evidenceHead()), true);
});

test('provider failures never select a second provider or a weaker suite', async () => {
  const failing = createClassicalProvider();
  failing.sign = async () => {
    throw new Error('private provider detail must not escape');
  };
  const fallback = createClassicalProvider();
  fallback.descriptor.id = 'second-provider';
  let fallbackCalls = 0;
  fallback.sign = async () => {
    fallbackCalls++;
    return new Uint8Array(64);
  };
  const e = engine({
    providers: [failing, fallback],
    policy: policy({ newSuites: [selection, { providerId: 'second-provider', suiteId }] }),
  });
  const key = await e.generateKey({ ...selection, purpose: 'sign' });
  await assert.rejects(
    e.sign({ keyId: key.keyId, data }),
    /Provider operation failed: sign; fallback is forbidden/,
  );
  assert.equal(fallbackCalls, 0);
  assert.equal(e.health()[0].status, 'degraded');
  assert.equal(e.health()[0].failures, 1);
  await assert.rejects(
    e.generateKey({ providerId, suiteId: 'weaker-suite', purpose: 'sign' }),
    /Unsupported/,
  );
});

test('local key revocation committed during provider signing denies the pending result', async () => {
  const provider = createClassicalProvider();
  const original = provider.sign;
  let release, started;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const entry = new Promise((resolve) => {
    started = resolve;
  });
  provider.sign = async (args) => {
    started();
    await gate;
    return original(args);
  };
  const e = engine({ providers: [provider] });
  const key = await e.generateKey({ ...selection, purpose: 'sign' });
  const pending = e.sign({ keyId: key.keyId, data });
  await entry;
  e.revokeKey({ keyId: key.keyId, reason: 'revoked before asynchronous completion' });
  release();
  await assert.rejects(pending, /revoked/);
});

test('suite policy committed during generation denies publishing the new key', async () => {
  const provider = createClassicalProvider();
  const original = provider.generateKey;
  let release, started;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const entry = new Promise((resolve) => {
    started = resolve;
  });
  provider.generateKey = async (args) => {
    started();
    await gate;
    return original(args);
  };
  const e = engine({ providers: [provider] });
  const pending = e.generateKey({ ...selection, purpose: 'sign' });
  await entry;
  e.updatePolicy({
    policy: policy({ revision: 2, newSuites: [] }),
    actor: 'lab-admin',
    reason: 'disable before key creation completed',
  });
  release();
  await assert.rejects(pending, /new-use policy/);
  assert.deepEqual(e.keyInventory(), []);
});

test('unknown, malformed, substituted and private public-key descriptors fail closed', async () => {
  const e = engine();
  const key = await e.generateKey({ ...selection, purpose: 'sign' });
  assert.deepEqual(validateProviderPublicKey(key), key);
  assert.throws(() => validateProviderPublicKey({ ...key, keyId: '0'.repeat(64) }), /identity/);
  assert.throws(() => validateProviderPublicKey({ ...key, extra: true }), /members/);
  await assert.rejects(
    e.verify({ key: { ...key, providerId: 'substituted' }, data, signature: new Uint8Array(64) }),
    /identity/,
  );
  const invalid = {
    ...key,
    publicKey: { ...key.publicKey, d: Buffer.alloc(32).toString('base64url') },
  };
  invalid.keyId = providerKeyId(invalid);
  await assert.rejects(
    e.verify({ key: invalid, data, signature: new Uint8Array(64) }),
    /Provider operation failed/,
  );
  await assert.rejects(e.sign({ keyId: 'unknown', data }), /Unknown/);
  await assert.rejects(e.generateKey({ ...selection, purpose: 'unknown' }), /purpose/);
});

test('registry and policy reject ambiguous declarations and laboratory production selection', () => {
  assert.throws(() => new ProviderRegistry([]), /provider/);
  assert.throws(
    () => new ProviderRegistry([createClassicalProvider(), createClassicalProvider()]),
    /Duplicate/,
  );
  const missing = createClassicalProvider();
  delete missing.sign;
  assert.throws(() => new ProviderRegistry([missing]), /interface/);
  const invalid = createClassicalProvider();
  invalid.descriptor.suites[0].contentEncryption = 'AES-CBC';
  assert.throws(() => new ProviderRegistry([invalid]), /suite/);
  const lab = createClassicalProvider();
  lab.descriptor.suites[0].laboratory = true;
  assert.throws(
    () => engine({ providers: [lab], policy: policy({ mode: 'production' }) }),
    /Laboratory/,
  );
  for (const override of [
    { revision: 0 },
    { schemaVersion: 2 },
    { mode: 'auto' },
    { newSuites: null },
    { newSuites: [selection, selection] },
    { newSuites: [{ providerId, suiteId, fallback: true }] },
  ])
    assert.throws(() => engine({ policy: policy(override) }));
  const e = engine();
  assert.throws(() => e.assertAllowed({ ...selection, legacy: 'yes' }), /explicit/);
  assert.throws(
    () => e.updatePolicy({ policy: policy({ revision: 2 }), actor: 'lab-admin', reason: '' }),
    /reason/,
  );
  assert.throws(() => e.revokeKey({ keyId: 'unknown', reason: 'test' }), /Unknown/);
  assert.throws(() => e.retireKey({ keyId: 'unknown', reason: '' }), /reason/);
});

test('configuration evidence detects modification, truncation, rollback and reordering against retained head', async () => {
  const e = engine();
  const key = await e.generateKey({ ...selection, purpose: 'sign' });
  e.revokeKey({ keyId: key.keyId, reason: 'synthetic retirement experiment' });
  const events = e.evidence(),
    head = e.evidenceHead();
  assert.equal(verifyCryptoEvidence(events, head), true);
  assert.equal(verifyCryptoEvidence(events), false);
  assert.equal(verifyCryptoEvidence(events.slice(0, -1), head), false);
  assert.equal(verifyCryptoEvidence([...events].reverse(), head), false);
  events[0].data.policy.revision = 999;
  assert.equal(verifyCryptoEvidence(events, head), false);
  assert.equal(verifyCryptoEvidence([{ malformed: true }], head), false);
  assert.equal(verifyCryptoEvidence(e.evidence(), head), true);
});

test('legacy adapter preserves schema-v1 objects and requires explicit historical policy', async () => {
  const e = engine();
  const adapter = createLegacyAdapter(e);
  const sender = await generateDeviceKeys(),
    recipient = await generateDeviceKeys(),
    authority = await generateDeviceKeys();
  const grant = await signPacket(authority.signing.privateKey, {
    userId: 'sender',
    deviceId: 'sender-device',
    unitId: 'unit-a',
    missionIds: ['exercise'],
    epoch: 1,
    issuedAt: 1,
    expiresAt: 10000,
    maxSensitivity: 'DEMO',
  });
  const legacyContext = {
    schemaVersion: 1,
    objectId: crypto.randomUUID(),
    senderUserId: 'sender',
    senderDeviceId: 'sender-device',
    senderUnitId: 'unit-a',
    recipientUserId: 'recipient',
    recipientDeviceId: 'recipient-device',
    recipientUnitId: 'unit-b',
    recipientKeyId: await keyId(recipient.encryption.publicKey),
    missionId: 'exercise',
    classification: 'DEMO',
    action: 'deliver',
    createdAt: 100,
    expiresAt: 1000,
    creationGrant: grant,
    cryptoSuite: suiteId,
    keyVersion: 1,
  };
  const payload = createTextPayload('Historical synthetic content');
  const existing = await encryptObject(
    legacyContext,
    payload,
    recipient.encryption.publicKey,
    sender.signing.privateKey,
  );
  await assert.rejects(
    adapter.decryptObject(existing, recipient.encryption.privateKey, sender.signing.publicKey),
    /explicit legacy/,
  );
  assert.deepEqual(
    await adapter.decryptObject(
      existing,
      recipient.encryption.privateKey,
      sender.signing.publicKey,
      { legacy: true },
    ),
    payload,
  );
  const fresh = await adapter.encryptObject(
    legacyContext,
    payload,
    recipient.encryption.publicKey,
    sender.signing.privateKey,
  );
  assert.deepEqual(
    await decryptObject(fresh, recipient.encryption.privateKey, sender.signing.publicKey),
    payload,
  );
  e.updatePolicy({
    policy: policy({ revision: 2, newSuites: [], legacySuites: [] }),
    actor: 'lab-admin',
    reason: 'disable compatibility path',
  });
  await assert.rejects(
    adapter.decryptObject(existing, recipient.encryption.privateKey, sender.signing.publicKey, {
      legacy: true,
    }),
    /legacy policy/,
  );
  await assert.rejects(
    adapter.encryptObject(
      legacyContext,
      payload,
      recipient.encryption.publicKey,
      sender.signing.privateKey,
    ),
    /new-use policy/,
  );
});

test('byte and canonical boundaries reject malformed encodings and unsupported values', async () => {
  assert.throws(() => bytes('secret'), /Invalid/);
  assert.throws(() => decode('*'), /Invalid/);
  assert.throws(() => decode('AB'), /Invalid/);
  assert.throws(() => decode('AA', 2), /Invalid/);
  assert.throws(() => members([], []), /members/);
  assert.throws(() => members(null, []), /members/);
  await assert.rejects(
    deriveWrapKey(new Uint8Array(31), new Uint8Array(32), context),
    /KEM shared secret/,
  );
  await assert.rejects(deriveWrapKey(new Uint8Array(32), new Uint8Array(31), context));
});

test('concurrent duplicate imports cannot overwrite a lifecycle record', async () => {
  const e = engine();
  const device = await generateDeviceKeys();
  const input = { ...selection, purpose: 'sign', key: device.signing.privateKey };
  const results = await Promise.allSettled([e.importKey(input), e.importKey(input)]);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(e.keyInventory().length, 1);
  assert.equal(e.evidence().filter((event) => event.type === 'key-imported').length, 1);
});
