import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as native from 'node:crypto';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { CryptoEngine } from '../crypto-provider/engine.mjs';
import { createXwingLabProvider, XWING_PROVIDER_ID, XWING_SUITE } from './xwing-provider.mjs';

const hex = (s) => Buffer.from(s, 'hex');
const fixture = (name) => JSON.parse(readFileSync(new URL(`fixtures/${name}`, import.meta.url)));

test('published X-Wing implementation matches all three author known-answer vectors', () => {
  const vectors = fixture('xwing.json');
  assert.equal(vectors.length, 3);
  for (const v of vectors) {
    const pair = ml_kem768_x25519.keygen(hex(v.seed));
    assert.deepEqual(Buffer.from(pair.publicKey), hex(v.pk));
    assert.deepEqual(Buffer.from(pair.secretKey), hex(v.sk));
    const result = ml_kem768_x25519.encapsulate(pair.publicKey, hex(v.eseed));
    assert.deepEqual(Buffer.from(result.cipherText), hex(v.ct));
    assert.deepEqual(Buffer.from(result.sharedSecret), hex(v.ss));
    assert.deepEqual(
      Buffer.from(ml_kem768_x25519.decapsulate(hex(v.ct), pair.secretKey)),
      hex(v.ss),
    );
  }
});

test('Noble ML-KEM and ML-DSA public keys match independently published NIST vectors', () => {
  for (const v of fixture('nist-mlkem-keygen.json')) {
    const impl = v.parameterSet === 'ML-KEM-768' ? ml_kem768 : ml_kem1024;
    assert.deepEqual(Buffer.from(impl.keygen(hex(v.d + v.z)).publicKey), hex(v.ek));
  }
  for (const v of fixture('nist-mldsa-keygen.json')) {
    assert.deepEqual(Buffer.from(ml_dsa65.keygen(hex(v.seed)).publicKey), hex(v.pk));
  }
});

for (const [algorithm, implementation] of [
  ['ml-kem-768', ml_kem768],
  ['ml-kem-1024', ml_kem1024],
]) {
  test(`${algorithm}: native and Noble interoperate in both directions`, () => {
    const seed = native.randomBytes(64);
    const pair = implementation.keygen(seed);
    const sk = native.createPrivateKey({
      key: seed,
      format: 'raw-seed',
      asymmetricKeyType: algorithm,
    });
    const pk = native.createPublicKey(sk);
    assert.deepEqual(pk.export({ format: 'raw-public' }), Buffer.from(pair.publicKey));
    const n = implementation.encapsulate(pair.publicKey);
    assert.deepEqual(native.decapsulate(sk, n.cipherText), Buffer.from(n.sharedSecret));
    const c = native.encapsulate(pk);
    assert.deepEqual(
      Buffer.from(implementation.decapsulate(c.ciphertext, pair.secretKey)),
      c.sharedKey,
    );
  });
}

test('ML-DSA-65 native and Noble signatures interoperate in both directions', () => {
  const seed = native.randomBytes(32);
  const pair = ml_dsa65.keygen(seed);
  const sk = native.createPrivateKey({
    key: seed,
    format: 'raw-seed',
    asymmetricKeyType: 'ml-dsa-65',
  });
  const pk = native.createPublicKey(sk);
  const message = Buffer.from('synthetic independent signature verification');
  assert.deepEqual(pk.export({ format: 'raw-public' }), Buffer.from(pair.publicKey));
  assert(native.verify(null, message, pk, ml_dsa65.sign(message, pair.secretKey)));
  assert(ml_dsa65.verify(native.sign(null, message, sk), message, pair.publicKey));
  message[0] ^= 1;
  assert.equal(
    ml_dsa65.verify(native.sign(null, Buffer.from('other'), sk), message, pair.publicKey),
    false,
  );
});

test('actual hybrid endpoint provider authenticates wrapping context and blocks downgrade or revoked keys', async () => {
  const selection = { providerId: XWING_PROVIDER_ID, suiteId: XWING_SUITE };
  const policy = {
    schemaVersion: 1,
    revision: 1,
    mode: 'laboratory',
    newSuites: [selection],
    legacySuites: [],
  };
  const provider = createXwingLabProvider();
  const engine = new CryptoEngine({ providers: [provider], policy });
  assert.throws(
    () => new CryptoEngine({ providers: [provider], policy: { ...policy, mode: 'production' } }),
    /Laboratory/,
  );
  const recipient = await engine.generateKey({ ...selection, purpose: 'encapsulate' });
  const sender = await engine.generateKey({ ...selection, purpose: 'sign' });
  const data = native.randomBytes(256);
  const signature = await engine.sign({ keyId: sender.keyId, data });
  assert(await engine.verify({ key: sender, data, signature }));
  const contentKey = native.randomBytes(32);
  const context = { schemaVersion: 3, objectId: 'lab-object', recipientDevice: 'lab-device' };
  const packet = await engine.wrapKey({ key: recipient, contentKey, context });
  assert.deepEqual(
    Buffer.from(await engine.unwrapKey({ keyId: recipient.keyId, packet, context })),
    contentKey,
  );
  await assert.rejects(
    engine.unwrapKey({
      keyId: recipient.keyId,
      packet,
      context: { ...context, objectId: 'other' },
    }),
  );
  await assert.rejects(
    engine.unwrapKey({
      keyId: recipient.keyId,
      packet: { ...packet, suiteId: 'classical' },
      context,
    }),
  );
  const tampered = structuredClone(packet);
  const ct = Buffer.from(tampered.encapsulation.ciphertext, 'base64url');
  ct[0] ^= 1;
  tampered.encapsulation.ciphertext = ct.toString('base64url');
  await assert.rejects(engine.unwrapKey({ keyId: recipient.keyId, packet: tampered, context }));
  engine.revokeKey({ keyId: recipient.keyId, reason: 'synthetic exercise' });
  await assert.rejects(engine.unwrapKey({ keyId: recipient.keyId, packet, context }), /revoked/);
  await assert.rejects(provider.generateKey({ suiteId: 'fallback', purpose: 'sign' }));
  await assert.rejects(provider.generateKey({ suiteId: XWING_SUITE, purpose: 'derive' }));
  await assert.rejects(
    provider.encapsulate({
      suiteId: XWING_SUITE,
      publicKey: { ...recipient.publicKey, privateKey: 'secret' },
    }),
  );
});
