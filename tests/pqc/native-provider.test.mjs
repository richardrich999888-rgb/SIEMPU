import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import {
  createNativePqcProvider,
  NATIVE_PQC_PROVIDER_ID,
  NATIVE_MLKEM768_SUITE,
  NATIVE_MLKEM1024_SUITE,
} from '../../packages/pqc-lab/native-provider.mjs';
import { CryptoEngine } from '../../packages/crypto-provider/engine.mjs';

const suites = [NATIVE_MLKEM768_SUITE, NATIVE_MLKEM1024_SUITE];
const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`../../packages/pqc-lab/fixtures/${name}`, import.meta.url)));
const policy = {
  schemaVersion: 1,
  revision: 1,
  mode: 'laboratory',
  newSuites: suites.map((suiteId) => ({ providerId: NATIVE_PQC_PROVIDER_ID, suiteId })),
  legacySuites: [],
};

test('native ML-KEM key generation matches four published NIST ACVP vectors', () => {
  for (const v of fixture('nist-mlkem-keygen.json')) {
    const key = createPrivateKey({
      key: Buffer.from(v.d + v.z, 'hex'),
      format: 'raw-seed',
      asymmetricKeyType: v.parameterSet.toLowerCase(),
    });
    assert.equal(
      createPublicKey(key).export({ format: 'raw-public' }).toString('hex'),
      v.ek.toLowerCase(),
    );
  }
});

test('native ML-DSA-65 key generation matches two published NIST ACVP vectors', () => {
  for (const v of fixture('nist-mldsa-keygen.json')) {
    const key = createPrivateKey({
      key: Buffer.from(v.seed, 'hex'),
      format: 'raw-seed',
      asymmetricKeyType: 'ml-dsa-65',
    });
    assert.equal(
      createPublicKey(key).export({ format: 'raw-public' }).toString('hex'),
      v.pk.toLowerCase(),
    );
  }
});

for (const suiteId of suites) {
  test(`${suiteId}: actual endpoint KEM, signatures and authenticated wrapping`, async () => {
    const engine = new CryptoEngine({ providers: [createNativePqcProvider()], policy });
    const selection = { providerId: NATIVE_PQC_PROVIDER_ID, suiteId };
    const recipient = await engine.generateKey({ ...selection, purpose: 'encapsulate' });
    const sender = await engine.generateKey({ ...selection, purpose: 'sign' });
    const message = new TextEncoder().encode('synthetic endpoint plaintext');
    const signature = await engine.sign({ keyId: sender.keyId, data: message });
    assert(await engine.verify({ key: sender, data: message, signature }));
    signature[0] ^= 1;
    assert.equal(await engine.verify({ key: sender, data: message, signature }), false);
    const contentKey = crypto.getRandomValues(new Uint8Array(32));
    const context = { objectId: 'synthetic-object', mission: 'lab', schemaVersion: 3 };
    const packet = await engine.wrapKey({ key: recipient, contentKey, context });
    assert.deepEqual(
      await engine.unwrapKey({ keyId: recipient.keyId, packet, context }),
      contentKey,
    );
    await assert.rejects(
      engine.unwrapKey({
        keyId: recipient.keyId,
        packet,
        context: { ...context, mission: 'other' },
      }),
    );
    await assert.rejects(
      engine.unwrapKey({
        keyId: recipient.keyId,
        packet: { ...packet, suiteId: 'weaker' },
        context,
      }),
    );
    const bad = structuredClone(packet);
    const ct = Buffer.from(bad.encapsulation.ciphertext, 'base64url');
    ct[0] ^= 1;
    bad.encapsulation.ciphertext = ct.toString('base64url');
    await assert.rejects(engine.unwrapKey({ keyId: recipient.keyId, packet: bad, context }));
    engine.revokeKey({ keyId: recipient.keyId, reason: 'synthetic revocation' });
    await assert.rejects(engine.unwrapKey({ keyId: recipient.keyId, packet, context }), /revoked/);
  });
}

test('native PQ provider rejects forbidden suites, cross-purpose handles and private public-key fields', async () => {
  const provider = createNativePqcProvider();
  const suiteId = NATIVE_MLKEM768_SUITE;
  assert.throws(
    () => new CryptoEngine({ providers: [provider], policy: { ...policy, mode: 'production' } }),
    /Laboratory/,
  );
  await assert.rejects(provider.generateKey({ suiteId: 'unsupported', purpose: 'sign' }));
  await assert.rejects(provider.generateKey({ suiteId, purpose: 'derive' }));
  const pair = await provider.generateKey({ suiteId, purpose: 'encapsulate' });
  assert.equal(JSON.stringify(pair.privateKey), '{}');
  await assert.rejects(
    provider.sign({ suiteId, privateKey: pair.privateKey, data: new Uint8Array(1) }),
  );
  await assert.rejects(
    provider.encapsulate({ suiteId, publicKey: { ...pair.publicKey, privateKey: 'injected' } }),
  );
  await assert.rejects(
    provider.encapsulate({ suiteId, publicKey: { ...pair.publicKey, format: 'raw-private' } }),
  );
  await assert.rejects(
    provider.encapsulate({
      suiteId,
      publicKey: { ...pair.publicKey, bytes: pair.publicKey.bytes + '=' },
    }),
  );
  await assert.rejects(
    provider.encapsulate({ suiteId: NATIVE_MLKEM1024_SUITE, publicKey: pair.publicKey }),
  );
  const e = await provider.encapsulate({ suiteId, publicKey: pair.publicKey });
  await assert.rejects(
    createNativePqcProvider().decapsulate({
      suiteId,
      privateKey: pair.privateKey,
      encapsulation: e.encapsulation,
    }),
  );
  await assert.rejects(
    provider.decapsulate({
      suiteId,
      privateKey: pair.privateKey,
      encapsulation: { ...e.encapsulation, algorithm: 'x25519' },
    }),
  );
  await assert.rejects(
    provider.decapsulate({
      suiteId,
      privateKey: pair.privateKey,
      encapsulation: { ...e.encapsulation, ciphertext: 'AA' },
    }),
  );
});
