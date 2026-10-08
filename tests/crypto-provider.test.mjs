import test from 'node:test';
import assert from 'node:assert/strict';
import { createObjectCryptography } from '../packages/crypto/crypto.mjs';
import {
  createWebCryptoProvider,
  negotiateSuite,
  DEMO_SUITE,
} from '../packages/crypto/providers/webcrypto.mjs';
import { createNodeClassicProvider } from '../packages/crypto/providers/node-classic.mjs';

test('both provider directions interoperate for v1/v2 objects, vaults and opaque keys', async () => {
  const peers = [
    createObjectCryptography(createWebCryptoProvider()),
    createObjectCryptography(createNodeClassicProvider()),
  ];
  for (const [sender, recipient] of [peers, [...peers].reverse()]) {
    const a = await sender.generateOpaqueDeviceKeys(),
      b = await recipient.generateOpaqueDeviceKeys();
    assert.equal('d' in a.signing.privateKey, false);
    await assert.rejects(
      sender.provider.subtle.exportKey(
        'jwk',
        sender.provider.resolve(a.signing.privateKey, 'sign'),
      ),
    );
    const creationGrant = await sender.signPacket(a.signing.privateKey, { epoch: 1 });
    for (const schemaVersion of [1, 2]) {
      const context = {
        schemaVersion,
        objectId: crypto.randomUUID(),
        senderUserId: 'a',
        senderDeviceId: 'a-device',
        senderUnitId: 'unit-a',
        recipientUserId: 'b',
        recipientDeviceId: 'b-device',
        recipientUnitId: 'unit-b',
        recipientKeyId: await recipient.keyId(b.encryption.publicKey),
        missionId: 'synthetic',
        classification: 'DEMO',
        action: 'deliver',
        createdAt: 1,
        expiresAt: 100,
        creationGrant,
        cryptoSuite: DEMO_SUITE,
        keyVersion: 1,
        ...(schemaVersion === 2 ? { messagePriority: 'ROUTINE', messageDomain: 'GENERAL' } : {}),
      };
      const payload = sender.createTextPayload('SYNTHETIC provider conformance');
      const sealed = await sender.encryptObject(
        context,
        payload,
        b.encryption.publicKey,
        a.signing.privateKey,
      );
      assert.deepEqual(
        await recipient.decryptObject(sealed, b.encryption.privateKey, a.signing.publicKey),
        payload,
      );
      const tampered = structuredClone(sealed);
      tampered.envelope.nonce = 'A'.repeat(16);
      await assert.rejects(
        recipient.decryptObject(tampered, b.encryption.privateKey, a.signing.publicKey),
      );
      await assert.rejects(
        sender.encryptObject(
          { ...context, cryptoSuite: 'downgrade' },
          payload,
          b.encryption.publicKey,
          a.signing.privateKey,
        ),
        /APPROVED/,
      );
    }
    assert.deepEqual(
      await recipient.openVault(
        await sender.sealVault({ synthetic: true }, 'long laboratory phrase'),
        'long laboratory phrase',
      ),
      { synthetic: true },
    );
    assert.throws(() => sender.provider.resolve(a.signing.privateKey, 'deriveBits'), /USAGE/);
    await assert.rejects(recipient.sign(a.signing.privateKey, {}), /HANDLE/);
    await assert.rejects(sender.sign(structuredClone(a.signing.privateKey), {}), /HANDLE/);
    sender.provider.destroy(a.signing.privateKey);
    await assert.rejects(sender.sign(a.signing.privateKey, {}), /DESTROYED/);
    const rotated = await sender.generateOpaqueDeviceKeys();
    assert.notEqual(
      await sender.keyId(rotated.signing.publicKey),
      await sender.keyId(a.signing.publicKey),
    );
  }
});
test('provider version, capability, failure and suite approval are fail closed', async () => {
  const provider = createWebCryptoProvider();
  assert.throws(() => createObjectCryptography({ ...provider, version: 2 }), /VERSION/);
  assert.throws(() => createObjectCryptography({ ...provider, suites: [] }), /APPROVED/);
  assert.throws(() => negotiateSuite(provider, [DEMO_SUITE], []), /APPROVED/);
  const broken = createObjectCryptography({
    ...provider,
    subtle: new Proxy(provider.subtle, {
      get: (target, name) =>
        name === 'sign'
          ? () => {
              throw new Error('PROVIDER_UNAVAILABLE');
            }
          : target[name].bind(target),
    }),
  });
  const keys = await provider.generateDeviceHandles();
  await assert.rejects(broken.sign(keys.signing.privateKey, {}), /PROVIDER_UNAVAILABLE/);
  assert.equal(provider.capabilities.hardwareBacked, false);
});
