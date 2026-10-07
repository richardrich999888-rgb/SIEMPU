import test from 'node:test';
import assert from 'node:assert/strict';
import { generateDeviceKeys } from '../../packages/crypto/crypto.mjs';
import {
  publicAuthorityKey,
  authorityFingerprint,
  publicMetadata,
  readAuthorityPin,
} from './trust.mjs';

test('trust pin is a digest of exact public-only authority material and safely migrates legacy public pins', async () => {
  const keys = await generateDeviceKeys();
  const fingerprint = await authorityFingerprint(keys.signing.publicKey);
  assert.match(fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(await readAuthorityPin(keys.signing.publicKey), fingerprint);
  assert.equal(await readAuthorityPin(fingerprint), fingerprint);
  assert.equal(await readAuthorityPin(null), null);
  await assert.rejects(publicAuthorityKey(keys.signing.privateKey), /no private or extra fields/);
  await assert.rejects(readAuthorityPin(keys.signing.privateKey), /no private or extra fields/);
  await assert.rejects(
    publicAuthorityKey({ ...keys.signing.publicKey, token: 'must-not-be-cached' }),
    /no private or extra fields/,
  );
});
test('offline metadata cache projects only public protocol fields and rejects private-key substitution', async () => {
  const keys = await generateDeviceKeys();
  const value = {
    version: 'test',
    serverPublicKey: keys.signing.publicKey,
    serverKeyId: await authorityFingerprint(keys.signing.publicKey),
    limits: {
      objectBytes: 100,
      sessionSeconds: 10,
      grantSeconds: 10,
      unused: 'not-public-protocol',
    },
    securityProfile: 'synthetic test',
    password: 'must-not-be-cached',
    privateKey: keys.signing.privateKey,
  };
  const projected = await publicMetadata(value);
  assert.deepEqual(Object.keys(projected).sort(), [
    'limits',
    'securityProfile',
    'serverKeyId',
    'serverPublicKey',
    'version',
  ]);
  assert.equal(JSON.stringify(projected).includes('must-not-be-cached'), false);
  assert.equal(JSON.stringify(projected).includes(keys.signing.privateKey.d), false);
  await assert.rejects(
    publicMetadata({ ...value, serverPublicKey: keys.signing.privateKey }),
    /no private or extra fields/,
  );
  await assert.rejects(
    publicMetadata({ ...value, serverKeyId: '0'.repeat(64) }),
    /fingerprint mismatch/,
  );
});
