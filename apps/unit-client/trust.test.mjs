import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
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
  await assert.rejects(
    publicAuthorityKey({
      ...keys.signing.publicKey,
      x: Buffer.alloc(32).toString('base64url'),
      y: Buffer.alloc(32).toString('base64url'),
    }),
    /invalid/i,
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

test('installed offline shell includes every transitive static module import and no API routes', async () => {
  const listeners = new Map();
  let cached;
  const source = await readFile(new URL('./sw.js', import.meta.url), 'utf8');
  runInNewContext(source, {
    self: {
      addEventListener: (name, callback) => listeners.set(name, callback),
      skipWaiting: async () => {},
    },
    caches: {
      open: async () => ({
        addAll: async (assets) => {
          cached = [...assets];
        },
      }),
    },
  });
  let installation;
  listeners.get('install')({
    waitUntil: (promise) => {
      installation = promise;
    },
  });
  await installation;
  assert.ok(cached.includes('/apps/unit-client/trust.mjs'));
  assert.ok(cached.includes('/apps/unit-client/authority-pin.mjs'));
  assert.ok(cached.every((asset) => !asset.startsWith('/api/')));
  const root = new URL('../../', import.meta.url);
  for (const asset of cached.filter((path) => path.endsWith('.mjs'))) {
    const module = await readFile(new URL(asset.slice(1), root), 'utf8');
    const imports = module.matchAll(/\bimport\s+(?:[^;]*?\s+from\s+)?['"]([^'"]+)['"]/g);
    for (const [, specifier] of imports) {
      assert.ok(
        specifier.startsWith('.') || specifier.startsWith('/'),
        `Unexpected bare import in ${asset}`,
      );
      const dependency = new URL(specifier, 'https://synthetic.invalid' + asset).pathname;
      assert.ok(
        cached.includes(dependency),
        `Offline shell lacks ${dependency}, imported by ${asset}`,
      );
    }
  }
});
