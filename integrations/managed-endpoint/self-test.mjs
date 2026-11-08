// Offline configuration/refusal tests. These do not stand in for the combined native gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateConfiguration, openManagedEndpoint } from './index.mjs';

const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
  'sign',
  'verify',
]);
const exported = await crypto.subtle.exportKey('jwk', pair.publicKey);
const key = Object.fromEntries(['kty', 'crv', 'x', 'y'].map((k) => [k, exported[k]]));
const hash = 'a'.repeat(64);
function configuration() {
  return {
    schemaVersion: 1,
    url: 'https://synthetic.invalid',
    authorityKey: key,
    profile: {
      username: 'synthetic',
      userId: 'synthetic-user',
      deviceId: 'synthetic-device',
      unitId: 'synthetic-unit',
      signing: { handleId: 'a'.repeat(32), publicKey: key },
      encryption: { handleId: 'b'.repeat(32), publicKey: key },
    },
    pkcs11: {
      python: '/not-provisioned/python',
      pythonSha256: hash,
      module: '/not-provisioned/module',
      moduleSha256: hash,
      workerSha256: hash,
      tokenLabel: 'synthetic',
      tokenSerial: 'synthetic',
    },
    inspection: {
      executable: '/not-provisioned/runtime/bin/clamscan',
      executableSha256: hash,
      database: '/not-provisioned/signatures',
      tempRoot: '/not-provisioned/ram',
      sandbox: {
        bwrap: '/not-provisioned/bwrap',
        bwrapSha256: hash,
        prlimit: '/not-provisioned/prlimit',
        prlimitSha256: hash,
        runtimeRoot: '/not-provisioned/runtime',
        files: { 'bin/clamscan': hash },
      },
    },
  };
}

test('configuration snapshots public pins without native execution', () => {
  const c = configuration(),
    checked = validateConfiguration(c);
  c.inspection.sandbox.files['bin/clamscan'] = 'b'.repeat(64);
  assert.equal(checked.inspection.sandbox.files['bin/clamscan'], hash);
  assert.equal('getPin' in checked.pkcs11, false);
});

test('unknown fields, secrets, raw private keys and missing isolation are refused', () => {
  for (const change of [
    (c) => (c.password = 'synthetic-secret'),
    (c) => (c.pkcs11.pin = 'synthetic-secret'),
    (c) => (c.profile.signing.publicKey = { ...key, d: 'synthetic-private' }),
    (c) => (c.inspection.sandbox = undefined),
    (c) => (c.inspection.executable = '/unisolated/clamscan'),
    (c) => (c.schemaVersion = 2),
    (c) => (c.inspection.sandbox.files['../escape'] = hash),
  ]) {
    const c = configuration();
    change(c);
    assert.throws(() => validateConfiguration(c));
  }
});

test('only a plain HTTPS origin is permitted', () => {
  for (const url of [
    'http://synthetic.invalid',
    'https://u:p@synthetic.invalid',
    'https://synthetic.invalid/path',
    'https://synthetic.invalid?x=1',
    'https://synthetic.invalid#fragment',
  ])
    assert.throws(() => validateConfiguration({ ...configuration(), url }), /DESTINATION/);
});

test('caller TLS overrides cannot replace hostname checking or lower protocol policy', async () => {
  for (const tls of [
    {},
    { ca: 'synthetic', rejectUnauthorized: false },
    { ca: 'synthetic', checkServerIdentity: () => undefined },
    { ca: 'synthetic', minVersion: 'TLSv1.2' },
    { ca: 'synthetic', cert: 'synthetic' },
  ]) {
    await assert.rejects(
      openManagedEndpoint({
        config: configuration(),
        tls,
        credentials: { password: 'synthetic', totpSecret: 'synthetic' },
        getPin: async () => 'synthetic',
      }),
    );
  }
});

test('unavailable scanner refuses startup before any PIN request', async () => {
  let requested = false;
  await assert.rejects(
    openManagedEndpoint({
      config: configuration(),
      tls: { ca: 'synthetic' },
      credentials: { password: 'synthetic', totpSecret: 'synthetic' },
      getPin: async () => {
        requested = true;
        return 'synthetic';
      },
    }),
    /FILE_INSPECTION_UNAVAILABLE/,
  );
  assert.equal(requested, false);
});
