import test from 'node:test';
import assert from 'node:assert/strict';
import {
  readFileSync,
  openSync,
  closeSync,
  fstatSync,
  writeFileSync,
  symlinkSync,
  ftruncateSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { coreFixture } from './helpers/fixture.mjs';
import { ApiClient, createObject } from './helpers/client.mjs';
import { recoverIdentity } from '../scripts/recover-identity.mjs';
import { totp, base32 } from '../services/control/primitives.mjs';
test('RFC6238 SHA1 six-digit truncation matches published vector', () => {
  assert.equal(totp(base32(Buffer.from('12345678901234567890')), 59000), '287082');
});
test('role downgrade during relay await cannot insert a pending object', async (t) => {
  const f = await coreFixture(t),
    alice = f.clients.alice;
  await alice.authenticate();
  const obj = createObject(f.profiles.alice, f.profiles.bob, await alice.grant());
  const put = f.authority.relay.putBlob;
  f.authority.relay.putBlob = async (...args) => {
    await put(...args);
    f.authority.tx(() =>
      f.authority.run("UPDATE users SET role='viewer' WHERE id=?", f.profiles.alice.userId),
    );
  };
  const result = await alice.request('POST', '/api/objects', {
    ...obj,
    proof: await alice.proof('submit', obj),
  });
  assert.equal(result.status, 403);
  assert.equal(f.authority.get('SELECT count(*) n FROM objects').n, 0);
});
test('relay outage and evidence write failure never create an issuance; retry recovers', async (t) => {
  const f = await coreFixture(t),
    { alice, bob } = f.clients;
  await alice.authenticate();
  await bob.authenticate();
  const obj = createObject(f.profiles.alice, f.profiles.bob, await alice.grant()),
    put = f.authority.relay.putBlob;
  f.authority.relay.putBlob = async () => {
    throw new Error('Injected relay outage');
  };
  await assert.rejects(() => alice.submit(obj), /Injected relay outage|INTERNAL/);
  assert.equal(f.authority.get('SELECT count(*) n FROM objects').n, 0);
  f.authority.relay.putBlob = put;
  await alice.submit(obj);
  const epoch = f.authority.epoch().epoch;
  const before = f.authority.get('SELECT count(*) n FROM evidence').n;
  f.authority.hooks.beforeEvidence = () => {
    throw new Error('Injected evidence persistence failure');
  };
  assert.throws(
    () => f.authority.claim(f.authority.authenticate(bob.token), obj.envelope.objectId, epoch),
    /Injected evidence/,
  );
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
  assert.equal(f.authority.get('SELECT count(*) n FROM evidence').n, before);
  delete f.authority.hooks.beforeEvidence;
  assert.equal((await bob.claim(obj.envelope.objectId, epoch)).status, 200);
});
test('offline identity recovery rotates MFA/password and revokes every session', async (t) => {
  const f = await coreFixture(t),
    alice = f.clients.alice;
  await alice.authenticate();
  const epoch = f.authority.epoch().epoch;
  const output = join(f.dir, 'private-recovery.json');
  const result = recoverIdentity(f.dir, 'alice', output);
  assert.equal(result.epoch, epoch + 1);
  const file = openSync(output, 'r');
  let material;
  try {
    assert.equal(fstatSync(file).mode & 0o077, 0);
    material = JSON.parse(readFileSync(file));
  } finally {
    closeSync(file);
  }
  assert.equal((await alice.request('GET', '/api/auth/me')).status, 401);
  assert.notEqual(material.password, f.profiles.alice.password);
  assert.notEqual(material.totpSecret, f.profiles.alice.totpSecret);
  const recovered = new ApiClient(f.transport, { ...f.profiles.alice, ...material });
  await recovered.authenticate();
  assert.equal((await recovered.ok('GET', '/api/auth/me')).user.username, 'alice');
  assert.throws(() => recoverIdentity(f.dir, 'alice', output), /new private/);
});

test('recovery refuses occupied/symlink/unwritable destinations before credential mutation', async (t) => {
  const f = await coreFixture(t);
  await f.clients.alice.authenticate();
  const before = f.authority.get(
    'SELECT password,totp,totp_floor FROM users WHERE username=?',
    'alice',
  );
  const epoch = f.authority.epoch().epoch;
  const existing = join(f.dir, 'occupied.json');
  writeFileSync(existing, 'original-output', { mode: 0o600 });
  const link = join(f.dir, 'linked-output.json');
  symlinkSync(existing, link);
  for (const output of [existing, link, join(f.dir, 'missing-parent', 'recovery.json')]) {
    assert.throws(() => recoverIdentity(f.dir, 'alice', output));
    assert.deepEqual(
      f.authority.get('SELECT password,totp,totp_floor FROM users WHERE username=?', 'alice'),
      before,
    );
    assert.equal(f.authority.epoch().epoch, epoch);
    assert.equal((await f.clients.alice.request('GET', '/api/auth/me')).status, 200);
  }
  assert.equal(readFileSync(existing, 'utf8'), 'original-output');
});

test('verifier CLI rejects an oversized opened input before JSON parsing', async (t) => {
  const f = await coreFixture(t);
  const oversized = join(f.dir, 'oversized.json'),
    trusted = join(f.dir, 'public-key.json');
  const descriptor = openSync(oversized, 'wx', 0o600);
  try {
    ftruncateSync(descriptor, 64 * 1024 * 1024 + 1);
  } finally {
    closeSync(descriptor);
  }
  writeFileSync(trusted, JSON.stringify(f.provisioned.serverPublicKey));
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL('../apps/verifier/verify.mjs', import.meta.url)), oversized, trusted],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /exceeds 64 MiB/);
});

test('SBOM purls encode every reserved package-name character without altering scope separators', async (t) => {
  const f = await coreFixture(t);
  writeFileSync(
    join(f.dir, 'package.json'),
    JSON.stringify({ name: 'synthetic', version: '1.0.0' }),
  );
  writeFileSync(
    join(f.dir, 'package-lock.json'),
    JSON.stringify({
      packages: {
        'node_modules/@scope/package': { name: '@scope/package', version: '1.2.3' },
        'node_modules/untrusted': { name: '@scope/name@extra?#', version: '1.0.0+metadata' },
      },
    }),
  );
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL('../scripts/sbom.mjs', import.meta.url))],
    { cwd: f.dir, encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(readFileSync(join(f.dir, 'artifacts/application.cdx.json')));
  assert.equal(
    output.components.find((component) => component.name === '@scope/package').purl,
    'pkg:npm/%40scope/package@1.2.3',
  );
  assert.equal(
    output.components.find((component) => component.name === '@scope/name@extra?#').purl,
    'pkg:npm/%40scope/name%40extra%3F%23@1.0.0%2Bmetadata',
  );
});
