import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, openSync, fstatSync, closeSync, existsSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
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
  const fd = openSync(output, 'r');
  let material;
  try {
    assert.equal(fstatSync(fd).mode & 0o077, 0);
    material = JSON.parse(readFileSync(fd));
  } finally {
    closeSync(fd);
  }
  assert.equal((await alice.request('GET', '/api/auth/me')).status, 401);
  assert.notEqual(material.password, f.profiles.alice.password);
  assert.notEqual(material.totpSecret, f.profiles.alice.totpSecret);
  const recovered = new ApiClient(f.transport, { ...f.profiles.alice, ...material });
  await recovered.authenticate();
  assert.equal((await recovered.ok('GET', '/api/auth/me')).user.username, 'alice');
  assert.throws(() => recoverIdentity(f.dir, 'alice', output), /new private/);
});

test('failed recovery output reservation cannot change credentials, sessions or epoch', async (t) => {
  const f = await coreFixture(t);
  await f.clients.alice.authenticate();
  const before = f.authority.get('SELECT * FROM users WHERE id=?', f.profiles.alice.userId);
  const epoch = f.authority.epoch().epoch;
  const existing = join(f.dir, 'existing.json');
  writeFileSync(existing, 'keep existing bytes', { mode: 0o600 });
  assert.throws(() => recoverIdentity(f.dir, 'alice', existing), /new private/);
  assert.equal(readFileSync(existing, 'utf8'), 'keep existing bytes');
  assert.throws(() => recoverIdentity(f.dir, 'alice', join(f.dir, 'missing', 'output.json')));
  const rejected = join(f.dir, 'unknown-user.json');
  assert.throws(() => recoverIdentity(f.dir, 'unknown', rejected), /Unknown recovery identity/);
  assert.equal(existsSync(rejected), false);
  assert.deepEqual(
    f.authority.get('SELECT * FROM users WHERE id=?', f.profiles.alice.userId),
    before,
  );
  assert.equal(f.authority.epoch().epoch, epoch);
  assert.equal((await f.clients.alice.request('GET', '/api/auth/me')).status, 200);
});

test('concurrent recovery writers reserve one output and rotate identity exactly once', async (t) => {
  const f = await coreFixture(t);
  const output = join(f.dir, 'concurrent-recovery.json');
  const epoch = f.authority.epoch().epoch;
  const recoveryModule = new URL('../scripts/recover-identity.mjs', import.meta.url).href;
  const children = Array.from({ length: 6 }, () => {
    const child = spawn(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `
      import { recoverIdentity } from ${JSON.stringify(recoveryModule)};
      process.on('message', () => {
        try { recoverIdentity(process.argv[1], 'alice', process.argv[2]); process.exit(0); }
        catch (error) { process.stderr.write(error.message); process.exit(1); }
      });
      process.send('ready');
    `,
        f.dir,
        output,
      ],
      { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] },
    );
    let error = '';
    child.stderr.on('data', (chunk) => {
      error += chunk;
    });
    const done = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code) => resolve({ code, error }));
    });
    const ready = new Promise((resolve) => child.once('message', resolve));
    return { child, ready, done };
  });
  t.after(() => children.forEach(({ child }) => child.kill()));
  await Promise.all(children.map(({ ready }) => ready));
  children.forEach(({ child }) => child.send('recover'));
  const results = await Promise.all(children.map(({ done }) => done));
  assert.equal(results.filter(({ code }) => code === 0).length, 1);
  for (const result of results.filter(({ code }) => code !== 0))
    assert.match(result.error, /new private file/);
  assert.equal(f.authority.epoch().epoch, epoch + 1);
  const material = JSON.parse(readFileSync(output, 'utf8'));
  const recovered = new ApiClient(f.transport, { ...f.profiles.alice, ...material });
  await recovered.authenticate();
});
