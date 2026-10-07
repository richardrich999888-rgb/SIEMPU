import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
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
  assert.equal(statSync(output).mode & 0o077, 0);
  assert.equal((await alice.request('GET', '/api/auth/me')).status, 401);
  const material = JSON.parse(readFileSync(output));
  assert.notEqual(material.password, f.profiles.alice.password);
  assert.notEqual(material.totpSecret, f.profiles.alice.totpSecret);
  const recovered = new ApiClient(f.transport, { ...f.profiles.alice, ...material });
  await recovered.authenticate();
  assert.equal((await recovered.ok('GET', '/api/auth/me')).user.username, 'alice');
  assert.throws(() => recoverIdentity(f.dir, 'alice', output), /new private/);
});
