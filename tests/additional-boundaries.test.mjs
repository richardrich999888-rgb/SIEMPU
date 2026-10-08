import test from 'node:test';
import assert from 'node:assert/strict';
import {
  readFileSync,
  openSync,
  fstatSync,
  closeSync,
  existsSync,
  writeFileSync,
  symlinkSync,
  ftruncateSync,
} from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
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
test('unreachable relay is a retryable 503 RELAY_UNAVAILABLE, never 500; integrity faults are not masked', async (t) => {
  // Regression: the three-host run (T5.3) observed HTTP 500 INTERNAL_ERROR while the relay was down.
  const f = await coreFixture(t),
    { alice, bob } = f.clients;
  await alice.authenticate();
  await bob.authenticate();
  const obj = createObject(f.profiles.alice, f.profiles.bob, await alice.grant()),
    { putBlob, getBlob } = f.authority.relay;
  const refused = () => {
    throw Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8442'), { code: 'ECONNREFUSED' });
  };
  f.authority.relay.putBlob = refused;
  const down = await alice.request('POST', '/api/objects', {
    ...obj,
    proof: await alice.proof('submit', obj),
  });
  assert.equal(down.status, 503);
  assert.equal(down.body.code, 'RELAY_UNAVAILABLE');
  assert.equal(f.authority.get('SELECT count(*) n FROM objects').n, 0);
  f.authority.relay.putBlob = putBlob;
  await alice.submit(obj);
  const epoch = f.authority.epoch().epoch;
  // Claiming while the relay cannot serve the ciphertext is also 503.
  f.authority.relay.getBlob = async () => {
    throw Object.assign(new Error('Ciphertext relay unavailable or request rejected'), {
      code: 'RELAY_ERROR',
      status: 503,
    });
  };
  const unavailable = await bob.claim(obj.envelope.objectId, epoch);
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.code, 'RELAY_UNAVAILABLE');
  // An integrity failure from the relay client is NOT reported as unavailability.
  f.authority.relay.getBlob = async () => {
    throw new Error('Relay ciphertext digest mismatch');
  };
  const corrupt = await bob.claim(obj.envelope.objectId, epoch);
  assert.notEqual(corrupt.status, 503);
  assert.ok(corrupt.status >= 500);
  f.authority.relay.getBlob = getBlob;
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

test('recovery durability or evidence failure leaves credentials, sessions and epoch unchanged', async (t) => {
  const f = await coreFixture(t);
  await f.clients.alice.authenticate();
  const before = f.authority.get('SELECT * FROM users WHERE id=?', f.profiles.alice.userId);
  const epoch = f.authority.epoch().epoch;
  const recoveryModule = new URL('../scripts/recover-identity.mjs', import.meta.url).href;
  const authorityModule = new URL('../services/control/core.mjs', import.meta.url).href;
  for (const failure of ['file-fsync', 'directory-fsync', 'evidence']) {
    const output = join(f.dir, `${failure}-recovery.json`);
    const result = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `
        import fs from 'node:fs';
        import { syncBuiltinESMExports } from 'node:module';
        import { Authority } from ${JSON.stringify(authorityModule)};
        const failure = process.argv[3];
        const originalFsync = fs.fsyncSync;
        fs.fsyncSync = (descriptor) => {
          const directory = fs.fstatSync(descriptor).isDirectory();
          if ((failure === 'file-fsync' && !directory) ||
              (failure === 'directory-fsync' && directory)) {
            throw new Error('Injected recovery durability failure');
          }
          return originalFsync(descriptor);
        };
        syncBuiltinESMExports();
        if (failure === 'evidence') Authority.prototype.event = () => {
          throw new Error('Injected recovery evidence failure');
        };
        const { recoverIdentity } = await import(${JSON.stringify(recoveryModule)});
        try { recoverIdentity(process.argv[1], 'alice', process.argv[2]); }
        catch (error) { process.stderr.write(error.message); process.exit(1); }
      `,
        f.dir,
        output,
        failure,
      ],
      { encoding: 'utf8', timeout: 10000 },
    );
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Injected recovery (durability|evidence) failure/);
    assert.equal(existsSync(output), false, failure);
    assert.deepEqual(
      f.authority.get('SELECT * FROM users WHERE id=?', f.profiles.alice.userId),
      before,
      failure,
    );
    assert.equal(f.authority.epoch().epoch, epoch, failure);
    assert.equal((await f.clients.alice.request('GET', '/api/auth/me')).status, 200, failure);
  }
});
