import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { coreFixture, root } from '../helpers/fixture.mjs';
import { createObject, sign } from '../helpers/client.mjs';

const binary = resolve(
  process.env.SIEPMU_NEXORA_BRIDGE ??
    join(root, 'integrations/nexora/target/release/siepmu-nexora-bridge'),
);
function run(args) {
  const result = spawnSync(binary, args, {
    encoding: 'utf8',
    timeout: 15000,
    maxBuffer: 20 * 1024 * 1024,
  });
  assert.equal(result.error, undefined, 'NEXORA bridge must be built and terminate within 15s');
  return result;
}
function success(args) {
  const result = run(args);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout ? JSON.parse(result.stdout) : null;
}
async function save(path, value) {
  await writeFile(path, JSON.stringify(value), { mode: 0o600 });
}
async function setup(t) {
  const f = await coreFixture(t);
  await f.clients.admin.authenticate();
  await f.clients.alice.authenticate();
  await f.clients.bob.authenticate();
  const paths = Object.fromEntries(
    ['evidence', 'authority', 'checkpoint', 'private', 'anchor', 'snapshot'].map((n) => [
      n,
      join(f.dir, `nexora-${n}.json`),
    ]),
  );
  success(['init', paths.private, paths.anchor, 'synthetic-audit-custodian', '1']);
  await save(paths.authority, f.authority.publicKey);
  const exported = await f.clients.admin.ok('GET', '/api/evidence/export');
  await save(paths.evidence, exported);
  // This fixture models a separately retained checkpoint; the CLI never imports it
  // from the snapshot. Production operators must supply their independently held copy.
  await save(paths.checkpoint, await f.clients.admin.ok('GET', '/api/evidence/checkpoint'));
  const seal = (output = paths.snapshot, evidence = paths.evidence) => [
    'seal',
    evidence,
    paths.authority,
    paths.checkpoint,
    paths.private,
    output,
  ];
  const verify = (input = paths.snapshot, checkpoint = paths.checkpoint, anchor = paths.anchor) => [
    'verify',
    input,
    paths.authority,
    checkpoint,
    anchor,
  ];
  return { ...f, paths, exported, seal, verify };
}

test('real authentication evidence is verified, sealed by NEXORA and inspected offline without exposing secrets', async (t) => {
  const f = await setup(t);
  assert.ok(f.exported.records.some((r) => r.payload.eventType === 'LOGIN'));
  success(f.seal());
  const snapshot = await readFile(f.paths.snapshot, 'utf8');
  const result = success(f.verify());
  assert.equal(result.valid, true);
  assert.equal(result.sourceVerification.valid, true);
  assert.equal(result.authorizesLogin, false);
  assert.equal(result.authorizesRelease, false);
  assert.equal((await stat(f.paths.snapshot)).mode & 0o777, 0o600);
  for (const profile of Object.values(f.profiles)) {
    for (const secret of [profile.password, profile.totpSecret, profile.keys.signing.privateKey.d])
      assert.ok(!snapshot.includes(secret));
  }
  for (const client of Object.values(f.clients))
    if (client.token) assert.ok(!snapshot.includes(client.token));
  const privateKey = JSON.parse(await readFile(f.paths.private, 'utf8')).private_key;
  assert.ok(!snapshot.includes(JSON.stringify(privateKey)));
  // Offline verification runs from files only; shutting the authority must not matter.
  const close = f.authority.close.bind(f.authority);
  f.authority.close = () => {
    if (f.authority.db.isOpen) close();
  };
  f.authority.close();
  assert.deepEqual(success(f.verify()), result);
});

test('a retained newer checkpoint rejects replay of an older, cryptographically valid NEXORA snapshot', async (t) => {
  const f = await setup(t);
  success(f.seal());
  await f.clients.admin.admin('POST', `/api/admin/devices/${f.profiles.bob.deviceId}/revoke`);
  const fresh = join(f.dir, 'fresh-retained-checkpoint.json');
  await save(fresh, await f.clients.admin.ok('GET', '/api/evidence/checkpoint'));
  assert.notEqual(run(f.verify(f.paths.snapshot, fresh)).status, 0);
  // It remains verifiable against its earlier retained checkpoint as historical evidence.
  assert.equal(success(f.verify()).authorizesLogin, false);
});

test('NEXORA evidence cannot replace a session or device challenge or bypass recipient revocation', async (t) => {
  const f = await setup(t);
  const object = createObject(f.profiles.alice, f.profiles.bob, await f.clients.alice.grant());
  await f.clients.alice.submit(object);
  await f.clients.alice.prepare(object.envelope.objectId);
  success(f.seal());
  const snapshot = JSON.parse(await readFile(f.paths.snapshot, 'utf8'));
  const claimedToken = JSON.stringify(snapshot);
  assert.equal((await f.transport('GET', '/api/control', {}, claimedToken)).status, 401);
  const challenge = await f.clients.bob.ok('POST', '/api/auth/challenge', {
    purpose: 'bind',
    deviceId: f.profiles.bob.deviceId,
  });
  const wrong = await f.clients.bob.request('POST', '/api/auth/bind', {
    deviceId: f.profiles.bob.deviceId,
    challengeId: challenge.challengeId,
    signature: Buffer.from(snapshot.head.signature.signature_bytes).toString('base64url'),
  });
  assert.notEqual(wrong.status, 200);
  // The real enrolled device must still prove possession of its key for this fresh nonce.
  assert.equal(
    (
      await f.clients.bob.request('POST', '/api/auth/bind', {
        deviceId: f.profiles.bob.deviceId,
        challengeId: challenge.challengeId,
        signature: sign(challenge.challenge, f.profiles.bob.keys.signing.privateKey),
      })
    ).status,
    200,
  );
  const body = { expectedEpoch: f.authority.epoch().epoch, nexoraProof: snapshot };
  const proof = await f.clients.bob.proof('claim:' + object.envelope.objectId, body);
  assert.equal(
    (await f.clients.admin.admin('POST', `/api/admin/devices/${f.profiles.bob.deviceId}/revoke`))
      .status,
    200,
  );
  const claim = await f.clients.bob.request(
    'POST',
    `/api/objects/${object.envelope.objectId}/claim`,
    {
      ...body,
      proof,
    },
  );
  assert.ok([401, 403].includes(claim.status));
  assert.ok(['SESSION_INVALID', 'DEVICE_UNTRUSTED'].includes(claim.body.error));
  assert.equal(f.authority.get('SELECT COUNT(*) n FROM issuances').n, 0);
  assert.ok(!JSON.stringify(claim.body).includes('wrappedKey'));
});

test('tampered source or bundle, unknown nested fields and a substituted signer anchor are rejected', async (t) => {
  const f = await setup(t);
  success(f.seal());
  const snapshot = JSON.parse(await readFile(f.paths.snapshot, 'utf8'));
  const bad = join(f.dir, 'bad-snapshot.json');
  for (const mutate of [
    (s) => {
      s.head.root[0] ^= 1;
    },
    (s) => {
      s.head.signature.authorizesLogin = true;
    },
    (s) => {
      s.evidence = s.evidence.replace('LOGIN', 'FORGED_LOGIN');
    },
    (s) => {
      s.profile = 'NEXORA_LOGIN_V1';
    },
  ]) {
    const changed = structuredClone(snapshot);
    mutate(changed);
    await save(bad, changed);
    assert.notEqual(run(f.verify(bad)).status, 0);
  }
  const other = join(f.dir, 'other-anchor.json');
  success(['init', join(f.dir, 'other-private.json'), other, 'synthetic-audit-custodian', '1']);
  assert.notEqual(run(f.verify(f.paths.snapshot, f.paths.checkpoint, other)).status, 0);
  const forged = structuredClone(f.exported);
  forged.records[0].payload.actorId = 'forged-person';
  const input = join(f.dir, 'forged-source.json');
  await save(input, forged);
  assert.notEqual(run(f.seal(join(f.dir, 'forged-sealed.json'), input)).status, 0);
});

test('CLI rejects unsafe private permissions, symlink inputs, overwrite and malformed invocation', async (t) => {
  const f = await setup(t);
  await chmod(f.paths.private, 0o644);
  assert.notEqual(run(f.seal()).status, 0);
  await chmod(f.paths.private, 0o600);
  const link = join(f.dir, 'evidence-link.json');
  await symlink(f.paths.evidence, link);
  assert.notEqual(run(f.seal(f.paths.snapshot, link)).status, 0);
  success(f.seal());
  const before = await readFile(f.paths.snapshot, 'utf8');
  assert.notEqual(run(f.seal()).status, 0);
  assert.equal(await readFile(f.paths.snapshot, 'utf8'), before);
  assert.notEqual(run(['verify']).status, 0);
});
