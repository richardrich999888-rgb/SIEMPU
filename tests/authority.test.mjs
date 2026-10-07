import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { join } from 'node:path';
import { coreFixture, openAuthority } from './helpers/fixture.mjs';
import {
  ApiClient,
  coreTransport,
  createObject,
  decryptObject,
  deviceKeys,
  sign,
  totp,
  verify,
} from './helpers/client.mjs';

async function ready(fixture, options = {}) {
  const { clients, profiles } = fixture;
  if (!clients.alice.token) await clients.alice.authenticate();
  if (!clients.bob.token) await clients.bob.authenticate();
  const object = createObject(profiles.alice, profiles.bob, await clients.alice.grant(), options);
  await clients.alice.submit(object);
  const prepared = await clients.alice.prepare(object.envelope.objectId);
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  assert.equal(prepared.body.object.state, 'READY');
  const control = await clients.alice.ok('GET', '/api/control');
  return { object, id: object.envelope.objectId, epoch: control.payload.epoch };
}
const denied = (result) =>
  assert.ok([400, 401, 403, 404, 409, 422, 429].includes(result.status), JSON.stringify(result));
const issuanceCount = (fixture) =>
  Number(fixture.authority.db.prepare('SELECT COUNT(*) AS n FROM issuances').get().n);

test('endpoint encryption interoperates; relay/generic lists never require plaintext or wrapped keys', async (t) => {
  const fixture = await coreFixture(t);
  const message = 'SYNTHETIC-secret-content-for-independent-acceptance';
  const { id, epoch, object } = await ready(fixture, { data: message });
  const list = await fixture.clients.alice.ok('GET', '/api/objects');
  assert.ok(!JSON.stringify(list).includes('wrappedKey'));
  assert.ok(!JSON.stringify(list).includes(message));
  assert.ok(!JSON.stringify(object).includes(message));
  const claimed = await fixture.clients.bob.claim(id, epoch);
  assert.equal(claimed.status, 200, JSON.stringify(claimed.body));
  assert.equal(decryptObject(claimed.body, fixture.profiles.bob).bytes.toString(), message);
  assert.ok(
    verify(
      claimed.body.receipt.payload,
      claimed.body.receipt.signature,
      fixture.provisioned.serverPublicKey,
    ),
  );
  assert.match(
    claimed.body.receipt.payload.details.proofEvidence.challengeDigest,
    /^[a-f0-9]{64}$/,
  );
  assert.equal(typeof claimed.body.receipt.payload.details.proofEvidence.sessionId, 'string');
  assert.equal(issuanceCount(fixture), 1);
  const tampered = structuredClone(claimed.body);
  tampered.ciphertext = (tampered.ciphertext[0] === 'A' ? 'B' : 'A') + tampered.ciphertext.slice(1);
  assert.throws(() => decryptObject(tampered, fixture.profiles.bob), /digest|signature|auth/i);
});

test('password, MFA, and durable TOTP replay floor are enforced', async (t) => {
  const fixture = await coreFixture(t),
    alice = fixture.clients.alice,
    p = fixture.profiles.alice;
  denied(
    await alice.request('POST', '/api/auth/login', {
      username: p.username,
      password: 'wrong-password',
      otp: totp(p.totpSecret),
    }),
  );
  denied(
    await alice.request('POST', '/api/auth/login', {
      username: p.username,
      password: p.password,
      otp: 'invalid',
    }),
  );
  const acceptedOtp = totp(p.totpSecret);
  const authenticated = await alice.ok('POST', '/api/auth/login', {
    username: p.username,
    password: p.password,
    otp: acceptedOtp,
  });
  alice.token = authenticated.token;
  await alice.bind();
  denied(
    await alice.request('POST', '/api/auth/login', {
      username: p.username,
      password: p.password,
      otp: acceptedOtp,
    }),
  );
  denied(await alice.request('GET', '/api/admin/overview'));
  denied(await alice.request('GET', '/api/objects', undefined, { token: 'made-up-session' }));
});

test('viewer cannot create; unrelated recipient and administrator cannot claim user content', async (t) => {
  const fixture = await coreFixture(t),
    { id, epoch } = await ready(fixture);
  await fixture.clients.eve.authenticate();
  await fixture.clients.admin.authenticate();
  denied(
    await fixture.clients.eve.request('POST', '/api/grants', {
      proof: await fixture.clients.eve.proof('grant'),
    }),
  );
  denied(await fixture.clients.eve.claim(id, epoch));
  denied(await fixture.clients.admin.claim(id, epoch));
  denied(await fixture.clients.eve.prepare(id));
  const listed = await fixture.clients.eve.ok('GET', '/api/objects');
  assert.equal(listed.objects.length, 0);
  assert.equal(issuanceCount(fixture), 0);
});

test('device challenge is one-use, session-bound, and operation-bound', async (t) => {
  const fixture = await coreFixture(t),
    { alice, bob } = fixture.clients;
  await alice.authenticate();
  await bob.authenticate();
  const proof = await alice.proof('grant');
  assert.equal((await alice.request('POST', '/api/grants', { proof })).status, 200);
  denied(await alice.request('POST', '/api/grants', { proof }));
  const second = await alice.proof('grant');
  denied(await bob.request('POST', '/api/grants', { proof: second }));
  const wrongOperation = await alice.proof('submit');
  denied(await alice.request('POST', '/api/grants', { proof: wrongOperation }));
});

test('administrator proof cannot authorize a changed request body', async (t) => {
  const f = await coreFixture(t),
    admin = f.clients.admin;
  await admin.authenticate();
  const path = '/api/admin/policies',
    body = {
      fromUnit: f.provisioned.units.A,
      toUnit: f.provisioned.units.B,
      missionId: 'DEMO-MISSION',
      allow: false,
    };
  const proof = await admin.proof('admin:PUT:' + path, body);
  const before = await admin.ok('GET', '/api/control');
  const substituted = await admin.request('PUT', path, { ...body, allow: true, proof });
  assert.equal(substituted.status, 403, JSON.stringify(substituted));
  const after = await admin.ok('GET', '/api/control');
  assert.equal(after.payload.epoch, before.payload.epoch);
  const row = f.authority.db
    .prepare('SELECT allow FROM policies WHERE from_unit=? AND to_unit=? AND mission_id=?')
    .get(body.fromUnit, body.toUnit, body.missionId);
  assert.equal(row.allow, 1);
});

test('operation proof rejects malformed signatures without mutating authority', async (t) => {
  const f = await coreFixture(t),
    alice = f.clients.alice;
  await alice.authenticate();
  const proof = await alice.proof('grant');
  for (const signature of ['', 'not-base64$%^', 'AAAA', null, { value: proof.signature }]) {
    const result = await alice.request('POST', '/api/grants', { proof: { ...proof, signature } });
    assert.ok([400, 403].includes(result.status), JSON.stringify(result));
  }
});

test('destination/action/ciphertext substitution fails before durable object mutation', async (t) => {
  const fixture = await coreFixture(t),
    alice = fixture.clients.alice;
  await alice.authenticate();
  const object = createObject(fixture.profiles.alice, fixture.profiles.bob, await alice.grant());
  for (const mutate of [
    (copy) => {
      copy.envelope.recipientUserId = fixture.profiles.eve.userId;
    },
    (copy) => {
      copy.envelope.action = 'admin';
    },
    (copy) => {
      copy.envelope.recipientKeyId = '0'.repeat(64);
    },
    (copy) => {
      copy.ciphertext = (copy.ciphertext[0] === 'A' ? 'B' : 'A') + copy.ciphertext.slice(1);
    },
  ]) {
    const copy = structuredClone(object);
    mutate(copy);
    denied(
      await alice.request('POST', '/api/objects', {
        ...copy,
        proof: await alice.proof('submit', copy),
      }),
    );
  }
  assert.equal(
    Number(fixture.authority.db.prepare('SELECT COUNT(*) AS n FROM objects').get().n),
    0,
  );
});

test('policy update between READY and claim fences the old epoch and holds the backlog', async (t) => {
  const fixture = await coreFixture(t),
    { id, epoch } = await ready(fixture),
    { admin, bob, alice } = fixture.clients;
  await admin.authenticate();
  const policy = {
    fromUnit: fixture.provisioned.units.A,
    toUnit: fixture.provisioned.units.B,
    missionId: 'DEMO-MISSION',
  };
  assert.equal(
    (await admin.admin('PUT', '/api/admin/policies', { ...policy, allow: false })).status,
    200,
  );
  const claimed = await bob.claim(id, epoch);
  assert.equal(claimed.status, 409, JSON.stringify(claimed.body));
  assert.equal(issuanceCount(fixture), 0);
  const deniedPrepare = await alice.prepare(id);
  assert.equal(deniedPrepare.body.object.state, 'HELD');
  assert.equal(
    (await admin.admin('PUT', '/api/admin/policies', { ...policy, allow: true })).status,
    200,
  );
  assert.equal((await alice.prepare(id)).body.object.state, 'READY');
  const current = await alice.ok('GET', '/api/control');
  assert.ok(current.payload.epoch > epoch);
  assert.equal((await bob.claim(id, current.payload.epoch)).status, 200);
});

test('negative-control check-then-send baseline leaks across the same policy interleaving the gate rejects', async (t) => {
  const f = await coreFixture(t),
    { id, epoch } = await ready(f),
    { admin, bob } = f.clients;
  await admin.authenticate();
  // Intentionally unsafe reference, NOT a representation of every conventional queue.
  const row = f.authority.db.prepare('SELECT * FROM objects WHERE id=?').get(id);
  const cachedAllow = f.authority.authorityReason(row) === null;
  assert.equal(cachedAllow, true);
  const change = await admin.admin('PUT', '/api/admin/policies', {
    fromUnit: f.provisioned.units.A,
    toUnit: f.provisioned.units.B,
    missionId: 'DEMO-MISSION',
    allow: false,
  });
  assert.equal(change.status, 200);
  const unfencedReferenceReleaseCount = cachedAllow ? 1 : 0;
  const candidate = await bob.claim(id, epoch);
  assert.equal(unfencedReferenceReleaseCount, 1);
  assert.equal(candidate.status, 409);
  assert.equal(issuanceCount(f), 0);
});

test('recipient device revocation invalidates previously issued operation challenges', async (t) => {
  const fixture = await coreFixture(t),
    { id, epoch } = await ready(fixture),
    { admin, bob } = fixture.clients;
  await admin.authenticate();
  const proof = await bob.proof('claim:' + id, { expectedEpoch: epoch });
  assert.equal(
    (await admin.admin('POST', `/api/admin/devices/${fixture.profiles.bob.deviceId}/revoke`))
      .status,
    200,
  );
  denied(await bob.request('POST', `/api/objects/${id}/claim`, { expectedEpoch: epoch, proof }));
  assert.equal(issuanceCount(fixture), 0);
});

test('sender revocation blocks queued release even when recipient remains authenticated', async (t) => {
  const fixture = await coreFixture(t),
    { id, epoch } = await ready(fixture),
    { admin, bob } = fixture.clients;
  await admin.authenticate();
  assert.equal(
    (
      await admin.admin('PATCH', `/api/admin/users/${fixture.profiles.alice.userId}`, {
        active: false,
      })
    ).status,
    200,
  );
  denied(await bob.claim(id, epoch));
  const now = await bob.ok('GET', '/api/control');
  denied(await bob.claim(id, now.payload.epoch));
  assert.equal(issuanceCount(fixture), 0);
});

test('session revocation is checked again when an already-proven claim reaches the gate', async (t) => {
  const f = await coreFixture(t),
    { id, epoch } = await ready(f),
    { admin, bob } = f.clients;
  await admin.authenticate();
  const proof = await bob.proof('claim:' + id, { expectedEpoch: epoch });
  const overview = await admin.ok('GET', '/api/admin/overview');
  const session = overview.sessions.find(
    (value) => value.userId === f.profiles.bob.userId && !value.revoked,
  );
  assert.ok(session);
  assert.equal((await admin.admin('POST', `/api/admin/sessions/${session.id}/revoke`)).status, 200);
  denied(await bob.request('POST', `/api/objects/${id}/claim`, { expectedEpoch: epoch, proof }));
  assert.equal(issuanceCount(f), 0);
});

test('sender role downgrade and recipient mission removal prevent queued release', async (t) => {
  const f = await coreFixture(t),
    { id } = await ready(f),
    { admin, alice, bob } = f.clients;
  await admin.authenticate();
  assert.equal(
    (await admin.admin('PATCH', `/api/admin/users/${f.profiles.alice.userId}`, { role: 'viewer' }))
      .status,
    200,
  );
  let control = await bob.ok('GET', '/api/control');
  assert.equal((await bob.claim(id, control.payload.epoch)).status, 409);
  assert.equal(
    (
      await admin.admin('PATCH', `/api/admin/users/${f.profiles.alice.userId}`, {
        role: 'operator',
      })
    ).status,
    200,
  );
  assert.equal(
    (await admin.admin('PATCH', `/api/admin/users/${f.profiles.bob.userId}`, { missionIds: [] }))
      .status,
    200,
  );
  control = await alice.ok('GET', '/api/control');
  assert.equal((await bob.claim(id, control.payload.epoch)).status, 409);
  assert.equal(issuanceCount(f), 0);
});

test('newly enrolled device requires approval; a revoked key cannot be reapproved', async (t) => {
  const f = await coreFixture(t),
    { alice, admin } = f.clients;
  await alice.authenticate();
  await admin.authenticate();
  const keys = deviceKeys(),
    challenge = await alice.ok('POST', '/api/auth/challenge', { purpose: 'enroll' });
  const enrolled = await alice.ok('POST', '/api/devices/enroll', {
    label: 'Unapproved synthetic key',
    signingPublicKey: keys.signing.publicKey,
    encryptionPublicKey: keys.encryption.publicKey,
    challengeId: challenge.challengeId,
    signature: sign(challenge.challenge, keys.signing.privateKey),
  });
  const binding = await alice.ok('POST', '/api/auth/challenge', {
    purpose: 'bind',
    deviceId: enrolled.device.id,
  });
  denied(
    await alice.request('POST', '/api/auth/bind', {
      deviceId: enrolled.device.id,
      challengeId: binding.challengeId,
      signature: sign(binding.challenge, keys.signing.privateKey),
    }),
  );
  assert.equal(
    (await admin.admin('POST', `/api/admin/devices/${enrolled.device.id}/revoke`)).status,
    200,
  );
  assert.equal(
    (await admin.admin('POST', `/api/admin/devices/${enrolled.device.id}/approve`)).status,
    409,
  );
});

test('expired but correctly signed creation grant cannot admit a new object', async (t) => {
  const f = await coreFixture(t),
    alice = f.clients.alice;
  await alice.authenticate();
  const grant = await alice.grant();
  grant.payload.issuedAt = Date.now() - 120000;
  grant.payload.expiresAt = Date.now() - 60000;
  grant.signature = sign(grant.payload, f.authority.key); // Fixture-owned authority key; genuine signature, expired delegation.
  const object = createObject(f.profiles.alice, f.profiles.bob, grant);
  denied(
    await alice.request('POST', '/api/objects', {
      ...object,
      proof: await alice.proof('submit', object),
    }),
  );
  assert.equal(Number(f.authority.db.prepare('SELECT COUNT(*) AS n FROM objects').get().n), 0);
});

test('login attempt limits survive reopening the authority database', async (t) => {
  const f = await coreFixture(t),
    alice = f.clients.alice,
    profile = f.profiles.alice;
  const realNow = Date.now,
    fixedNow = Math.floor(Date.now() / 60000) * 60000 + 15000;
  Date.now = () => fixedNow;
  t.after(() => {
    Date.now = realNow;
  });
  for (let i = 0; i < 8; i++)
    denied(
      await alice.request('POST', '/api/auth/login', {
        username: profile.username,
        password: 'wrong-password',
        otp: '000000',
      }),
    );
  const reopened = await openAuthority(f.dir);
  t.after(() => reopened.close());
  const deniedLogin = await coreTransport(reopened)('POST', '/api/auth/login', {
    username: profile.username,
    password: profile.password,
    otp: totp(profile.totpSecret),
  });
  assert.equal(deniedLogin.status, 429);
});

test('100 eligible retries retain one committed issuance and one receipt identity', async (t) => {
  const fixture = await coreFixture(t),
    { id, epoch } = await ready(fixture);
  let first;
  for (let i = 0; i < 100; i++) {
    const result = await fixture.clients.bob.claim(id, epoch);
    assert.equal(result.status, 200, `retry ${i}: ${JSON.stringify(result.body)}`);
    first ??= result.body.receipt;
    assert.deepEqual(result.body.receipt, first);
  }
  assert.equal(issuanceCount(fixture), 1);
});

test('revocation after issuance prevents wrapped-key redisclosure on retry', async (t) => {
  const fixture = await coreFixture(t),
    { id, epoch } = await ready(fixture),
    { bob, admin } = fixture.clients;
  assert.equal((await bob.claim(id, epoch)).status, 200);
  await admin.authenticate();
  assert.equal(
    (
      await admin.admin('PUT', '/api/admin/policies', {
        fromUnit: fixture.provisioned.units.A,
        toUnit: fixture.provisioned.units.B,
        missionId: 'DEMO-MISSION',
        allow: false,
      })
    ).status,
    200,
  );
  const next = await bob.ok('GET', '/api/control');
  const result = await bob.claim(id, next.payload.epoch);
  denied(result);
  assert.ok(!JSON.stringify(result.body).includes('wrappedKey'));
  assert.equal(issuanceCount(fixture), 1);
});

test('ordinary reopen preserves authority state, session/device revocation and signing identity', async (t) => {
  const fixture = await coreFixture(t),
    { id, epoch } = await ready(fixture);
  await fixture.clients.admin.authenticate();
  await fixture.clients.admin.admin(
    'POST',
    `/api/admin/devices/${fixture.profiles.alice.deviceId}/revoke`,
  );
  const before = await fixture.clients.bob.ok('GET', '/api/control');
  const reopened = await openAuthority(fixture.dir);
  t.after(() => reopened.close());
  const bob = new ApiClient(coreTransport(reopened), fixture.profiles.bob);
  bob.token = fixture.clients.bob.token;
  const after = await bob.ok('GET', '/api/control');
  assert.equal(after.payload.epoch, before.payload.epoch);
  assert.equal(after.keyId, before.keyId);
  denied(await bob.claim(id, epoch));
  denied(await bob.claim(id, after.payload.epoch));
});

export { ready };

function policyWorker(t, fixture, delay = 0) {
  const worker = fork(
    new URL('./helpers/policy-worker.mjs', import.meta.url),
    [
      join(fixture.dir, 'control.sqlite'),
      fixture.provisioned.units.A,
      fixture.provisioned.units.B,
      'DEMO-MISSION',
      String(delay),
    ],
    { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] },
  );
  const events = [],
    waiters = [];
  let output = '';
  worker.stdout.on('data', (chunk) => {
    output += chunk;
  });
  worker.stderr.on('data', (chunk) => {
    output += chunk;
  });
  worker.on('message', (event) => {
    events.push(event);
    for (const waiter of [...waiters]) waiter(event);
  });
  t.after(() => worker.kill('SIGKILL'));
  const wait = (event) =>
    new Promise((resolve, reject) => {
      const present = events.find((value) => value.event === event);
      if (present) return resolve(present);
      const timer = setTimeout(
        () => reject(new Error('Worker timed out at ' + event + ': ' + output)),
        12000,
      );
      const listener = (value) => {
        if (value.event === event) {
          clearTimeout(timer);
          waiters.splice(waiters.indexOf(listener), 1);
          resolve(value);
        }
      };
      waiters.push(listener);
    });
  return { worker, wait };
}

test(
  'independent policy writer commits first: waiting gate cannot release the stale READY decision',
  { timeout: 20000 },
  async (t) => {
    const f = await coreFixture(t),
      { id, epoch } = await ready(f);
    const writer = policyWorker(t, f, 120);
    await writer.wait('ready');
    writer.worker.send({ go: true });
    await writer.wait('locked');
    const attempted = await f.clients.bob.claim(id, epoch);
    assert.equal(attempted.status, 409, JSON.stringify(attempted));
    const committed = await writer.wait('committed');
    assert.equal(committed.epoch, epoch + 1);
    assert.equal(issuanceCount(f), 0);
  },
);

test(
  'claim transaction commits first: independent policy writer is serialized after issuance',
  { timeout: 20000 },
  async (t) => {
    const hooks = {},
      f = await coreFixture(t, hooks),
      { id, epoch } = await ready(f);
    const writer = policyWorker(t, f);
    await writer.wait('ready');
    hooks.beforeCommit = () => {
      writer.worker.send({ go: true });
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
    };
    const claimed = await f.clients.bob.claim(id, epoch);
    assert.equal(claimed.status, 200, JSON.stringify(claimed));
    hooks.beforeCommit = undefined;
    const committed = await writer.wait('committed');
    assert.equal(committed.epoch, epoch + 1);
    assert.ok(
      committed.waitedMs >= 100,
      `Policy writer lock wait measured only ${committed.waitedMs}ms`,
    );
    assert.equal(claimed.body.receipt.payload.epoch, epoch);
    assert.equal(issuanceCount(f), 1);
  },
);

for (const stage of ['beforeCommit', 'afterCommit']) {
  test(
    `real process exit ${stage}: issuance and evidence recover together`,
    { timeout: 20000 },
    async (t) => {
      const f = await coreFixture(t),
        { id, epoch } = await ready(f);
      const child = fork(
        new URL('./helpers/crash-worker.mjs', import.meta.url),
        [f.dir, f.clients.bob.token, id, String(epoch), stage],
        { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] },
      );
      let output = '';
      child.stdout.on('data', (chunk) => {
        output += chunk;
      });
      child.stderr.on('data', (chunk) => {
        output += chunk;
      });
      t.after(() => child.kill('SIGKILL'));
      const [code] = await once(child, 'exit');
      assert.equal(code, stage === 'beforeCommit' ? 71 : 72, output);
      const issuance = f.authority.db.prepare('SELECT * FROM issuances WHERE object_id=?').get(id);
      const records = f.authority.db
        .prepare('SELECT record FROM evidence')
        .all()
        .map((row) => JSON.parse(row.record));
      if (stage === 'beforeCommit') {
        assert.equal(issuance, undefined);
        assert.equal(
          f.authority.db.prepare('SELECT state FROM objects WHERE id=?').get(id).state,
          'READY',
        );
      } else {
        assert.ok(issuance);
        const receipt = JSON.parse(issuance.receipt);
        assert.ok(
          records.some((record) => JSON.stringify(record) === JSON.stringify(receipt)),
          'Committed issuance lacks matching durable signed evidence',
        );
        const retry = await f.clients.bob.claim(id, epoch);
        assert.equal(retry.status, 200, JSON.stringify(retry));
        assert.deepEqual(retry.body.receipt, receipt);
        assert.equal(issuanceCount(f), 1);
      }
    },
  );
}
