import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { recoveryFixture, getJson } from './helpers/recovery-rehearsal.mjs';
import { ApiClient, coreTransport, createObject } from './helpers/client.mjs';
import { Authority } from '../services/control/core.mjs';
import { createRecoveryGuard } from '../services/evidence/custody.mjs';
import {
  stageGuardedRecovery,
  verifyQuarantinedRecovery,
  reconcileRecoveryHandover,
} from '../scripts/guarded-recovery.mjs';

function noNewIssuance(f, generation = 1) {
  for (const dir of [f.source, f.request.destination]) {
    if (!fs.existsSync(join(dir, 'control.sqlite'))) continue;
    const db = new DatabaseSync(join(dir, 'control.sqlite'), { readOnly: true });
    try {
      assert.equal(db.prepare('SELECT count(*) n FROM issuances').get().n, 1);
    } finally {
      db.close();
    }
  }
  const c = f.openCustody();
  try {
    assert.equal(c.db.prepare('SELECT generation FROM writer_fence').get().generation, generation);
    assert.equal(c.db.prepare('SELECT count(*) n FROM fence_history').get().n, generation);
  } finally {
    c.close();
  }
}
const stage = (f) => stageGuardedRecovery(f.request, f.config);

test('actual SQLite capacity exhaustion rolls back writer handover without issuing a key', async (t) => {
  const f = await recoveryFixture(t);
  await stage(f);
  const c = f.openCustody();
  try {
    c.db.exec('CREATE TABLE capacity_probe(data BLOB)');
    const pages = c.db.prepare('PRAGMA page_count').get().page_count;
    c.db.exec(`PRAGMA max_page_count=${pages}`);
    c.db.exec(
      'CREATE TRIGGER capacity_fault BEFORE INSERT ON fence_history BEGIN INSERT INTO capacity_probe VALUES(zeroblob(1048576)); END',
    );
    assert.throws(
      () => reconcileRecoveryHandover(c, f.plan, f.approval, f.trust, { perform: true }),
      /database or disk is full/,
    );
    assert.equal(c.db.prepare('SELECT generation FROM writer_fence').get().generation, 1);
    assert.equal(c.db.prepare('SELECT count(*) n FROM fence_history').get().n, 1);
  } finally {
    c.close();
  }
  noNewIssuance(f);
});

test('quarantine verification cannot authorize activation or transfer writer custody', async (t) => {
  const f = await recoveryFixture(t);
  const staged = await stage(f);
  assert.equal(staged.recoveryState, 'QUARANTINED');
  assert.equal(staged.activationAuthorised, false);
  const verified = verifyQuarantinedRecovery(f.request, f.config);
  assert.equal(verified.recoveryState, 'VERIFIED');
  assert.equal(verified.activationAuthorised, false);
  assert.equal(verified.planDigest, f.config.expectedPlanDigest);
  noNewIssuance(f);
  for (const options of [
    { ...f.config, expectedPlanDigest: undefined },
    { ...f.config, approval: undefined },
    { ...f.config, approval: { ...f.approval, signature: 'invalid' } },
  ]) {
    assert.throws(() => verifyQuarantinedRecovery(f.request, options));
    noNewIssuance(f);
  }
  const db = new DatabaseSync(join(f.request.destination, 'control.sqlite'));
  db.exec("UPDATE users SET missions='[]' WHERE id=(SELECT id FROM users LIMIT 1)");
  db.close();
  assert.throws(() => verifyQuarantinedRecovery(f.request, f.config), /AUTHORIZATION_COMMIT/);
  noNewIssuance(f);
});

for (const fault of ['partial restore write', 'review journal write', 'parent fsync'])
  test(`${fault}: I/O failure never grants authority`, async (t) => {
    const f = await recoveryFixture(t);
    const originalWrite = fs.writeFileSync,
      originalSync = fs.fsyncSync;
    let injected = false;
    fs.writeFileSync = function (path, bytes, options) {
      const p = String(path);
      const target =
        fault === 'partial restore write'
          ? p.startsWith(f.root) && p.includes('.siepmu-restore-') && p.endsWith('control.sqlite')
          : fault === 'review journal write' &&
            p.startsWith(f.root) &&
            p.endsWith('recovery-plan.json');
      if (target) {
        injected = true;
        originalWrite(path, Buffer.from(bytes).subarray(0, 16), options);
        throw Object.assign(new Error('SYNTHETIC_ENOSPC_AFTER_PARTIAL_WRITE'), { code: 'ENOSPC' });
      }
      return originalWrite(path, bytes, options);
    };
    fs.fsyncSync = function (fd) {
      if (fault === 'parent fsync' && fs.realpathSync(`/proc/self/fd/${fd}`) === f.root) {
        injected = true;
        throw Object.assign(new Error('SYNTHETIC_PARENT_FSYNC_EIO'), { code: 'EIO' });
      }
      return originalSync(fd);
    };
    syncBuiltinESMExports();
    try {
      await assert.rejects(stage(f), /SYNTHETIC_(ENOSPC|PARENT_FSYNC)/);
    } finally {
      fs.writeFileSync = originalWrite;
      fs.fsyncSync = originalSync;
      syncBuiltinESMExports();
    }
    assert.equal(injected, true);
    noNewIssuance(f);
    if (fault === 'parent fsync') {
      assert.equal(fs.existsSync(f.request.destination), true);
      assert.equal(verifyQuarantinedRecovery(f.request, f.config).activationAuthorised, false);
      await assert.rejects(stage(f), /DESTINATION_EXISTS/);
    } else {
      assert.equal(fs.existsSync(f.request.destination), false);
      assert.deepEqual(
        fs.readdirSync(f.root).filter((n) => n.startsWith('.siepmu-recovery-')),
        [],
      );
      assert.equal((await stage(f)).recoveryState, 'QUARANTINED');
    }
    noNewIssuance(f);
  });

for (const kind of [
  'revoked user',
  'revoked device',
  'removed mission',
  'changed duty role',
  'expired session',
])
  test(`${kind} after verified restore blocks fresh key issuance`, async (t) => {
    const f = await recoveryFixture(t);
    await stage(f);
    assert.equal(verifyQuarantinedRecovery(f.request, f.config).activationAuthorised, false);
    const c = f.openCustody();
    let a;
    const relay = new DatabaseSync(join(f.request.destination, 'relay/relay.sqlite'));
    try {
      reconcileRecoveryHandover(c, f.plan, f.approval, f.trust, { perform: true });
      a = new Authority({
        dbPath: join(f.request.destination, 'control.sqlite'),
        signingKey: getJson(join(f.request.destination, 'server-key.json')),
        masterKey: fs.readFileSync(join(f.request.destination, 'master.key')),
        recoveryGuard: createRecoveryGuard({
          custodianKey: f.trust.custodianKey,
          writer: f.config.writer,
          exchange: (r) => c.accept(r),
        }),
        relay: {
          putBlob: async (digest, bytes) =>
            relay
              .prepare('INSERT INTO blobs VALUES(?,?,?,?)')
              .run(digest, bytes, bytes.length, Date.now()),
          getBlob: async (digest) =>
            Buffer.from(
              relay.prepare('SELECT ciphertext FROM blobs WHERE hash=?').get(digest).ciphertext,
            ),
        },
      });
      const alice = new ApiClient(coreTransport(a), f.config.profiles.alice);
      const bob = new ApiClient(coreTransport(a), f.config.profiles.bob);
      alice.token = f.config.tokens.alice;
      bob.token = f.config.tokens.bob;
      const object = createObject(
        f.config.profiles.alice,
        f.config.profiles.bob,
        await alice.grant(),
        {
          context: { schemaVersion: 2, messagePriority: 'ROUTINE', messageDomain: 'GENERAL' },
        },
      );
      await alice.submit(object);
      const expectedEpoch = a.epoch().epoch + 1;
      let proof = await bob.proof('claim:' + object.envelope.objectId, { expectedEpoch });
      a.tx(() => {
        const id = f.config.profiles.bob.userId;
        if (kind === 'revoked user') a.run('UPDATE users SET active=0 WHERE id=?', id);
        if (kind === 'revoked device')
          a.run("UPDATE devices SET status='revoked' WHERE id=?", f.config.profiles.bob.deviceId);
        if (kind === 'removed mission') a.run("UPDATE users SET missions='[]' WHERE id=?", id);
        if (kind === 'changed duty role')
          a.run("UPDATE users SET duty_role='INTELLIGENCE_ANALYST' WHERE id=?", id);
        if (kind === 'expired session')
          a.run('UPDATE sessions SET expires_at=0 WHERE user_id=?', id);
        a.run('UPDATE authority SET epoch=epoch+1,revocation_version=revocation_version+1');
        a.event('SYNTHETIC_POST_RECOVERY_POLICY_CHANGE', 'synthetic');
      });
      if (kind === 'removed mission' || kind === 'changed duty role')
        proof = await bob.proof('claim:' + object.envelope.objectId, { expectedEpoch });
      const response = await bob.request('POST', `/api/objects/${object.envelope.objectId}/claim`, {
        expectedEpoch,
        proof,
      });
      const expectedStatus = {
        'revoked user': 401,
        'revoked device': 403,
        'removed mission': 409,
        'changed duty role': 404,
        'expired session': 401,
      };
      assert.equal(response.status, expectedStatus[kind], JSON.stringify(response));
      assert.equal(a.get('SELECT count(*) n FROM issuances').n, 1);
      assert.equal(
        a.get('SELECT count(*) n FROM issuances WHERE object_id=?', object.envelope.objectId).n,
        0,
      );
      assert.equal(response.body?.envelope?.wrappedKey, undefined);
    } finally {
      a?.close();
      relay.close();
      c.close();
    }
    noNewIssuance(f, 2);
  });
