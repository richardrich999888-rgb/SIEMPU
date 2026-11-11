import test from 'node:test';
import assert from 'node:assert/strict';
import {
  recoveryFixture,
  runRecoveryFixture,
  putJson,
  getJson,
} from './helpers/recovery-rehearsal.mjs';
for (const migrated of [false, true])
  test(`${migrated ? 'migrated' : 'sealed'} guarded recovery and encrypted exchange`, async (t) => {
    const f = await recoveryFixture(t, { migrated });
    assert.equal((await runRecoveryFixture(f.config)).outcome, 'PASS');
  });
import {
  readFileSync,
  readdirSync,
  existsSync,
  writeFileSync,
  rmSync,
  chmodSync,
  symlinkSync,
} from 'node:fs';
import { join } from 'node:path';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { hash, canonical, packet } from '../services/control/primitives.mjs';
import {
  inspectGuardedRecovery,
  stageGuardedRecovery,
  reviewRecoveryResume,
  verifyRecoveryWorkingSet,
  reconcileRecoveryHandover,
} from '../scripts/guarded-recovery.mjs';
import { backup } from '../scripts/backup.mjs';
import { Authority } from '../services/control/core.mjs';
import { createRecoveryGuard } from '../services/evidence/custody.mjs';
import { authorizationDigest } from '../services/evidence/authorization-state.mjs';
import { pair } from './helpers/client.mjs';
const inspect = (f) => inspectGuardedRecovery(f.request, { passphrase: f.passphrase });
const edit = (path, fn) => {
  const db = new DatabaseSync(path);
  try {
    return fn(db);
  } finally {
    db.close();
  }
};
const noStaging = (f) =>
  assert.deepEqual(
    readdirSync(f.root).filter((n) => n.startsWith('.siepmu-recovery-')),
    [],
  );
const reviewed = (f) => reviewRecoveryResume(f.request, f.config);
const stage = (f) =>
  stageGuardedRecovery(f.request, { passphrase: f.passphrase, approval: f.approval });
test('independent evidence cannot be omitted, forged, substituted or silently repinned', async (t) => {
  const f = await recoveryFixture(t),
    original = structuredClone(f.trust);
  const cases = [
    [
      'checkpoint',
      (v) => {
        v.checkpoint = null;
      },
    ],
    [
      'monitor witness',
      (v) => {
        v.monitorWitness = null;
      },
    ],
    [
      'monitor signature',
      (v) => {
        v.monitorWitness.signature = 'bad';
      },
    ],
    [
      'custody receipt',
      (v) => {
        v.lease = null;
      },
    ],
    [
      'custody signature',
      (v) => {
        v.lease.signature = 'bad';
      },
    ],
    [
      'manifest pin',
      (v) => {
        v.manifestSha256 = '0'.repeat(64);
      },
    ],
    [
      'policy',
      (v) => {
        v.policyDigest = 'f'.repeat(64);
      },
    ],
    [
      'reviewer separation',
      (v) => {
        v.reviewerKey = v.authorityKey;
      },
    ],
    [
      'unknown field',
      (v) => {
        v.allowBootstrap = true;
      },
    ],
    [
      'monitor pin',
      (v) => {
        v.monitorWitnessSha256 = '0'.repeat(64);
      },
    ],
  ];
  for (const [name, mutate] of cases)
    await t.test(name, () => {
      const v = structuredClone(original);
      mutate(v);
      putJson(f.request.trust, v);
      assert.throws(() => inspect(f));
      noStaging(f);
    });
  putJson(f.request.trust, original);
  assert.throws(() => inspectGuardedRecovery(f.request, { passphrase: 'wrong passphrase' }));
});
test('operator review is required and bound to complete plan and expiry', async (t) => {
  const f = await recoveryFixture(t);
  for (const kind of [
    'absent',
    'forged',
    'expired',
    'policy unchecked',
    'writers unchecked',
    'wrong plan',
  ])
    await t.test(kind, async () => {
      let approval = structuredClone(f.approval);
      const p = approval.payload;
      if (kind === 'absent') approval = undefined;
      else if (kind === 'forged') approval.signature = 'bad';
      else {
        if (kind === 'expired') p.expiresAt = 0;
        if (kind === 'policy unchecked') p.currentPolicyConfirmed = false;
        if (kind === 'writers unchecked') p.writersStoppedConfirmed = false;
        if (kind === 'wrong plan') p.planDigest = '0'.repeat(64);
        approval = packet(f.reviewer.privateKey, p);
      }
      await assert.rejects(
        stageGuardedRecovery(f.request, { passphrase: f.passphrase, approval }),
        /OPERATOR_REVIEW/,
      );
      noStaging(f);
    });
  await assert.rejects(
    stageGuardedRecovery(
      { ...f.request, destination: join(f.root, 'other') },
      { passphrase: f.passphrase, approval: f.approval },
    ),
    /OPERATOR_REVIEW/,
  );
  putJson(f.request.writerPublicKey, pair().publicKey);
  await assert.rejects(stage(f), /OPERATOR_REVIEW/);
});
test('signed divergent history and selective rollback remain refused even with new authority signatures', async (t) => {
  for (const kind of [
    'fork',
    'missing seal',
    'selective rollback',
    'forged seal',
    'unsupported policy',
  ])
    await t.test(kind, async (st) => {
      const f = await recoveryFixture(st),
        key = getJson(join(f.source, 'server-key.json'));
      edit(join(f.source, 'control.sqlite'), (db) => {
        if (kind === 'missing seal') return db.exec('DELETE FROM authorization_commit');
        const seal = JSON.parse(db.prepare('SELECT seal FROM authorization_commit').get().seal);
        if (kind === 'fork') {
          const row = db.prepare('SELECT * FROM evidence ORDER BY sequence DESC LIMIT 1').get();
          const record = packet(key, {
            ...JSON.parse(row.record).payload,
            eventType: 'SYNTHETIC_FORK',
          });
          db.prepare('UPDATE evidence SET record=?,hash=? WHERE sequence=?').run(
            canonical(record),
            hash(canonical(record)),
            row.sequence,
          );
          seal.payload.headHash = hash(canonical(record));
        } else {
          if (kind === 'unsupported policy') {
            const policy = JSON.parse(db.prepare('SELECT value FROM crypto_policy').get().value);
            policy.newSuites = [{ providerId: 'unknown-provider', suiteId: 'unknown-suite' }];
            db.prepare('UPDATE crypto_policy SET value=?').run(canonical(policy));
            f.trust.policyDigest = hash(canonical(policy));
          } else
            db.prepare('UPDATE users SET active=1 WHERE id=?').run(f.config.profiles.bravo.userId);
          if (kind === 'selective rollback') return;
          seal.payload.stateDigest = authorizationDigest({
            all: (sql) => db.prepare(sql).all(),
            epoch: () => db.prepare('SELECT * FROM authority WHERE id=1').get(),
            crypto: { allowPqcLab: false },
          });
          if (kind === 'unsupported policy') {
            const lease = packet(f.custodian.privateKey, {
              ...f.trust.lease.payload.lease.payload,
              stateDigest: seal.payload.stateDigest,
            });
            f.trust.lease = packet(f.custodian.privateKey, { ...f.trust.lease.payload, lease });
          }
        }
        db.prepare('UPDATE authorization_commit SET seal=?').run(
          canonical(packet(key, seal.payload)),
        );
      });
      const path = join(f.root, 'tampered.backup'),
        { manifest } = backup(f.source, path, f.passphrase);
      f.request.archive = path;
      f.trust.manifestSha256 = hash(canonical(manifest));
      putJson(f.request.trust, f.trust);
      assert.throws(
        () => inspect(f),
        kind === 'fork'
          ? /checkpoint/
          : kind === 'unsupported policy'
            ? /Unsupported cryptographic suite/
            : kind === 'forged seal'
              ? /CUSTODY_STATE/
              : /AUTHORIZATION_COMMIT/,
      );
      assert.equal(existsSync(f.request.destination), false);
      noStaging(f);
    });
});
test('independently pinned but internally inconsistent relay and monitoring snapshots fail', async (t) => {
  for (const kind of [
    'missing ciphertext',
    'corrupt ciphertext',
    'missing telemetry',
    'altered telemetry',
    'forged acknowledgement',
    'extra trigger',
    'misbound detection',
  ])
    await t.test(kind, async (st) => {
      const f = await recoveryFixture(st);
      if (kind.includes('ciphertext')) {
        edit(join(f.source, 'relay/relay.sqlite'), (db) =>
          db.exec(
            kind === 'missing ciphertext'
              ? 'DELETE FROM blobs'
              : 'UPDATE blobs SET ciphertext=zeroblob(size)',
          ),
        );
        const path = join(f.root, 'bad.backup'),
          { manifest } = backup(f.source, path, f.passphrase);
        f.request.archive = path;
        f.trust.manifestSha256 = hash(canonical(manifest));
      } else {
        edit(f.request.monitor, (db) => {
          if (kind === 'misbound detection')
            return db.prepare('INSERT INTO detections VALUES(?,?,?,NULL)').run(
              'a'.repeat(64),
              1,
              canonical(
                packet(f.collector.privateKey, {
                  kind: 'SIEPMU_THREAT_SIGNAL',
                  detectionId: 'b'.repeat(64),
                  detectedAt: 1,
                  sourceId: hash(canonical(f.trust.authorityKey)),
                }),
              ),
            );
          db.exec(
            {
              'missing telemetry': 'DELETE FROM events WHERE id=(SELECT id FROM events LIMIT 1)',
              'altered telemetry':
                "UPDATE events SET event='{}' WHERE id=(SELECT id FROM events LIMIT 1)",
              'forged acknowledgement': "UPDATE events SET ack='{}' WHERE ack IS NOT NULL",
              'extra trigger':
                'CREATE TRIGGER poison AFTER INSERT ON events BEGIN DELETE FROM events; END',
            }[kind],
          );
        });
        f.trust.monitorWitness = packet(f.collector.privateKey, {
          ...f.trust.monitorWitness.payload,
          databaseSha256: hash(readFileSync(f.request.monitor)),
        });
        f.trust.monitorWitnessSha256 = hash(canonical(f.trust.monitorWitness));
      }
      putJson(f.request.trust, f.trust);
      assert.throws(() => inspect(f), /RECOVERY_(RELAY|MONITOR|AUXILIARY)/);
      noStaging(f);
    });
});
test('missing, conflicting or advanced custody cannot be reset', async (t) => {
  for (const kind of [
    'missing anchor',
    'changed head',
    'changed generation',
    'bootstrap enabled',
    'previous writer',
  ])
    await t.test(kind, async (st) => {
      const f = await recoveryFixture(st),
        c = f.openCustody();
      try {
        if (kind === 'missing anchor') c.db.exec('DELETE FROM anchor');
        if (kind === 'changed head') c.db.prepare('UPDATE anchor SET state=?').run('f'.repeat(64));
        if (kind === 'changed generation') c.db.exec('UPDATE writer_fence SET generation=3');
        if (kind === 'previous writer')
          c.db.prepare('UPDATE writer_fence SET public_key=?').run(canonical(pair().publicKey));
      } finally {
        c.close();
      }
      if (kind === 'bootstrap enabled') f.config.custodyConfig.allowBootstrap = true;
      await assert.rejects(
        runRecoveryFixture(f.config),
        /ANCHOR|WRITER_CHANGED|INDEPENDENT_CUSTODY/,
      );
      const check = f.openCustody();
      try {
        assert.equal(check.db.prepare('SELECT count(*) n FROM fence_history').get().n, 1);
      } finally {
        check.close();
      }
    });
});
test('a genuine newer custody anchor rejects an authentic old recovery set', async (t) => {
  const f = await recoveryFixture(t),
    c = f.openCustody();
  const a = new Authority({
    dbPath: join(f.source, 'control.sqlite'),
    signingKey: getJson(join(f.source, 'server-key.json')),
    masterKey: readFileSync(join(f.source, 'master.key')),
    recoveryGuard: createRecoveryGuard({
      custodianKey: f.trust.custodianKey,
      writer: f.config.oldWriter,
      exchange: (r) => c.accept(r),
    }),
  });
  try {
    a.tx(() => a.event('NEWER_HISTORY', 'synthetic'));
    await a.recoveryGuard.authorize(a);
  } finally {
    a.close();
    c.close();
  }
  await assert.rejects(runRecoveryFixture(f.config), /ANCHOR/);
});
test('lost custody database is refused without recreating it', async (t) => {
  const f = await recoveryFixture(t);
  rmSync(f.config.custodyConfig.database);
  await assert.rejects(runRecoveryFixture(f.config), /ENOENT/);
  assert.equal(existsSync(f.config.custodyConfig.database), false);
});
test('custody outage quarantines; resume obtains a new lease', async (t) => {
  const f = await recoveryFixture(t);
  await assert.rejects(runRecoveryFixture(f.config, { exchangeFailure: true }), /Recovery trust/);
  assert.equal((await runRecoveryFixture(f.config, { resume: true })).outcome, 'PASS');
});
test('lost handover response reconciles exactly once', async (t) => {
  const f = await recoveryFixture(t);
  await assert.rejects(
    runRecoveryFixture(f.config, { loseHandoverResponse: true }),
    /LOST_HANDOVER/,
  );
  assert.equal((await runRecoveryFixture(f.config, { resume: true })).outcome, 'PASS');
  const c = f.openCustody();
  try {
    assert.equal(c.db.prepare('SELECT count(*) n FROM fence_history').get().n, 2);
  } finally {
    c.close();
  }
});
test('missing or forged handover history cannot be replaced by a local marker', async (t) => {
  for (const kind of ['missing', 'forged'])
    await t.test(kind, async (st) => {
      const f = await recoveryFixture(st);
      await assert.rejects(runRecoveryFixture(f.config, { loseHandoverResponse: true }));
      const c = f.openCustody();
      try {
        c.db.exec(
          kind === 'missing'
            ? 'DELETE FROM fence_history WHERE generation=2'
            : "UPDATE fence_history SET receipt='{}' WHERE generation=2",
        );
      } finally {
        c.close();
      }
      await assert.rejects(
        runRecoveryFixture(f.config, { resume: true }),
        /HANDOVER_EVIDENCE_MISSING|HANDOVER_RECEIPT/,
      );
    });
});
test('resume refuses changed keys, metadata, counters, nonce rows, monitoring and journal', async (t) => {
  for (const kind of ['key', 'metadata', 'counter', 'nonce', 'monitor', 'journal'])
    await t.test(kind, async (st) => {
      const f = await recoveryFixture(st);
      await stage(f);
      if (kind === 'key')
        writeFileSync(join(f.request.destination, 'master.key'), Buffer.alloc(32));
      if (kind === 'metadata')
        edit(join(f.request.destination, 'control.sqlite'), (db) =>
          db.exec("UPDATE units SET name=name||'-changed'"),
        );
      if (kind === 'counter')
        edit(join(f.request.destination, 'control.sqlite'), (db) =>
          db.exec("INSERT INTO counters VALUES('forged',999)"),
        );
      if (kind === 'nonce')
        edit(join(f.request.destination, 'relay/relay.sqlite'), (db) =>
          db.exec('DELETE FROM workload_nonces'),
        );
      if (kind === 'monitor') rmSync(join(f.request.destination, 'monitor/collector.sqlite'));
      if (kind === 'journal') putJson(join(f.request.destination, 'recovery-plan.json'), {});
      await assert.rejects(runRecoveryFixture(f.config, { resume: true }));
    });
});
test('resume needs independent plan, current review and explicit handover; post-serving replay is refused', async (t) => {
  const f = await recoveryFixture(t);
  await stage(f);
  assert.throws(
    () => reviewRecoveryResume(f.request, { ...f.config, expectedPlanDigest: undefined }),
    /RETAINED_PLAN/,
  );
  assert.throws(
    () => reviewRecoveryResume(f.request, { ...f.config, approval: undefined }),
    /OPERATOR_REVIEW/,
  );
  const { plan, trust } = reviewed(f),
    c = f.openCustody();
  try {
    assert.throws(() => reconcileRecoveryHandover(c, plan, f.approval, trust), /HANDOVER_REQUIRED/);
    reconcileRecoveryHandover(c, plan, f.approval, trust, { perform: true });
  } finally {
    c.close();
  }
  await assert.rejects(stage(f), /DESTINATION_EXISTS/);
  assert.equal((await runRecoveryFixture(f.config, { resume: true })).outcome, 'PASS');
  assert.throws(() => verifyRecoveryWorkingSet(plan, trust), /REVIEW_SUPERSEDED/);
  await assert.rejects(runRecoveryFixture(f.config, { resume: true }), /REVIEW_SUPERSEDED/);
});
test('private inputs, monitor sidecars, source preservation and failed staging cleanup', async (t) => {
  const f = await recoveryFixture(t),
    bytes = readFileSync(f.request.monitor),
    archive = readFileSync(f.request.archive);
  chmodSync(f.request.monitor, 0o644);
  assert.throws(() => inspect(f), /PRIVATE_FILE/);
  chmodSync(f.request.monitor, 0o600);
  writeFileSync(f.request.monitor + '-wal', 'bad');
  assert.throws(() => inspect(f), /OFFLINE_MONITOR/);
  rmSync(f.request.monitor + '-wal');
  const link = join(f.root, 'link');
  symlinkSync(f.request.monitor, link);
  assert.throws(() =>
    inspectGuardedRecovery({ ...f.request, monitor: link }, { passphrase: f.passphrase }),
  );
  await assert.rejects(
    stageGuardedRecovery(f.request, {
      passphrase: f.passphrase,
      approval: f.approval,
      onPhase: () => {
        throw new Error('SYNTHETIC_DISK_FAILURE');
      },
    }),
    /DISK_FAILURE/,
  );
  assert.deepEqual(readFileSync(f.request.monitor), bytes);
  assert.deepEqual(readFileSync(f.request.archive), archive);
  assert.equal(existsSync(f.request.destination), false);
  noStaging(f);
});
for (const phase of ['verified', 'handover-committed', 'leased', 'before-message'])
  test(`expired review at ${phase} prevents protected work`, async (t) => {
    const f = await recoveryFixture(t),
      now = Date.now;
    try {
      await assert.rejects(
        runRecoveryFixture(f.config, {
          onPhase: (p) => {
            if (p === phase) Date.now = () => f.approval.payload.expiresAt + 1;
          },
        }),
        /OPERATOR_REVIEW/,
      );
    } finally {
      Date.now = now;
    }
    if (existsSync(f.request.destination))
      edit(join(f.request.destination, 'control.sqlite'), (db) =>
        assert.equal(db.prepare('SELECT count(*) n FROM issuances').get().n, 1),
      );
  });
for (const phase of [
  'verified',
  'staged',
  'handover-committed',
  'handover-retained',
  'leased',
  'before-message',
  'message-acknowledged',
])
  test(`real SIGKILL at ${phase}: reconcile or quarantine`, async (t) => {
    const f = await recoveryFixture(t),
      archive = hash(readFileSync(f.request.archive));
    const child = fork(
      new URL('./helpers/recovery-worker.mjs', import.meta.url),
      [f.configPath, phase],
      { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] },
    );
    t.after(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    });
    const exited = once(child, 'exit');
    const [message] = await once(child, 'message', { signal: AbortSignal.timeout(20000) });
    assert.equal(message.phase, phase, JSON.stringify(message));
    child.kill('SIGKILL');
    await exited;
    assert.equal(hash(readFileSync(f.request.archive)), archive);
    const c = f.openCustody();
    try {
      assert.equal(
        c.db.prepare('SELECT generation FROM writer_fence').get().generation,
        ['verified', 'staged'].includes(phase) ? 1 : 2,
      );
    } finally {
      c.close();
    }
    if (phase === 'verified') {
      assert.equal(existsSync(f.request.destination), false);
      assert.ok(readdirSync(f.root).some((n) => n.startsWith('.siepmu-recovery-')));
      assert.equal((await runRecoveryFixture(f.config)).outcome, 'PASS');
    } else if (phase === 'staged') {
      await assert.rejects(runRecoveryFixture(f.config, { resume: true }), /HANDOVER_REQUIRED/);
      const { plan, trust } = reviewed(f),
        operator = f.openCustody();
      try {
        reconcileRecoveryHandover(operator, plan, f.approval, trust, { perform: true });
      } finally {
        operator.close();
      }
      assert.equal((await runRecoveryFixture(f.config, { resume: true })).outcome, 'PASS');
    } else if (phase === 'message-acknowledged')
      await assert.rejects(runRecoveryFixture(f.config, { resume: true }), /REVIEW_SUPERSEDED/);
    else assert.equal((await runRecoveryFixture(f.config, { resume: true })).outcome, 'PASS');
  });
