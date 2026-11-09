import test from 'node:test';
import assert from 'node:assert/strict';
import fs, {
  readFileSync,
  writeFileSync,
  readdirSync,
  existsSync,
  statSync,
  rmSync,
  chmodSync,
  symlinkSync,
  mkdirSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import {
  inspectLegacyMigration,
  applyLegacyMigration,
  readMigrationFile,
} from '../scripts/legacy-migration.mjs';
import { legacyFixture, privateJson } from './helpers/legacy-migration-fixture.mjs';
import { Authority } from '../services/control/core.mjs';
import { restore } from '../scripts/backup.mjs';
import { createRecoveryGuard } from '../services/evidence/custody.mjs';
import {
  assertAuthorizationCommit,
  authorizationDigest,
} from '../services/evidence/authorization-state.mjs';
import { packet, canonical, hash, verifyPacket } from '../services/control/primitives.mjs';
import { pair } from './helpers/client.mjs';
const edit = (path, fn) => {
  const db = new DatabaseSync(path);
  try {
    fn(db);
  } finally {
    db.close();
  }
};
const clean = (f) => {
  assert.equal(existsSync(f.request.destination), false);
  assert.deepEqual(
    readdirSync(f.root).filter((n) => n.startsWith('.siepmu-migration-')),
    [],
  );
};
const open = (f, recoveryGuard) =>
  new Authority({
    dbPath: join(f.request.destination, 'control.sqlite'),
    signingKey: f.key,
    masterKey: readFileSync(join(f.data, 'master.key')),
    recoveryGuard,
  });
for (const schema of [6, 7])
  for (const sourceType of ['database', 'backup']) {
    test(`schema ${schema}, ${sourceType}: reviewed exact snapshot gains a seal; custody stays independent`, async (t) => {
      const f = await legacyFixture(t, schema);
      if (sourceType === 'backup') Object.assign(f.request, { sourceType, source: f.archive });
      const before = hash(readFileSync(f.request.source)),
        custodyBefore = canonical(f.custody.db.prepare('SELECT * FROM anchor').get());
      const inspected = inspectLegacyMigration(f.request, { passphrase: f.passphrase });
      clean(f);
      const approval = f.review();
      const receipt = await applyLegacyMigration(f.request, {
        approval,
        signingKey: f.key,
        passphrase: f.passphrase,
      });
      assert.ok(verifyPacket(f.trust.authorityKey, receipt));
      assert.equal(
        receipt.payload.databaseSha256,
        hash(readFileSync(join(f.request.destination, 'control.sqlite'))),
      );
      assert.equal(
        receipt.payload.checkpoint.payload.sequence,
        f.trust.checkpoint.payload.sequence + 1,
      );
      assert.equal(hash(readFileSync(f.request.source)), before);
      assert.equal(canonical(f.custody.db.prepare('SELECT * FROM anchor').get()), custodyBefore);
      assert.equal(readdirSync(f.request.destination).length, 5);
      for (const name of readdirSync(f.request.destination))
        assert.equal(statSync(join(f.request.destination, name)).mode & 0o077, 0);
      // No activation is performed by migration; even the correct writer cannot acquire a lease yet.
      f.custody.requireFencing = true;
      const guard = createRecoveryGuard({
        custodianKey: f.custodyKeys.publicKey,
        exchange: (r) => f.custody.accept(r),
        writer: { key: f.writer.privateKey, generation: 1 },
      });
      const a = open(f, guard);
      t.after(() => a.close());
      assertAuthorizationCommit(a);
      assert.equal(authorizationDigest(a), inspected.plan.stateDigest);
      assert.equal(a.crypto.policy().newSuites.length, 0);
      assert.equal(a.get('SELECT revocation_version FROM authority').revocation_version, 1);
      await assert.rejects(guard.authorize(a), /Recovery trust/);
      assert.equal(guard.state, 'QUARANTINED');
      const handover = JSON.parse(
        readFileSync(join(f.request.destination, 'handover-request.json')),
      );
      f.custody.transferWriter(handover); // Synthetic custodian only; distinct, explicit operator step.
      await guard.authorize(a);
      assert.equal(guard.state, 'VALIDATED');
      const stale = createRecoveryGuard({
        custodianKey: f.custodyKeys.publicKey,
        exchange: (r) => f.custody.accept(r),
      });
      await assert.rejects(stale.authorize(a), /Recovery trust/);
      assert.equal(stale.state, 'QUARANTINED');
      assert.equal(stale.reason, 'FENCING_REQUIRED');
      const original = new DatabaseSync(join(f.root, 'legacy.sqlite'), { readOnly: true });
      try {
        assert.deepEqual(
          a.all(
            'SELECT * FROM evidence WHERE sequence<=? ORDER BY sequence',
            f.trust.checkpoint.payload.sequence,
          ),
          original.prepare('SELECT * FROM evidence ORDER BY sequence').all(),
        );
      } finally {
        original.close();
      }
      await assert.rejects(
        applyLegacyMigration(f.request, { approval, signingKey: f.key, passphrase: f.passphrase }),
        /DESTINATION_EXISTS/,
      );
    });
  }

test('unsealed legacy backup is still rejected by ordinary restore', async (t) => {
  const f = await legacyFixture(t, 7);
  assert.throws(
    () =>
      restore(f.archive, f.request.destination, f.passphrase, f.trust.authorityKey, {
        checkpoint: f.trust.checkpoint,
      }),
    /AUTHORIZATION_COMMIT_MISSING/,
  );
  clean(f);
});

test('independent trust evidence omissions, forks, policy disagreement and substitution fail closed', async (t) => {
  const f = await legacyFixture(t),
    original = structuredClone(f.trust);
  const cases = [
    [
      'missing checkpoint',
      (v) => {
        v.checkpoint = null;
      },
      /CHECKPOINT/,
    ],
    [
      'missing full snapshot',
      (v) => {
        v.manifest = null;
      },
      /MANIFEST/,
    ],
    [
      'old limited digest alone',
      (v) => {
        delete v.retainedManifestSha256;
      },
      /TRUST_PROFILE/,
    ],
    [
      'missing custody receipt',
      (v) => {
        v.lease = null;
      },
      /CUSTODY_RECEIPT/,
    ],
    [
      'forged snapshot signature',
      (v) => {
        v.manifest.signature = 'x';
      },
      /MANIFEST/,
    ],
    [
      're-signed snapshot without retained pin',
      (v) => {
        v.manifest = packet(f.key, { ...v.manifest.payload, createdAt: 0 });
      },
      /MANIFEST/,
    ],
    [
      'forged custody state',
      (v) => {
        v.lease.payload.stateDigest = 'f'.repeat(64);
      },
      /CUSTODY_RECEIPT/,
    ],
    [
      'signed divergent checkpoint',
      (v) => {
        v.checkpoint = packet(f.key, { ...v.checkpoint.payload, headHash: 'f'.repeat(64) });
      },
      /EXACT_ANCHOR/,
    ],
    [
      'newer independent checkpoint',
      (v) => {
        v.checkpoint = packet(f.key, {
          ...v.checkpoint.payload,
          sequence: v.checkpoint.payload.sequence + 1,
        });
      },
      /EXACT_ANCHOR/,
    ],
    [
      'older ancestor alone',
      (v) => {
        v.checkpoint = packet(f.key, { sequence: 0, headHash: '0'.repeat(64), issuedAt: 0 });
      },
      /EXACT_ANCHOR/,
    ],
    [
      'policy disagreement',
      (v) => {
        v.expectedPolicyDigest = 'f'.repeat(64);
      },
      /POLICY_MISMATCH/,
    ],
    [
      'runtime downgrade',
      (v) => {
        v.allowPqcLab = true;
      },
      /TRUST_PROFILE/,
    ],
    [
      'authority key substitution',
      (v) => {
        v.authorityKey = pair().publicKey;
      },
      /CHECKPOINT/,
    ],
    [
      'unknown trust field',
      (v) => {
        v.unsafe = true;
      },
      /TRUST_PROFILE/,
    ],
    [
      'non-independent reviewer',
      (v) => {
        v.reviewerKey = v.authorityKey;
      },
      /KEY_SEPARATION/,
    ],
  ];
  for (const [name, mutate, error] of cases)
    await t.test(name, () => {
      const trust = structuredClone(original);
      mutate(trust);
      privateJson(f.request.trust, trust);
      assert.throws(() => inspectLegacyMigration(f.request), error);
      clean(f);
    });
});

test('selective authorization rollback is detected even though the legacy custody digest omits it', async (t) => {
  const f = await legacyFixture(t),
    bytes = readFileSync(f.request.source);
  const mutations = [
    [
      'crypto policy',
      'UPDATE crypto_policy SET value=replace(value,\'"revision":2\',\'"revision":1\')',
    ],
    ['MFA floor', 'UPDATE users SET totp_floor=-1'],
    ['logged-out session rollback', 'UPDATE sessions SET revoked=0'],
    ['consumed challenge rollback', 'UPDATE challenges SET used=0'],
    [
      'forged FLASH approval',
      "PRAGMA foreign_keys=OFF; INSERT INTO release_approvals VALUES('forged','forged',2,'forged','forged',1,'{}')",
    ],
    [
      'forged crypto key',
      "PRAGMA foreign_keys=OFF; INSERT INTO crypto_keys VALUES('forged','forged','{}','active',1)",
    ],
    ['credential', "UPDATE users SET password='forged'"],
    ['revoked device', "UPDATE devices SET status='approved'"],
    ['epoch rollback', 'UPDATE authority SET epoch=1,revocation_version=0'],
  ];
  for (const [name, sql] of mutations)
    await t.test(name, () => {
      writeFileSync(f.request.source, bytes);
      edit(f.request.source, (db) => db.exec(sql));
      assert.throws(() => inspectLegacyMigration(f.request), /SNAPSHOT_MISMATCH/);
      clean(f);
    });
});

test('trusted but structurally inconsistent snapshots are refused before a seal is created', async (t) => {
  const f = await legacyFixture(t),
    bytes = readFileSync(f.request.source),
    original = structuredClone(f.trust);
  const cases = [
    [
      'modified signed record',
      (db) =>
        db.exec(
          "UPDATE evidence SET record=replace(record,'LEGACY_FIXTURE_POLICY','ALTERED_EVENT') WHERE sequence=(SELECT max(sequence) FROM evidence)",
        ),
      /EVIDENCE_ROW/,
    ],
    [
      'deleted history',
      (db) => db.exec('DELETE FROM evidence WHERE sequence=1'),
      /gap|sequence|Sequence/i,
    ],
    [
      'forged chain with recomputed hash',
      (db) => {
        const row = db.prepare('SELECT * FROM evidence ORDER BY sequence DESC LIMIT 1').get();
        const rec = JSON.parse(row.record);
        rec.signature = 'a'.repeat(86);
        db.prepare('UPDATE evidence SET record=?,hash=? WHERE sequence=?').run(
          canonical(rec),
          hash(canonical(rec)),
          row.sequence,
        );
      },
      /Signature|signature/,
    ],
    [
      'unwitnessed descendant',
      (db) => {
        const row = db
          .prepare('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1')
          .get();
        const rec = packet(f.key, {
          sequence: row.sequence + 1,
          previousHash: row.hash,
          eventId: 'extra',
          eventType: 'UNWITNESSED',
          timestamp: Date.now(),
          epoch: 2,
        });
        db.prepare('INSERT INTO evidence VALUES(?,?,?)').run(
          rec.payload.sequence,
          canonical(rec),
          hash(canonical(rec)),
        );
      },
      /EXACT_ANCHOR/,
    ],
    [
      'trigger',
      (db) =>
        db.exec(
          'CREATE TRIGGER hostile AFTER INSERT ON evidence BEGIN UPDATE authority SET epoch=1; END',
        ),
      /SCHEMA_SHAPE/,
    ],
    [
      'schema checksum',
      (db) =>
        db.exec("UPDATE schema_migrations SET checksum='forged' WHERE version='001-initial.sql'"),
      /SCHEMA_CHECKSUM/,
    ],
    [
      'foreign key violation',
      (db) => db.exec("PRAGMA foreign_keys=OFF; UPDATE devices SET user_id='missing'"),
      /DATABASE_INTEGRITY/,
    ],
    ['policy history mismatch', (db) => db.exec('UPDATE authority SET epoch=3'), /POLICY_HISTORY/],
    [
      'limited custody mismatch',
      (db) => db.exec('UPDATE authority SET revocation_version=0'),
      /LEGACY_STATE/,
    ],
    [
      'unknown crypto policy',
      (db) => db.exec("UPDATE crypto_policy SET value='{}'"),
      /members|policy/i,
    ],
  ];
  for (const [name, mutate, error] of cases)
    await t.test(name, () => {
      writeFileSync(f.request.source, bytes);
      Object.assign(f.trust, structuredClone(original));
      edit(f.request.source, mutate);
      f.repin();
      assert.throws(() => inspectLegacyMigration(f.request), error);
      clean(f);
    });
});

test('operator review is mandatory, independently signed, unexpired and bound to exact inputs and destination', async (t) => {
  const f = await legacyFixture(t),
    approval = f.review();
  const cases = [
    ['absent', () => undefined],
    ['forged', () => ({ ...approval, signature: 'bad' })],
    ['wrong reviewer key', () => packet(f.key, approval.payload)],
    ['expired', () => packet(f.reviewer.privateKey, { ...approval.payload, expiresAt: 0 })],
    [
      'unchecked current policy',
      () => packet(f.reviewer.privateKey, { ...approval.payload, currentPolicyConfirmed: false }),
    ],
    [
      'unchecked independence',
      () =>
        packet(f.reviewer.privateKey, { ...approval.payload, independentSnapshotConfirmed: false }),
    ],
    [
      'unchecked latest anchor',
      () =>
        packet(f.reviewer.privateKey, { ...approval.payload, latestCheckpointConfirmed: false }),
    ],
    [
      'unchecked maintenance',
      () => packet(f.reviewer.privateKey, { ...approval.payload, maintenanceConfirmed: false }),
    ],
    [
      'wrong full state',
      () => packet(f.reviewer.privateKey, { ...approval.payload, stateDigest: 'f'.repeat(64) }),
    ],
    [
      'unknown approval field',
      () => packet(f.reviewer.privateKey, { ...approval.payload, force: true }),
    ],
  ];
  for (const [name, get] of cases)
    await t.test(name, async () => {
      await assert.rejects(
        applyLegacyMigration(f.request, { approval: get(), signingKey: f.key }),
        /OPERATOR_APPROVAL/,
      );
      clean(f);
    });
  const changed = { ...f.request, destination: join(f.root, 'different') };
  await assert.rejects(
    applyLegacyMigration(changed, { approval, signingKey: f.key }),
    /OPERATOR_APPROVAL/,
  );
  await assert.rejects(
    applyLegacyMigration(f.request, { approval, signingKey: pair().privateKey }),
    /AUTHORITY_KEY/,
  );
  clean(f);
  privateJson(f.request.writerPublicKey, pair().publicKey);
  await assert.rejects(
    applyLegacyMigration(f.request, { approval, signingKey: f.key }),
    /OPERATOR_APPROVAL/,
  );
  clean(f);
});

test('archive authentication errors, source mutation and changed trust between review and apply fail closed', async (t) => {
  const f = await legacyFixture(t),
    approval = f.review();
  f.trust.expectedPolicyDigest = 'f'.repeat(64);
  privateJson(f.request.trust, f.trust);
  await assert.rejects(
    applyLegacyMigration(f.request, { approval, signingKey: f.key }),
    /POLICY_MISMATCH/,
  );
  clean(f);
  // A new fixture keeps the independent trust record intact for archive checks.
  const g = await legacyFixture(t);
  Object.assign(g.request, { sourceType: 'backup', source: g.archive });
  assert.throws(() => inspectLegacyMigration(g.request, { passphrase: 'incorrect passphrase' }));
  clean(g);
  const original = readFileSync(g.archive),
    p = JSON.parse(original);
  p.tag = Buffer.alloc(16).toString('base64');
  privateJson(g.archive, p);
  assert.throws(() => inspectLegacyMigration(g.request, { passphrase: g.passphrase }));
  clean(g);
  writeFileSync(g.archive, original);
  const reviewed = g.review();
  const v = JSON.parse(original);
  v.extra = true;
  privateJson(g.archive, v);
  await assert.rejects(
    applyLegacyMigration(g.request, {
      approval: reviewed,
      signingKey: g.key,
      passphrase: g.passphrase,
    }),
    /format/,
  );
  clean(g);
});

for (const phase of ['staged', 'uncommitted', 'sealed'])
  test(`handled ${phase} failure leaves source intact and no candidate; retry succeeds`, async (t) => {
    const f = await legacyFixture(t),
      before = hash(readFileSync(f.request.source)),
      approval = f.review();
    await assert.rejects(
      applyLegacyMigration(f.request, {
        approval,
        signingKey: f.key,
        onPhase: (p) => {
          if (p === phase) throw new Error('INJECTED_IO_FAILURE');
        },
      }),
      /INJECTED_IO_FAILURE/,
    );
    clean(f);
    assert.equal(hash(readFileSync(f.request.source)), before);
    await applyLegacyMigration(f.request, { approval, signingKey: f.key });
  });

for (const phase of ['staged', 'uncommitted', 'sealed'])
  test(`real process kill at ${phase} never publishes; private orphan is not resumed`, async (t) => {
    const f = await legacyFixture(t),
      before = hash(readFileSync(f.request.source));
    const requestPath = join(f.root, 'request.json'),
      approvalPath = join(f.root, 'approval.json');
    privateJson(requestPath, f.request);
    privateJson(approvalPath, f.review());
    const child = spawn(
      process.execPath,
      [
        'tests/helpers/migration-worker.mjs',
        requestPath,
        approvalPath,
        join(f.data, 'server-key.json'),
        phase,
      ],
      { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] },
    );
    t.after(() => {
      if (child.exitCode === null) child.kill('SIGKILL');
    });
    const exit = once(child, 'exit');
    const timeout = AbortSignal.timeout(15000);
    const [message] = await once(child, 'message', { signal: timeout });
    assert.equal(message.phase, phase);
    child.kill('SIGKILL');
    await exit;
    assert.equal(existsSync(f.request.destination), false);
    assert.equal(hash(readFileSync(f.request.source)), before);
    const orphan = readdirSync(f.root).find((n) => n.startsWith('.siepmu-migration-'));
    assert.ok(orphan);
    assert.equal(statSync(join(f.root, orphan)).mode & 0o077, 0);
    // Recovery always starts again from the independently verified source, ignoring orphan state.
    await applyLegacyMigration(f.request, { approval: f.review(), signingKey: f.key });
    assert.ok(existsSync(join(f.root, orphan)));
  });

test('post-write corruption is caught and publication disk failure is cleaned up', async (t) => {
  const f = await legacyFixture(t),
    approval = f.review();
  await assert.rejects(
    applyLegacyMigration(f.request, {
      approval,
      signingKey: f.key,
      onPhase: (p, stage) => {
        if (p === 'sealed')
          edit(join(stage, 'control.sqlite'), (db) => db.exec('UPDATE users SET totp_floor=999'));
      },
    }),
    /COMMIT_MISMATCH/,
  );
  clean(f);
  const rename = fs.renameSync;
  try {
    fs.renameSync = () => {
      throw new Error('INJECTED_RENAME_FAILURE');
    };
    syncBuiltinESMExports();
    await assert.rejects(
      applyLegacyMigration(f.request, { approval, signingKey: f.key }),
      /INJECTED_RENAME_FAILURE/,
    );
  } finally {
    fs.renameSync = rename;
    syncBuiltinESMExports();
  }
  clean(f);
});

test('unavailable or advanced custody prevents recovery; stale handover cannot reset custody', async (t) => {
  const f = await legacyFixture(t);
  await applyLegacyMigration(f.request, { approval: f.review(), signingKey: f.key });
  const guard = createRecoveryGuard({
    custodianKey: f.custodyKeys.publicKey,
    exchange: async () => {
      throw new Error('CUSTODY_UNAVAILABLE');
    },
    writer: { key: f.writer.privateKey, generation: 1 },
  });
  const a = open(f, guard);
  t.after(() => a.close());
  await assert.rejects(guard.authorize(a), /Recovery trust/);
  assert.equal(guard.state, 'QUARANTINED');
  assert.equal(guard.reason, 'CUSTODY_UNAVAILABLE');
  const handover = JSON.parse(readFileSync(join(f.request.destination, 'handover-request.json')));
  f.custody.db.prepare('UPDATE anchor SET state=?').run('f'.repeat(64));
  assert.throws(() => f.custody.transferWriter(handover), /ANCHOR_CHANGED/);
  assert.equal(f.custody.db.prepare('SELECT count(*) n FROM writer_fence').get().n, 0);
});

test('private-file, symlink, live-WAL and destination protections; executable inspection and application', async (t) => {
  const f = await legacyFixture(t),
    requestPath = join(f.root, 'request.json');
  privateJson(requestPath, f.request);
  const cli = (args) =>
    spawnSync(process.execPath, ['scripts/legacy-migration.mjs', ...args], { encoding: 'utf8' });
  assert.equal(cli(['inspect', requestPath]).status, 0);
  clean(f);
  assert.notEqual(cli(['apply', requestPath]).status, 0);
  const p = join(f.root, 'symlink');
  symlinkSync(f.request.source, p);
  assert.throws(() => readMigrationFile(p));
  chmodSync(f.request.source, 0o644);
  assert.throws(() => inspectLegacyMigration(f.request), /PRIVATE_FILE/);
  chmodSync(f.request.source, 0o600);
  writeFileSync(f.request.source + '-wal', 'present');
  assert.throws(() => inspectLegacyMigration(f.request), /OFFLINE_SNAPSHOT/);
  rmSync(f.request.source + '-wal');
  mkdirSync(f.request.destination);
  assert.throws(() => inspectLegacyMigration(f.request), /DESTINATION_EXISTS/);
  rmSync(f.request.destination, { recursive: true });
  assert.throws(() => readMigrationFile(f.request.source, 1), /PRIVATE_FILE/);
  const approvalPath = join(f.root, 'approval.json');
  privateJson(approvalPath, f.review());
  const result = cli(['apply', requestPath, approvalPath, join(f.data, 'server-key.json')]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    JSON.parse(result.stdout).payload.activation,
    'QUARANTINED_PENDING_INDEPENDENT_WRITER_HANDOVER',
  );
});

test('a longer correctly signed fork cannot replace the independently retained checkpoint', async (t) => {
  const f = await legacyFixture(t);
  edit(f.request.source, (db) => {
    let previousHash = '0'.repeat(64);
    const rows = db.prepare('SELECT * FROM evidence ORDER BY sequence').all();
    for (const row of rows) {
      const old = JSON.parse(row.record);
      const next = packet(f.key, { ...old.payload, previousHash, eventId: 'fork-' + row.sequence });
      previousHash = hash(canonical(next));
      db.prepare('UPDATE evidence SET record=?,hash=? WHERE sequence=?').run(
        canonical(next),
        previousHash,
        row.sequence,
      );
    }
    const extra = packet(f.key, {
      sequence: rows.length + 1,
      previousHash,
      eventId: 'longer-fork',
      eventType: 'FORK',
      epoch: 2,
      timestamp: Date.now(),
    });
    db.prepare('INSERT INTO evidence VALUES(?,?,?)').run(
      extra.payload.sequence,
      canonical(extra),
      hash(canonical(extra)),
    );
    f.trust.manifest = packet(f.key, {
      ...f.trust.manifest.payload,
      checkpoint: { sequence: extra.payload.sequence, headHash: hash(canonical(extra)) },
    });
  });
  f.repin();
  assert.throws(() => inspectLegacyMigration(f.request), /EXACT_ANCHOR/);
  clean(f);
});

test('candidate cannot overwrite an existing seal even with a newly pinned synthetic snapshot', async (t) => {
  const f = await legacyFixture(t, 7);
  edit(f.request.source, (db) =>
    db.prepare('INSERT INTO authorization_commit VALUES(1,?)').run('{}'),
  );
  f.repin();
  assert.throws(() => inspectLegacyMigration(f.request), /ALREADY_SEALED/);
  clean(f);
});

for (const phase of ['staged', 'uncommitted', 'sealed'])
  test(`approval expiring at ${phase} cannot publish a candidate`, async (t) => {
    const f = await legacyFixture(t),
      approval = f.review(),
      realNow = Date.now;
    try {
      await assert.rejects(
        applyLegacyMigration(f.request, {
          approval,
          signingKey: f.key,
          onPhase: (p) => {
            if (p === phase) Date.now = () => approval.payload.expiresAt + 1;
          },
        }),
        /APPROVAL_EXPIRED/,
      );
    } finally {
      Date.now = realNow;
    }
    clean(f);
  });
