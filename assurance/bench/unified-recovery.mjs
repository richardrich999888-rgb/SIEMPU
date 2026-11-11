// Same driver, fresh process per revision/sample. Synthetic laboratory comparison.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, statSync, existsSync } from 'node:fs';
import { cpus, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { snapshot } from '../sag/package.mjs';
import { fingerprint, sha256 } from '../sag/format.mjs';
const root = process.cwd(),
  kind = process.argv[2],
  destination = resolve(process.argv[3]);
assert.ok(['maintenance', 'guarded'].includes(kind));
const before = snapshot(root),
  load = (p) => import(pathToFileURL(resolve(root, p)));
const { backup, restore, readBackup } = await load('scripts/backup.mjs');
const { Authority } = await load('services/control/core.mjs');
const { ApiClient, coreTransport, createObject, decryptObject } = await load(
  'tests/helpers/client.mjs',
);
const getJson = (p) => JSON.parse(readFileSync(p));
const sizes = (p) => ({
  main: statSync(p).size,
  wal: existsSync(p + '-wal') ? statSync(p + '-wal').size : 0,
});
const timed = async (fn) => {
  const start = performance.now();
  const value = await fn();
  return { ms: performance.now() - start, value };
};
const cleanups = [],
  cpu = process.cpuUsage();
let result;
try {
  if (kind === 'maintenance') {
    const temp = mkdtempSync(join(tmpdir(), 'siepmu-p046-bench-'));
    cleanups.push(() => rmSync(temp, { recursive: true, force: true }));
    const dir = join(temp, 'source');
    const { initDemo } = await load('scripts/bootstrap.mjs');
    const { createRelayServer } = await load('services/relay/server.mjs');
    const profiles = await initDemo(dir);
    createRelayServer({
      database: join(dir, 'relay/relay.sqlite'),
      secret: Buffer.alloc(32),
    }).close();
    const relay = new DatabaseSync(join(dir, 'relay/relay.sqlite'));
    const a = new Authority({
      dbPath: join(dir, 'control.sqlite'),
      signingKey: getJson(join(dir, 'server-key.json')),
      masterKey: readFileSync(join(dir, 'master.key')),
      relay: {
        putBlob: async (h, b) =>
          relay.prepare('INSERT INTO blobs VALUES(?,?,?,?)').run(h, b, b.length, Date.now()),
      },
    });
    const alice = profiles.profiles.find((p) => p.username === 'alice'),
      bob = profiles.profiles.find((p) => p.username === 'bob');
    const objects = [],
      sendMs = [],
      data = 'SYNTHETIC'.padEnd(4096, '.');
    let checkpoint, controlBytes, relayBytes;
    try {
      const client = await new ApiClient(coreTransport(a), alice).authenticate(),
        grant = await client.grant();
      for (let i = 0; i < 20; i++) {
        const object = createObject(alice, bob, grant, { data });
        sendMs.push((await timed(() => client.submit(object))).ms);
        objects.push(object);
      }
      checkpoint = a.checkpoint();
      controlBytes = sizes(join(dir, 'control.sqlite'));
      relayBytes = sizes(join(dir, 'relay/relay.sqlite'));
    } finally {
      a.close();
      relay.close();
    }
    const archive = join(temp, 'backup.enc'),
      dest = join(temp, 'restored'),
      pass = 'Synthetic benchmark passphrase';
    const made = await timed(() => backup(dir, archive, pass));
    const verified = await timed(() =>
      readBackup(archive, pass, profiles.serverPublicKey, checkpoint),
    );
    const restored = await timed(() =>
      restore(archive, dest, pass, profiles.serverPublicKey, { checkpoint }),
    );
    const db = new DatabaseSync(join(dest, 'relay/relay.sqlite'), { readOnly: true });
    let decrypted = 0;
    try {
      for (const object of objects) {
        const row = db
          .prepare('SELECT ciphertext FROM blobs WHERE hash=?')
          .get(object.envelope.ciphertextHash);
        assert.equal(
          decryptObject(
            {
              ...object,
              ciphertext: Buffer.from(row.ciphertext).toString('base64url'),
              senderSigningPublicKey: alice.keys.signing.publicKey,
            },
            bob,
          ).bytes.toString(),
          data,
        );
        decrypted++;
      }
    } finally {
      db.close();
    }
    result = {
      objects: 20,
      objectsRecovered: decrypted,
      sendMs,
      backupMs: made.ms,
      archiveAuthenticationMs: verified.ms,
      restoreMs: restored.ms,
      archiveBytes: statSync(archive).size,
      controlBytes,
      relayBytes,
      evidenceRecords: checkpoint.payload.sequence,
    };
  } else {
    assert.ok(
      existsSync(join(root, 'scripts/guarded-recovery.mjs')),
      'GUARDED_PROFILE_NOT_IMPLEMENTED_AT_THIS_REVISION',
    );
    const { recoveryFixture } = await load('tests/helpers/recovery-rehearsal.mjs');
    const { stageGuardedRecovery, verifyRecoveryWorkingSet, reconcileRecoveryHandover } =
      await load('scripts/guarded-recovery.mjs');
    const { createRecoveryGuard, authoritySnapshot } = await load('services/evidence/custody.mjs');
    const { verifyEvidence } = await load('apps/verifier/verify.mjs');
    const f = await recoveryFixture({ after: (fn) => cleanups.push(fn) });
    const started = performance.now();
    const staged = await timed(() => stageGuardedRecovery(f.request, f.config));
    const checked = await timed(() => verifyRecoveryWorkingSet(f.plan, f.trust));
    const custody = f.openCustody();
    let a;
    const relay = new DatabaseSync(join(f.request.destination, 'relay/relay.sqlite'));
    try {
      const handover = await timed(() =>
        reconcileRecoveryHandover(custody, f.plan, f.approval, f.trust, { perform: true }),
      );
      const guard = createRecoveryGuard({
        custodianKey: f.trust.custodianKey,
        writer: f.config.writer,
        exchange: (r) => custody.accept(r),
      });
      a = new Authority({
        dbPath: join(f.request.destination, 'control.sqlite'),
        signingKey: getJson(join(f.request.destination, 'server-key.json')),
        masterKey: readFileSync(join(f.request.destination, 'master.key')),
        recoveryGuard: guard,
        relay: {
          putBlob: async (h, b) =>
            relay.prepare('INSERT INTO blobs VALUES(?,?,?,?)').run(h, b, b.length, Date.now()),
          getBlob: async (h) =>
            Buffer.from(
              relay.prepare('SELECT ciphertext FROM blobs WHERE hash=?').get(h).ciphertext,
            ),
        },
      });
      const lease = await timed(() => guard.authorize(a)),
        readyMs = performance.now() - started;
      const alice = new ApiClient(coreTransport(a), f.config.profiles.alice),
        bob = new ApiClient(coreTransport(a), f.config.profiles.bob);
      alice.token = f.config.tokens.alice;
      bob.token = f.config.tokens.bob;
      const requestMs = [];
      for (let i = 0; i < 100; i++) {
        const r = await timed(() => alice.request('GET', '/api/control'));
        assert.equal(r.value.status, 200);
        requestMs.push(r.ms);
      }
      const object = createObject(
        f.config.profiles.alice,
        f.config.profiles.bob,
        await alice.grant(),
        { data: 'SYNTHETIC recovered fenced exchange' },
      );
      await alice.submit(object);
      const claim = await timed(() => bob.claim(object.envelope.objectId, a.epoch().epoch));
      assert.equal(claim.value.status, 200);
      assert.equal(
        decryptObject(claim.value.body, f.config.profiles.bob).bytes.toString(),
        'SYNTHETIC recovered fenced exchange',
      );
      const check = await timed(() =>
        verifyEvidence(authoritySnapshot(a), f.trust.authorityKey, {
          checkpoint: f.trust.checkpoint,
        }),
      );
      result = {
        stageMs: staged.ms,
        workingSetVerificationMs: checked.ms,
        handoverMs: handover.ms,
        freshLeaseMs: lease.ms,
        readyMs,
        protectedRequestMs: requestMs,
        keyReleaseMs: claim.ms,
        checkpointVerificationMs: check.ms,
        objectsBefore: 1,
        objectsRecovered: checked.value.objects,
        postRecoveryExchange: true,
        evidenceRecords: a.checkpoint().payload.sequence,
        controlBytes: sizes(join(f.request.destination, 'control.sqlite')),
        relayBytes: sizes(join(f.request.destination, 'relay/relay.sqlite')),
        monitorBytes: sizes(join(f.request.destination, 'monitor/collector.sqlite')),
      };
    } finally {
      a?.close();
      relay.close();
      custody.close();
    }
  }
} finally {
  for (const f of cleanups.reverse()) await f();
}
const after = snapshot(root);
assert.equal(after.commit, before.commit);
assert.equal(fingerprint(after.index), fingerprint(before.index));
writeFileSync(
  destination,
  JSON.stringify(
    {
      kind,
      commit: before.commit,
      tree: before.tree,
      sourceFingerprint: fingerprint(before.index),
      harnessSha256: sha256(readFileSync(fileURLToPath(import.meta.url))),
      runtime: { node: process.version, openssl: process.versions.openssl, cpu: cpus()[0]?.model },
      cpuMicroseconds: process.cpuUsage(cpu),
      maxRssKiB: process.resourceUsage().maxRSS,
      result,
      limitations: [
        'One host, shared administrator; no independent custody or operational RTO/RPO.',
        'Fresh process per sample, identical workload and driver; synthetic keys/data are regenerated.',
        'Maintenance profile measures unfenced offline control/relay snapshots; guarded profile requires existing custody and review.',
        'Protected requests use in-process transport; network impairments are measured separately in hosted CI.',
        'CPU and peak RSS include fixture setup; percentile estimates are empirical and not service guarantees.',
      ],
    },
    null,
    2,
  ) + '\n',
  { flag: 'wx', mode: 0o600 },
);
