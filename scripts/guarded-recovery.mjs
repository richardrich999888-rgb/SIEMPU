// Source-only synthetic recovery protocol. Never imported by service startup.
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  lstatSync,
  realpathSync,
  renameSync,
  openSync,
  closeSync,
  fsyncSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { readBackup, restore } from './backup.mjs';
import { readMigrationFile } from './legacy-migration.mjs';
import { SecurityCollector, redactSecurityEvents } from '../services/monitoring/collector.mjs';
import { CryptoPolicyRegistry } from '../services/crypto-policy/registry.mjs';
import {
  authorizationDigest,
  assertAuthorizationCommit,
} from '../services/evidence/authorization-state.mjs';
import { verifyEvidenceRecords } from '../apps/verifier/verify.mjs';
import { exactMembers, isPosition } from '../services/evidence/incremental.mjs';
import {
  validateWriterPublicKey,
  validateAuthorityFloor,
  validGeneration,
} from '../services/evidence/fencing.mjs';
import { canonical, hash, keyId, verifyPacket } from '../services/control/primitives.mjs';
const insist = (ok, code) => {
  if (!ok) throw new Error(code);
};
const digest = (s) => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const signed = (p, key) =>
  exactMembers(p, ['payload', 'signature', 'keyId']) && verifyPacket(key, p);
const equal = (a, b) => canonical(a) === canonical(b);
const position = (p) => ({ sequence: p.sequence, headHash: p.headHash });
const schema = (db) =>
  db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name').all();
export function recoveryDirectory(path) {
  const s = lstatSync(path);
  insist(
    s.isDirectory() &&
      s.uid === process.getuid() &&
      !(s.mode & 0o077) &&
      realpathSync(path) === path,
    'RECOVERY_PRIVATE_DIRECTORY',
  );
}
function absent(path) {
  try {
    lstatSync(path);
  } catch (e) {
    if (e.code === 'ENOENT') return;
    throw e;
  }
  throw new Error('RECOVERY_DESTINATION_EXISTS');
}
function sync(path) {
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function controlSchema(db) {
  const expected = new DatabaseSync(':memory:');
  try {
    expected.exec(
      'CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)',
    );
    const names = [
      '001-initial.sql',
      '002-observability.sql',
      '003-duty-roles.sql',
      '004-release-approvals.sql',
      '005-crypto-policy.sql',
      '006-alert-epoch.sql',
      '007-authorization-commit.sql',
    ];
    const rows = db.prepare('SELECT * FROM schema_migrations ORDER BY version').all();
    insist(rows.length === names.length, 'RECOVERY_SCHEMA');
    for (const [i, name] of names.entries()) {
      const sql = readFileSync(new URL('../database/migrations/' + name, import.meta.url), 'utf8');
      insist(rows[i].version === name && rows[i].checksum === hash(sql), 'RECOVERY_SCHEMA');
      expected.exec(sql);
    }
    insist(equal(schema(db), schema(expected)), 'RECOVERY_SCHEMA');
  } finally {
    expected.close();
  }
}
function logicalDigest(db) {
  return hash(
    canonical(
      schema(db)
        .filter((r) => r.type === 'table')
        .map((r) => [
          r.name,
          db
            .prepare(`SELECT * FROM "${r.name}" ORDER BY rowid`)
            .all()
            .map((row) =>
              Object.fromEntries(
                Object.entries(row).map(([name, value]) => [
                  name,
                  value instanceof Uint8Array
                    ? ['blob', Buffer.from(value).toString('base64')]
                    : ['value', value],
                ]),
              ),
            ),
        ]),
    ),
  );
}
function verifyStores(dir, t) {
  let control, relay, monitor, model, relayModel;
  try {
    control = new DatabaseSync(join(dir, 'control.sqlite'), { readOnly: true });
    relay = new DatabaseSync(join(dir, 'relay/relay.sqlite'), { readOnly: true });
    monitor = new DatabaseSync(join(dir, 'monitor/collector.sqlite'), { readOnly: true });
    model = new SecurityCollector({
      database: ':memory:',
      sourceKey: t.authorityKey,
      signingKey: t.collectorKey,
    });
    relayModel = new DatabaseSync(':memory:');
    for (const db of [control, relay, monitor]) {
      db.exec('PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;');
      insist(
        equal(db.prepare('PRAGMA quick_check').all(), [{ quick_check: 'ok' }]) &&
          !db.prepare('PRAGMA foreign_key_check').all().length,
        'RECOVERY_DATABASE_INTEGRITY',
      );
    }
    controlSchema(control);
    relayModel.exec(
      'CREATE TABLE blobs(hash TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE workload_nonces(nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL); CREATE INDEX workload_nonce_expiry ON workload_nonces(expires_at);',
    );
    insist(
      equal(schema(relay), schema(relayModel)) && equal(schema(monitor), schema(model.db)),
      'RECOVERY_AUXILIARY_SCHEMA',
    );
    insist(
      equal(
        monitor.prepare('SELECT * FROM detection_configuration').all(),
        model.db.prepare('SELECT * FROM detection_configuration').all(),
      ),
      'RECOVERY_MONITOR_SOURCE',
    );
    for (const b of relay.prepare('SELECT * FROM blobs').iterate())
      insist(
        digest(b.hash) && hash(b.ciphertext) === b.hash && b.size === b.ciphertext.length,
        'RECOVERY_RELAY_CORRUPTION',
      );
    for (const row of control.prepare('SELECT envelope FROM objects').iterate())
      insist(
        relay
          .prepare('SELECT 1 FROM blobs WHERE hash=?')
          .get(JSON.parse(row.envelope).ciphertextHash),
        'RECOVERY_RELAY_MISSING_OBJECT',
      );
    for (const table of ['evidence', 'alerts'])
      insist(
        control.prepare(`SELECT count(*) n FROM ${table}`).get().n <= 1000,
        'RECOVERY_MONITOR_PROFILE_LIMIT',
      );
    const expected = new Map(
      redactSecurityEvents({ all: (sql) => control.prepare(sql).all() }).events.map((e) => [
        e.eventId,
        e,
      ]),
    );
    const rows = monitor.prepare('SELECT * FROM events ORDER BY id').all();
    insist(rows.length === expected.size, 'RECOVERY_MONITOR_INCOMPLETE');
    for (const row of rows) {
      const event = JSON.parse(row.event);
      insist(
        expected.has(row.id) &&
          equal(event, expected.get(row.id)) &&
          row.digest === hash(canonical(event)),
        'RECOVERY_MONITOR_CONFLICT',
      );
      if (row.ack) {
        const ack = JSON.parse(row.ack);
        insist(
          signed(ack, t.collectorKey) && ack.payload.eventId === row.id,
          'RECOVERY_MONITOR_ACK',
        );
      }
    }
    for (const row of monitor.prepare('SELECT * FROM detections').iterate()) {
      const record = JSON.parse(row.record),
        p = record.payload;
      insist(
        signed(record, t.collectorKey) &&
          p.kind === 'SIEPMU_THREAT_SIGNAL' &&
          p.detectionId === row.id &&
          p.detectedAt === row.created_at &&
          p.sourceId === hash(canonical(t.authorityKey)),
        'RECOVERY_MONITOR_DETECTION',
      );
      if (row.ack) {
        const ack = JSON.parse(row.ack);
        insist(
          signed(ack, t.collectorKey) &&
            ack.payload.kind === 'SIEPMU_DETECTION_ACK' &&
            ack.payload.detectionId === row.id,
          'RECOVERY_MONITOR_ACK',
        );
      }
    }
    const a = {
      all: (sql) => control.prepare(sql).all(),
      get: (sql, ...args) => control.prepare(sql).get(...args),
      epoch: () => control.prepare('SELECT * FROM authority WHERE id=1').get(),
      crypto: new CryptoPolicyRegistry(control, false),
    };
    const head = control
      .prepare('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1')
      .get();
    insist(head, 'RECOVERY_HISTORY');
    const checkpoint = { sequence: head.sequence, headHash: head.hash };
    function* records() {
      for (const row of control.prepare('SELECT * FROM evidence ORDER BY sequence').iterate()) {
        const record = JSON.parse(row.record);
        insist(
          record.payload?.sequence === row.sequence && hash(canonical(record)) === row.hash,
          'RECOVERY_EVIDENCE_ROW',
        );
        yield record;
      }
    }
    const verified = verifyEvidenceRecords(records(), t.authorityKey, { checkpoint: t.checkpoint });
    insist(
      verified.records === head.sequence && verified.headHash === head.hash,
      'RECOVERY_HISTORY',
    );
    assertAuthorizationCommit({
      ...a,
      publicKey: t.authorityKey,
      checkpoint: () => ({ payload: checkpoint }),
    });
    const epoch = a.epoch(),
      authority = { epoch: epoch.epoch, revocationVersion: epoch.revocation_version };
    validateAuthorityFloor(authority);
    const policy = a.crypto.validatePolicy(a.crypto.policy());
    insist(
      policy.mode === 'production' &&
        !control.prepare('SELECT count(*) n FROM crypto_keys').get().n,
      'RECOVERY_CLASSICAL_PROFILE',
    );
    insist(hash(canonical(policy)) === t.policyDigest, 'RECOVERY_POLICY_MISMATCH');
    return {
      stateDigest: authorizationDigest(a),
      authority,
      checkpoint,
      controlDigest: logicalDigest(control),
      relayDigest: logicalDigest(relay),
      monitorDigest: logicalDigest(monitor),
      objects: control.prepare('SELECT count(*) n FROM objects').get().n,
      monitoringEvents: rows.length,
    };
  } finally {
    control?.close();
    relay?.close();
    monitor?.close();
    model?.close();
    relayModel?.close();
  }
}
function prepare(request, passphrase, existing = false) {
  insist(
    exactMembers(request, [
      'version',
      'scope',
      'archive',
      'monitor',
      'trust',
      'writerPublicKey',
      'destination',
    ]) &&
      request.version === 1 &&
      request.scope === 'SYNTHETIC_ONLY',
    'RECOVERY_REQUEST',
  );
  const destination = resolve(request.destination),
    parent = dirname(destination);
  recoveryDirectory(parent);
  if (existing) recoveryDirectory(destination);
  else absent(destination);
  const archive = readMigrationFile(request.archive, 64 * 1024 * 1024),
    monitor = readMigrationFile(request.monitor, 64 * 1024 * 1024);
  for (const suffix of ['-wal', '-shm', '-journal']) {
    try {
      lstatSync(request.monitor + suffix);
    } catch (e) {
      if (e.code === 'ENOENT') continue;
      throw e;
    }
    throw new Error('RECOVERY_OFFLINE_MONITOR_REQUIRED');
  }
  const trustBytes = readMigrationFile(request.trust),
    t = JSON.parse(trustBytes);
  insist(
    exactMembers(t, [
      'authorityKey',
      'custodianKey',
      'collectorKey',
      'reviewerKey',
      'manifestSha256',
      'checkpoint',
      'lease',
      'monitorWitness',
      'monitorWitnessSha256',
      'policyDigest',
    ]),
    'RECOVERY_TRUST',
  );
  const keys = [t.authorityKey, t.custodianKey, t.collectorKey, t.reviewerKey];
  keys.forEach(validateWriterPublicKey);
  insist(new Set(keys.map(keyId)).size === 4, 'RECOVERY_KEY_SEPARATION');
  const writer = validateWriterPublicKey(JSON.parse(readMigrationFile(request.writerPublicKey)));
  insist(!keys.map(keyId).includes(keyId(writer)), 'RECOVERY_KEY_SEPARATION');
  const decoded = readBackup(archive, passphrase, t.authorityKey, t.checkpoint),
    head = decoded.manifest.payload.checkpoint;
  insist(
    digest(t.manifestSha256) && hash(canonical(decoded.manifest)) === t.manifestSha256,
    'RECOVERY_MANIFEST_PIN',
  );
  insist(equal(position(t.checkpoint.payload), head), 'RECOVERY_EXACT_CHECKPOINT');
  const l = t.lease?.payload,
    inner = l?.lease?.payload;
  insist(
    signed(t.lease, t.custodianKey) &&
      exactMembers(l, ['version', 'kind', 'generation', 'writerKeyId', 'authority', 'lease']) &&
      l.version === 3 &&
      l.kind === 'FENCED_LEASE' &&
      validGeneration(l.generation) &&
      l.generation < Number.MAX_SAFE_INTEGER &&
      digest(l.writerKeyId) &&
      l.writerKeyId !== keyId(writer) &&
      signed(l.lease, t.custodianKey),
    'RECOVERY_FENCED_CUSTODY_REQUIRED',
  );
  insist(
    exactMembers(inner, [
      'version',
      'nonce',
      'authorityKeyId',
      'sequence',
      'headHash',
      'stateDigest',
      'issuedAt',
      'expiresAt',
    ]) &&
      inner.version === 1 &&
      typeof inner.nonce === 'string' &&
      inner.nonce.length > 0 &&
      inner.nonce.length <= 128 &&
      inner.authorityKeyId === keyId(t.authorityKey) &&
      equal(position(inner), head) &&
      digest(inner.stateDigest) &&
      Number.isSafeInteger(inner.issuedAt) &&
      inner.issuedAt >= 0 &&
      Number.isSafeInteger(inner.expiresAt) &&
      inner.expiresAt > inner.issuedAt,
    'RECOVERY_CUSTODY_ANCHOR',
  );
  validateAuthorityFloor(l.authority);
  const m = t.monitorWitness?.payload;
  insist(
    signed(t.monitorWitness, t.collectorKey) &&
      exactMembers(m, ['version', 'kind', 'authorityKeyId', 'checkpoint', 'databaseSha256']) &&
      m.version === 1 &&
      m.kind === 'SYNTHETIC_MONITOR_RECOVERY_SNAPSHOT' &&
      m.authorityKeyId === keyId(t.authorityKey) &&
      isPosition(m.checkpoint) &&
      equal(m.checkpoint, head) &&
      m.databaseSha256 === hash(monitor) &&
      digest(t.monitorWitnessSha256) &&
      hash(canonical(t.monitorWitness)) === t.monitorWitnessSha256,
    'RECOVERY_INDEPENDENT_MONITOR_REQUIRED',
  );
  const staging = mkdtempSync(join(parent, '.siepmu-recovery-')),
    service = join(staging, 'service');
  try {
    try {
      restore(archive, service, passphrase, t.authorityKey, { checkpoint: t.checkpoint });
    } catch (error) {
      // The bounded backup verifier now rejects these before verifyStores runs.
      // Preserve the recovery API's error contract, never retry or bypass restore.
      const code = {
        'Backup referenced ciphertext missing': 'RECOVERY_RELAY_MISSING_OBJECT',
        'Backup relay blob integrity': 'RECOVERY_RELAY_CORRUPTION',
      }[error.message];
      if (code) throw new Error(code, { cause: error });
      throw error;
    }
    mkdirSync(join(service, 'monitor'), { mode: 0o700 });
    writeFileSync(join(service, 'monitor/collector.sqlite'), monitor, { flag: 'wx', mode: 0o600 });
    const c = verifyStores(service, t);
    insist(
      c.stateDigest === inner.stateDigest && equal(c.authority, l.authority),
      'RECOVERY_CUSTODY_STATE',
    );
    const plan = {
      version: 1,
      kind: 'SYNTHETIC_GUARDED_RECOVERY_PLAN',
      scope: 'SYNTHETIC_ONLY',
      destination,
      archiveSha256: hash(archive),
      trustSha256: hash(trustBytes),
      manifestSha256: t.manifestSha256,
      monitorWitnessSha256: t.monitorWitnessSha256,
      controlDigest: c.controlDigest,
      relayDigest: c.relayDigest,
      monitorDigest: c.monitorDigest,
      previousWriterKeyId: l.writerKeyId,
      reviewerKeyId: keyId(t.reviewerKey),
      custodianKeyId: keyId(t.custodianKey),
      handover: {
        writerKey: writer,
        expectedGeneration: l.generation,
        expectedAnchor: { ...head, stateDigest: c.stateDigest },
        authority: c.authority,
      },
      policyDigest: t.policyDigest,
      objects: c.objects,
      monitoringEvents: c.monitoringEvents,
      files: { ...decoded.manifest.payload.files, 'monitor/collector.sqlite': hash(monitor) },
      activation: 'QUARANTINED_UNTIL_REVIEWED_HANDOVER_AND_FRESH_LEASE',
    };
    return { staging, service, plan, t };
  } catch (e) {
    rmSync(staging, { recursive: true, force: true });
    throw e;
  }
}
export function inspectGuardedRecovery(request, { passphrase } = {}) {
  const p = prepare(request, passphrase);
  try {
    return { plan: p.plan, planDigest: hash(canonical(p.plan)) };
  } finally {
    rmSync(p.staging, { recursive: true, force: true });
  }
}
export function checkRecoveryApproval(plan, approval, reviewerKey) {
  const a = approval?.payload;
  insist(
    signed(approval, reviewerKey) &&
      keyId(reviewerKey) === plan.reviewerKeyId &&
      exactMembers(a, [
        'version',
        'kind',
        'planDigest',
        'reviewer',
        'currentPolicyConfirmed',
        'latestCustodyConfirmed',
        'independentSnapshotsConfirmed',
        'writersStoppedConfirmed',
        'expiresAt',
      ]) &&
      a.version === 1 &&
      a.kind === 'SYNTHETIC_RECOVERY_APPROVAL' &&
      a.planDigest === hash(canonical(plan)) &&
      typeof a.reviewer === 'string' &&
      a.reviewer.trim().length > 0 &&
      a.reviewer.length <= 128 &&
      a.currentPolicyConfirmed === true &&
      a.latestCustodyConfirmed === true &&
      a.independentSnapshotsConfirmed === true &&
      a.writersStoppedConfirmed === true &&
      Number.isSafeInteger(a.expiresAt) &&
      a.expiresAt > Date.now(),
    'RECOVERY_OPERATOR_REVIEW_REQUIRED',
  );
}
export async function stageGuardedRecovery(
  request,
  { passphrase, approval, onPhase = () => {} } = {},
) {
  approval = structuredClone(approval);
  const p = prepare(request, passphrase);
  try {
    checkRecoveryApproval(p.plan, approval, p.t.reviewerKey);
    await onPhase('verified');
    for (const [name, value] of Object.entries({
      'recovery-plan.json': p.plan,
      'recovery-approval.json': approval,
    }))
      writeFileSync(join(p.service, name), canonical(value), { flag: 'wx', mode: 0o600 });
    for (const name of [
      ...Object.keys(p.plan.files),
      'recovery-plan.json',
      'recovery-approval.json',
      'relay',
      'monitor',
      '.',
    ])
      sync(join(p.service, name));
    checkRecoveryApproval(p.plan, approval, p.t.reviewerKey);
    absent(p.plan.destination);
    renameSync(p.service, p.plan.destination);
    sync(dirname(p.plan.destination));
    return { plan: p.plan, planDigest: hash(canonical(p.plan)) };
  } finally {
    rmSync(p.staging, { recursive: true, force: true });
  }
}
export function reviewRecoveryResume(request, { passphrase, expectedPlanDigest, approval } = {}) {
  insist(digest(expectedPlanDigest), 'RECOVERY_RETAINED_PLAN_REQUIRED');
  const p = prepare(request, passphrase, true);
  try {
    insist(hash(canonical(p.plan)) === expectedPlanDigest, 'RECOVERY_PLAN_MISMATCH');
    checkRecoveryApproval(p.plan, approval, p.t.reviewerKey);
    insist(
      equal(
        JSON.parse(readMigrationFile(join(p.plan.destination, 'recovery-plan.json'))),
        p.plan,
      ) &&
        equal(
          JSON.parse(readMigrationFile(join(p.plan.destination, 'recovery-approval.json'))),
          approval,
        ),
      'RECOVERY_JOURNAL_MISMATCH',
    );
    return { plan: p.plan, trust: p.t };
  } finally {
    rmSync(p.staging, { recursive: true, force: true });
  }
}
export function verifyRecoveryHandover(plan, receipt, key) {
  const p = receipt?.payload,
    h = plan.handover;
  insist(
    keyId(key) === plan.custodianKeyId &&
      signed(receipt, key) &&
      exactMembers(p, [
        'version',
        'kind',
        'generation',
        'writerKeyId',
        'previousWriterKeyId',
        'anchor',
        'authority',
        'issuedAt',
      ]) &&
      p.version === 1 &&
      p.kind === 'WRITER_HANDOVER' &&
      p.generation === h.expectedGeneration + 1 &&
      p.writerKeyId === keyId(h.writerKey) &&
      p.previousWriterKeyId === plan.previousWriterKeyId &&
      equal(p.anchor, h.expectedAnchor) &&
      equal(p.authority, h.authority) &&
      Number.isSafeInteger(p.issuedAt) &&
      p.issuedAt >= 0,
    'RECOVERY_HANDOVER_RECEIPT',
  );
  return p.generation;
}
export function reconcileRecoveryHandover(
  custody,
  plan,
  approval,
  trust,
  { perform = false } = {},
) {
  checkRecoveryApproval(plan, approval, trust.reviewerKey);
  insist(
    !custody.allowBootstrap &&
      custody.requireFencing &&
      keyId(custody.key) === keyId(trust.custodianKey) &&
      keyId(custody.authorityKey) === keyId(trust.authorityKey),
    'RECOVERY_INDEPENDENT_CUSTODY_REQUIRED',
  );
  const h = plan.handover,
    f = custody.db.prepare('SELECT * FROM writer_fence WHERE id=1').get();
  insist(f, 'RECOVERY_FENCE_MISSING');
  if (f.generation === h.expectedGeneration) {
    insist(perform, 'RECOVERY_HANDOVER_REQUIRED');
    insist(
      keyId(JSON.parse(f.public_key)) === plan.previousWriterKeyId,
      'RECOVERY_PREVIOUS_WRITER_CHANGED',
    );
    const r = custody.transferWriter(h);
    verifyRecoveryHandover(plan, r, trust.custodianKey);
    return r;
  }
  insist(
    f.generation === h.expectedGeneration + 1 &&
      keyId(JSON.parse(f.public_key)) === keyId(h.writerKey) &&
      f.epoch === h.authority.epoch &&
      f.revocation_version === h.authority.revocationVersion,
    'RECOVERY_WRITER_CHANGED',
  );
  const anchor = custody.db.prepare('SELECT * FROM anchor WHERE id=1').get();
  insist(
    anchor &&
      equal(
        { ...position(JSON.parse(anchor.checkpoint).payload), stateDigest: anchor.state },
        h.expectedAnchor,
      ),
    'RECOVERY_ANCHOR_ADVANCED',
  );
  const row = custody.db
    .prepare('SELECT receipt FROM fence_history WHERE generation=?')
    .get(f.generation);
  insist(row, 'RECOVERY_HANDOVER_EVIDENCE_MISSING');
  const r = JSON.parse(row.receipt);
  verifyRecoveryHandover(plan, r, trust.custodianKey);
  return r;
}
export function verifyRecoveryWorkingSet(plan, trust) {
  recoveryDirectory(plan.destination);
  for (const [name, expected] of Object.entries(plan.files)) {
    const bytes = readMigrationFile(join(plan.destination, name), 64 * 1024 * 1024);
    if (!name.endsWith('.sqlite'))
      insist(hash(bytes) === expected, 'RECOVERY_KEY_MATERIAL_CHANGED');
  }
  const c = verifyStores(plan.destination, trust);
  insist(
    equal(c.checkpoint, position(plan.handover.expectedAnchor)) &&
      c.stateDigest === plan.handover.expectedAnchor.stateDigest &&
      c.controlDigest === plan.controlDigest &&
      c.relayDigest === plan.relayDigest &&
      c.monitorDigest === plan.monitorDigest &&
      equal(c.authority, plan.handover.authority),
    'RECOVERY_REVIEW_SUPERSEDED',
  );
  return c;
}
