#!/usr/bin/env node
// Explicit, offline, synthetic-only candidate builder. Never imported by service startup.
import {
  constants,
  openSync,
  closeSync,
  fstatSync,
  readSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  lstatSync,
  realpathSync,
  existsSync,
  mkdtempSync,
  rmSync,
  renameSync,
  fsyncSync,
} from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { readBackup } from './backup.mjs';
import { verifyEvidenceRecords } from '../apps/verifier/verify.mjs';
import { exactMembers, isPosition } from '../services/evidence/incremental.mjs';
import { validateAuthorityFloor, validateWriterPublicKey } from '../services/evidence/fencing.mjs';
import {
  authorizationDigest,
  sealAuthorizationCommit,
  assertAuthorizationCommit,
} from '../services/evidence/authorization-state.mjs';
import { CryptoPolicyRegistry } from '../services/crypto-policy/registry.mjs';
import { canonical, hash, packet, verifyPacket, keyId } from '../services/control/primitives.mjs';

const insist = (ok, code) => {
  if (!ok) throw new Error(code);
};
const digest = (v) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const migrations = [
  '001-initial.sql',
  '002-observability.sql',
  '003-duty-roles.sql',
  '004-release-approvals.sql',
  '005-crypto-policy.sql',
  '006-alert-epoch.sql',
  '007-authorization-commit.sql',
];
const sqlFor = (name) =>
  readFileSync(new URL('../database/migrations/' + name, import.meta.url), 'utf8');
const migrationTable =
  'CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)';
const files = [
  'control.sqlite',
  'server-key.json',
  'master.key',
  'relay.secret',
  'public-key.json',
  'relay/relay.sqlite',
];
const packetShape = (p) => exactMembers(p, ['payload', 'signature', 'keyId']);
const candidateFiles = [
  'control.sqlite',
  'plan.json',
  'approval.json',
  'receipt.json',
  'handover-request.json',
];

/** Bounded, same-descriptor read. Inputs must be private, owner-held regular files. */
export function readMigrationFile(path, limit = 1048576) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    insist(
      st.isFile() &&
        st.uid === process.getuid() &&
        st.nlink === 1 &&
        !(st.mode & 0o077) &&
        st.size <= limit,
      'MIGRATION_PRIVATE_FILE_REQUIRED',
    );
    const bytes = Buffer.alloc(limit + 1);
    let length = 0,
      n;
    while (length < bytes.length && (n = readSync(fd, bytes, length, bytes.length - length, null)))
      length += n;
    insist(length <= limit, 'MIGRATION_INPUT_TOO_LARGE');
    return bytes.subarray(0, length);
  } finally {
    closeSync(fd);
  }
}
const jsonFile = (p) => JSON.parse(readMigrationFile(p));
function privateDirectory(path) {
  const st = lstatSync(path);
  insist(
    st.isDirectory() &&
      !st.isSymbolicLink() &&
      st.uid === process.getuid() &&
      !(st.mode & 0o077) &&
      realpathSync(path) === path,
    'MIGRATION_PRIVATE_PARENT_REQUIRED',
  );
}
function destinationParent(destination) {
  const parent = dirname(destination);
  privateDirectory(parent);
  // lexists, including a dangling symlink; an existing destination is never replaced.
  try {
    lstatSync(destination);
  } catch (e) {
    if (e.code === 'ENOENT') return parent;
    throw e;
  }
  throw new Error('MIGRATION_DESTINATION_EXISTS');
}
function facade(db, publicKey, signingKey) {
  return {
    publicKey,
    key: signingKey,
    get: (sql, ...args) => db.prepare(sql).get(...args),
    all: (sql, ...args) => db.prepare(sql).all(...args),
    run: (sql, ...args) => db.prepare(sql).run(...args),
    epoch: () => db.prepare('SELECT * FROM authority WHERE id=1').get(),
    checkpoint: () => {
      const r = db
        .prepare('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1')
        .get();
      return { payload: { sequence: r?.sequence ?? 0, headHash: r?.hash ?? '0'.repeat(64) } };
    },
    crypto: new CryptoPolicyRegistry(db, false),
  };
}
// Exactly the PR #40 profile; deliberately never equated with authorization-state V2.
function legacyDigest(a) {
  return hash(
    canonical({
      authority: a.epoch(),
      users: a.all('SELECT id,unit_id,role,missions,active,duty_role FROM users ORDER BY id'),
      devices: a.all(
        'SELECT id,user_id,signing_key,encryption_key,status FROM devices ORDER BY id',
      ),
      policies: a.all('SELECT * FROM policies ORDER BY from_unit,to_unit,mission_id'),
    }),
  );
}
function checkSchema(db, sealed = false) {
  const rows = db.prepare('SELECT * FROM schema_migrations ORDER BY version').all();
  insist((sealed ? [7] : [6, 7]).includes(rows.length), 'MIGRATION_UNSUPPORTED_SCHEMA');
  const expected = new DatabaseSync(':memory:');
  try {
    expected.exec(migrationTable);
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i],
        sql = sqlFor(migrations[i]);
      insist(
        r.version === migrations[i] &&
          r.checksum === hash(sql) &&
          Number.isSafeInteger(r.applied_at) &&
          r.applied_at >= 0,
        'MIGRATION_SCHEMA_CHECKSUM',
      );
      expected.exec(sql);
    }
    const schema = (d) =>
      d.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name').all();
    insist(canonical(schema(db)) === canonical(schema(expected)), 'MIGRATION_SCHEMA_SHAPE');
    if (rows.length === 7)
      insist(
        db.prepare('SELECT count(*) n FROM authorization_commit').get().n === (sealed ? 1 : 0),
        sealed ? 'MIGRATION_SEAL_REQUIRED' : 'MIGRATION_ALREADY_SEALED',
      );
  } finally {
    expected.close();
  }
  return rows.length;
}
function verifyHistory(db, authorityKey, checkpoint, head) {
  let lastEpoch = 0;
  function* records() {
    for (const row of db
      .prepare('SELECT sequence,record,hash FROM evidence ORDER BY sequence')
      .iterate()) {
      const record = JSON.parse(row.record),
        p = record.payload;
      insist(
        row.sequence === p?.sequence && hash(canonical(record)) === row.hash,
        'MIGRATION_EVIDENCE_ROW',
      );
      insist(
        Number.isSafeInteger(p.epoch) && p.epoch >= lastEpoch && p.epoch > 0,
        'MIGRATION_EPOCH_HISTORY',
      );
      lastEpoch = p.epoch;
      yield record;
    }
  }
  const result = verifyEvidenceRecords(records(), authorityKey, { checkpoint });
  insist(
    result.records === head.sequence && result.headHash === head.headHash,
    'MIGRATION_HEAD_MISMATCH',
  );
  insist(
    lastEpoch === db.prepare('SELECT epoch FROM authority WHERE id=1').get().epoch,
    'MIGRATION_POLICY_HISTORY',
  );
}
function verifyTrust(t) {
  insist(
    exactMembers(t, [
      'version',
      'scope',
      'authorityKey',
      'custodianKey',
      'reviewerKey',
      'checkpoint',
      'lease',
      'manifest',
      'retainedManifestSha256',
      'expectedPolicyDigest',
      'allowPqcLab',
    ]) &&
      t.version === 1 &&
      t.scope === 'SYNTHETIC_ONLY' &&
      t.allowPqcLab === false,
    'MIGRATION_TRUST_PROFILE',
  );
  for (const k of [t.authorityKey, t.custodianKey, t.reviewerKey]) validateWriterPublicKey(k);
  insist(
    new Set([t.authorityKey, t.custodianKey, t.reviewerKey].map(keyId)).size === 3,
    'MIGRATION_KEY_SEPARATION',
  );
  insist(
    packetShape(t.checkpoint) &&
      verifyPacket(t.authorityKey, t.checkpoint) &&
      exactMembers(t.checkpoint.payload, ['sequence', 'headHash', 'issuedAt']) &&
      isPosition({
        sequence: t.checkpoint.payload.sequence,
        headHash: t.checkpoint.payload.headHash,
      }) &&
      Number.isSafeInteger(t.checkpoint.payload.issuedAt) &&
      t.checkpoint.payload.issuedAt >= 0,
    'MIGRATION_CHECKPOINT_REQUIRED',
  );
  const m = t.manifest?.payload;
  insist(
    packetShape(t.manifest) &&
      verifyPacket(t.authorityKey, t.manifest) &&
      exactMembers(m, ['format', 'createdAt', 'checkpoint', 'files']) &&
      m.format === 'SIEPMU_BACKUP_V1' &&
      Number.isSafeInteger(m.createdAt) &&
      m.createdAt >= 0 &&
      isPosition(m.checkpoint) &&
      exactMembers(m.files, files) &&
      Object.values(m.files).every(digest) &&
      digest(t.retainedManifestSha256) &&
      hash(canonical(t.manifest)) === t.retainedManifestSha256,
    'MIGRATION_INDEPENDENT_MANIFEST_REQUIRED',
  );
  const l = t.lease?.payload;
  // Historical receipt, NOT a live serving lease. Its expiry is not renewed or ignored at runtime.
  insist(
    packetShape(t.lease) &&
      verifyPacket(t.custodianKey, t.lease) &&
      exactMembers(l, [
        'version',
        'nonce',
        'authorityKeyId',
        'sequence',
        'headHash',
        'stateDigest',
        'issuedAt',
        'expiresAt',
      ]) &&
      l.version === 1 &&
      typeof l.nonce === 'string' &&
      l.nonce.length > 0 &&
      l.nonce.length <= 128 &&
      l.authorityKeyId === keyId(t.authorityKey) &&
      digest(l.stateDigest) &&
      Number.isSafeInteger(l.issuedAt) &&
      l.issuedAt >= 0 &&
      Number.isSafeInteger(l.expiresAt) &&
      l.expiresAt > l.issuedAt,
    'MIGRATION_CUSTODY_RECEIPT_REQUIRED',
  );
  for (const h of [t.checkpoint.payload, l])
    insist(
      h.sequence === m.checkpoint.sequence && h.headHash === m.checkpoint.headHash,
      'MIGRATION_EXACT_ANCHOR_REQUIRED',
    );
  insist(digest(t.expectedPolicyDigest), 'MIGRATION_POLICY_REVIEW_REQUIRED');
}
function prepare(request, passphrase, existingCandidate = false) {
  insist(
    exactMembers(request, ['sourceType', 'source', 'destination', 'trust', 'writerPublicKey']) &&
      ['database', 'backup'].includes(request.sourceType),
    'MIGRATION_REQUEST',
  );
  const destination = resolve(request.destination),
    parent = dirname(destination);
  if (existingCandidate) {
    privateDirectory(parent);
    privateDirectory(destination);
  } else destinationParent(destination);
  if (request.sourceType === 'database') {
    for (const suffix of ['-wal', '-shm', '-journal'])
      insist(!existsSync(request.source + suffix), 'MIGRATION_OFFLINE_SNAPSHOT_REQUIRED');
  }
  const source = readMigrationFile(request.source, 64 * 1024 * 1024);
  const trustBytes = readMigrationFile(request.trust),
    t = JSON.parse(trustBytes);
  verifyTrust(t);
  const writerKey = validateWriterPublicKey(jsonFile(request.writerPublicKey));
  insist(
    ![t.authorityKey, t.custodianKey, t.reviewerKey].map(keyId).includes(keyId(writerKey)),
    'MIGRATION_KEY_SEPARATION',
  );
  let database = source;
  if (request.sourceType === 'backup') {
    const decoded = readBackup(source, passphrase, t.authorityKey, t.checkpoint);
    insist(
      hash(canonical(decoded.manifest)) === t.retainedManifestSha256,
      'MIGRATION_ARCHIVE_MANIFEST_MISMATCH',
    );
    database = decoded.decoded.get('control.sqlite');
  }
  insist(
    hash(database) === t.manifest.payload.files['control.sqlite'],
    'MIGRATION_SNAPSHOT_MISMATCH',
  );
  const staging = mkdtempSync(join(parent, '.siepmu-migration-'));
  let db;
  try {
    writeFileSync(join(staging, 'control.sqlite'), database, { flag: 'wx', mode: 0o600 });
    db = new DatabaseSync(join(staging, 'control.sqlite'));
    db.exec('PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;');
    insist(
      canonical(db.prepare('PRAGMA quick_check').all()) === canonical([{ quick_check: 'ok' }]) &&
        db.prepare('PRAGMA foreign_key_check').all().length === 0,
      'MIGRATION_DATABASE_INTEGRITY',
    );
    const schemaVersion = checkSchema(db),
      a = facade(db, t.authorityKey);
    const head = a.checkpoint().payload;
    verifyHistory(db, t.authorityKey, t.checkpoint, head);
    insist(
      head.sequence === t.lease.payload.sequence && head.headHash === t.lease.payload.headHash,
      'MIGRATION_EXACT_ANCHOR_REQUIRED',
    );
    insist(legacyDigest(a) === t.lease.payload.stateDigest, 'MIGRATION_LEGACY_STATE_MISMATCH');
    const policy = a.crypto.validatePolicy(a.crypto.policy());
    insist(
      policy.mode === 'production' && a.all('SELECT * FROM crypto_keys').length === 0,
      'MIGRATION_CLASSICAL_PROFILE_ONLY',
    );
    const policyDigest = hash(canonical(policy));
    insist(policyDigest === t.expectedPolicyDigest, 'MIGRATION_POLICY_MISMATCH');
    const row = a.epoch(),
      authority = { epoch: row.epoch, revocationVersion: row.revocation_version };
    validateAuthorityFloor(authority);
    const plan = {
      version: 1,
      kind: 'LEGACY_MIGRATION_PLAN',
      scope: 'SYNTHETIC_ONLY',
      sourceType: request.sourceType,
      sourceSha256: hash(source),
      trustSha256: hash(trustBytes),
      destination,
      schemaVersion,
      authorityKeyId: keyId(t.authorityKey),
      custodianKeyId: keyId(t.custodianKey),
      reviewerKeyId: keyId(t.reviewerKey),
      writerKeyId: keyId(writerKey),
      checkpoint: head,
      authority,
      legacyStateDigest: legacyDigest(a),
      stateDigest: authorizationDigest(a),
      policyDigest,
      retainedManifestSha256: t.retainedManifestSha256,
      activation: 'QUARANTINED_PENDING_INDEPENDENT_WRITER_HANDOVER',
    };
    return { staging, db, a, t, writerKey, plan };
  } catch (e) {
    db?.close();
    rmSync(staging, { recursive: true, force: true });
    throw e;
  }
}
export function inspectLegacyMigration(request, { passphrase } = {}) {
  const p = prepare(request, passphrase);
  try {
    return { plan: p.plan, planDigest: hash(canonical(p.plan)) };
  } finally {
    p.db.close();
    rmSync(p.staging, { recursive: true, force: true });
  }
}
// The only permitted logical changes are migration 007, one appended event and its seal.
// Include non-authorization data too: a valid V2 seal cannot detect changed object/counter rows.
function preservedDigest(db, plan) {
  return hash(
    canonical(
      db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .all()
        .filter(({ name }) => name !== 'authorization_commit')
        .map(({ name }) => {
          // Table names have already been checked against the exact trusted schema.
          const where =
            name === 'evidence'
              ? ' WHERE sequence<=?'
              : name === 'schema_migrations' && plan.schemaVersion === 6
                ? ' WHERE version!=?'
                : '';
          const args =
            name === 'evidence' ? [plan.checkpoint.sequence] : where ? [migrations[6]] : [];
          return [name, db.prepare(`SELECT * FROM "${name}"${where} ORDER BY rowid`).all(...args)];
        }),
    ),
  );
}
function checkApproval(approval, t, plan) {
  const review = approval?.payload;
  insist(
    packetShape(approval) &&
      verifyPacket(t.reviewerKey, approval) &&
      exactMembers(review, [
        'version',
        'kind',
        'planDigest',
        'stateDigest',
        'reviewer',
        'scope',
        'independentSnapshotConfirmed',
        'latestCheckpointConfirmed',
        'currentPolicyConfirmed',
        'maintenanceConfirmed',
        'expiresAt',
      ]) &&
      review.version === 1 &&
      review.kind === 'LEGACY_MIGRATION_APPROVAL' &&
      review.scope === 'SYNTHETIC_ONLY' &&
      review.planDigest === hash(canonical(plan)) &&
      review.stateDigest === plan.stateDigest &&
      typeof review.reviewer === 'string' &&
      review.reviewer.trim().length > 0 &&
      review.reviewer.length <= 128 &&
      review.independentSnapshotConfirmed === true &&
      review.latestCheckpointConfirmed === true &&
      review.currentPolicyConfirmed === true &&
      review.maintenanceConfirmed === true &&
      Number.isSafeInteger(review.expiresAt) &&
      review.expiresAt > Date.now(),
    'MIGRATION_OPERATOR_APPROVAL_REQUIRED',
  );
  return review;
}
function handoverRequest(p) {
  return {
    writerKey: p.writerKey,
    expectedGeneration: 0,
    expectedAnchor: { ...p.plan.checkpoint, stateDigest: p.plan.legacyStateDigest },
    authority: p.plan.authority,
  };
}
/** Public-key-only verification against original evidence and an independently retained plan pin.
 * Does not open the supplied candidate with SQLite, refresh approval, mutate custody or activate. */
export function verifyLegacyMigration(request, { expectedPlanDigest, passphrase } = {}) {
  insist(digest(expectedPlanDigest), 'MIGRATION_RETAINED_PLAN_REQUIRED');
  const p = prepare(request, passphrase, true);
  let db;
  try {
    insist(hash(canonical(p.plan)) === expectedPlanDigest, 'MIGRATION_RETAINED_PLAN_MISMATCH');
    insist(
      canonical(readdirSync(p.plan.destination).sort()) === canonical([...candidateFiles].sort()),
      'MIGRATION_CANDIDATE_FILES',
    );
    const records = Object.fromEntries(
      candidateFiles.map((name) => [
        name,
        readMigrationFile(
          join(p.plan.destination, name),
          name === 'control.sqlite' ? 64 * 1024 * 1024 : 1048576,
        ),
      ]),
    );
    insist(
      canonical(JSON.parse(records['plan.json'])) === canonical(p.plan),
      'MIGRATION_PLAN_MISMATCH',
    );
    const approval = JSON.parse(records['approval.json']),
      review = checkApproval(approval, p.t, p.plan),
      receipt = JSON.parse(records['receipt.json']),
      r = receipt?.payload;
    insist(
      packetShape(receipt) &&
        verifyPacket(p.t.authorityKey, receipt) &&
        exactMembers(r, [
          'version',
          'kind',
          'planDigest',
          'approvalDigest',
          'checkpoint',
          'databaseSha256',
          'activation',
        ]) &&
        r.version === 1 &&
        r.kind === 'LEGACY_MIGRATION_CANDIDATE' &&
        r.planDigest === expectedPlanDigest &&
        r.approvalDigest === hash(canonical(approval)) &&
        r.databaseSha256 === hash(records['control.sqlite']) &&
        r.activation === p.plan.activation,
      'MIGRATION_RECEIPT_MISMATCH',
    );
    insist(
      canonical(JSON.parse(records['handover-request.json'])) === canonical(handoverRequest(p)),
      'MIGRATION_HANDOVER_MISMATCH',
    );
    const candidate = join(p.staging, 'candidate.sqlite');
    writeFileSync(candidate, records['control.sqlite'], { flag: 'wx', mode: 0o600 });
    db = new DatabaseSync(candidate, { readOnly: true });
    db.exec('PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;');
    insist(
      canonical(db.prepare('PRAGMA quick_check').all()) === canonical([{ quick_check: 'ok' }]) &&
        db.prepare('PRAGMA foreign_key_check').all().length === 0,
      'MIGRATION_DATABASE_INTEGRITY',
    );
    checkSchema(db, true);
    const a = facade(db, p.t.authorityKey),
      head = a.checkpoint().payload;
    verifyHistory(db, p.t.authorityKey, p.t.checkpoint, head);
    verifyHistory(db, p.t.authorityKey, r.checkpoint, head);
    insist(
      r.checkpoint.payload.sequence === head.sequence &&
        r.checkpoint.payload.headHash === head.headHash &&
        head.sequence === p.plan.checkpoint.sequence + 1,
      'MIGRATION_CANDIDATE_HEAD',
    );
    assertAuthorizationCommit(a);
    insist(authorizationDigest(a) === p.plan.stateDigest, 'MIGRATION_STATE_CHANGED');
    insist(
      preservedDigest(db, p.plan) === preservedDigest(p.db, p.plan),
      'MIGRATION_PRESERVED_DATA_CHANGED',
    );
    const event = JSON.parse(
      a.get('SELECT record FROM evidence WHERE sequence=?', head.sequence).record,
    ).payload;
    insist(
      exactMembers(event, [
        'sequence',
        'previousHash',
        'eventId',
        'eventType',
        'timestamp',
        'epoch',
        'actorId',
        'details',
      ]) &&
        event.eventType === 'LEGACY_AUTHORIZATION_MIGRATED' &&
        event.previousHash === p.plan.checkpoint.headHash &&
        typeof event.eventId === 'string' &&
        event.eventId.length > 0 &&
        event.eventId.length <= 128 &&
        Number.isSafeInteger(event.timestamp) &&
        event.timestamp >= 0 &&
        event.timestamp <= Date.now() &&
        event.timestamp < review.expiresAt &&
        event.epoch === p.plan.authority.epoch &&
        event.actorId === review.reviewer &&
        canonical(event.details) ===
          canonical({
            planDigest: expectedPlanDigest,
            approvalDigest: r.approvalDigest,
            stateDigest: p.plan.stateDigest,
            retainedManifestSha256: p.plan.retainedManifestSha256,
          }),
      'MIGRATION_EVENT_MISMATCH',
    );
    insist(review.expiresAt > Date.now(), 'MIGRATION_APPROVAL_EXPIRED');
    return {
      version: 1,
      kind: 'LEGACY_MIGRATION_VERIFICATION',
      scope: 'SYNTHETIC_ONLY',
      status: 'VERIFIED_QUARANTINED',
      planDigest: expectedPlanDigest,
      receiptDigest: hash(canonical(receipt)),
      databaseSha256: r.databaseSha256,
      checkpoint: r.checkpoint,
      writerKeyId: p.plan.writerKeyId,
      activation: p.plan.activation,
    };
  } finally {
    db?.close();
    p.db.close();
    rmSync(p.staging, { recursive: true, force: true });
  }
}
export async function applyLegacyMigration(
  request,
  { approval, signingKey, passphrase, onPhase = () => {} } = {},
) {
  approval = structuredClone(approval);
  signingKey = structuredClone(signingKey);
  const p = prepare(request, passphrase);
  let closed = false;
  try {
    const planDigest = hash(canonical(p.plan)),
      review = checkApproval(approval, p.t, p.plan),
      preserved = preservedDigest(p.db, p.plan);
    insist(
      signingKey?.d &&
        verifyPacket(p.t.authorityKey, packet(signingKey, { kind: 'MIGRATION_KEY_CHECK' })),
      'MIGRATION_AUTHORITY_KEY',
    );
    p.a.key = signingKey;
    await onPhase('staged', p.staging);
    insist(review.expiresAt > Date.now(), 'MIGRATION_APPROVAL_EXPIRED');
    p.db.exec('BEGIN IMMEDIATE');
    try {
      if (p.plan.schemaVersion === 6) {
        const sql = sqlFor(migrations[6]);
        p.db.exec(sql);
        p.a.run(
          'INSERT INTO schema_migrations VALUES(?,?,?)',
          migrations[6],
          hash(sql),
          Date.now(),
        );
      }
      const event = packet(signingKey, {
        sequence: p.plan.checkpoint.sequence + 1,
        previousHash: p.plan.checkpoint.headHash,
        eventId: randomUUID(),
        eventType: 'LEGACY_AUTHORIZATION_MIGRATED',
        timestamp: Date.now(),
        epoch: p.plan.authority.epoch,
        actorId: review.reviewer,
        details: {
          planDigest,
          approvalDigest: hash(canonical(approval)),
          stateDigest: p.plan.stateDigest,
          retainedManifestSha256: p.plan.retainedManifestSha256,
        },
      });
      p.a.run(
        'INSERT INTO evidence VALUES(?,?,?)',
        event.payload.sequence,
        canonical(event),
        hash(canonical(event)),
      );
      await onPhase('uncommitted', p.staging);
      insist(review.expiresAt > Date.now(), 'MIGRATION_APPROVAL_EXPIRED');
      sealAuthorizationCommit(p.a);
      insist(authorizationDigest(p.a) === p.plan.stateDigest, 'MIGRATION_STATE_CHANGED');
      p.db.exec('COMMIT');
    } catch (e) {
      if (p.db.isTransaction) p.db.exec('ROLLBACK');
      throw e;
    }
    await onPhase('sealed', p.staging);
    checkSchema(p.db, true);
    assertAuthorizationCommit(p.a);
    insist(preservedDigest(p.db, p.plan) === preserved, 'MIGRATION_PRESERVED_DATA_CHANGED');
    verifyHistory(p.db, p.t.authorityKey, p.t.checkpoint, p.a.checkpoint().payload);
    const checkpoint = packet(signingKey, { ...p.a.checkpoint().payload, issuedAt: Date.now() });
    p.db.exec('PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;');
    p.db.close();
    closed = true;
    const receipt = packet(signingKey, {
      version: 1,
      kind: 'LEGACY_MIGRATION_CANDIDATE',
      planDigest,
      approvalDigest: hash(canonical(approval)),
      checkpoint,
      databaseSha256: hash(readFileSync(join(p.staging, 'control.sqlite'))),
      activation: p.plan.activation,
    });
    // A request only. No custodian mutation, service restart, live lease or private writer key.
    const handover = handoverRequest(p);
    for (const [name, value] of Object.entries({
      'plan.json': p.plan,
      'approval.json': approval,
      'receipt.json': receipt,
      'handover-request.json': handover,
    }))
      writeFileSync(join(p.staging, name), canonical(value) + '\n', { flag: 'wx', mode: 0o600 });
    for (const name of [...candidateFiles, '.']) {
      const fd = openSync(join(p.staging, name), constants.O_RDONLY);
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    }
    insist(review.expiresAt > Date.now(), 'MIGRATION_APPROVAL_EXPIRED');
    destinationParent(p.plan.destination);
    renameSync(p.staging, p.plan.destination);
    const fd = openSync(dirname(p.plan.destination), constants.O_RDONLY);
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return receipt;
  } finally {
    if (!closed) p.db.close();
    rmSync(p.staging, { recursive: true, force: true });
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [command, requestPath, approvalPath, signingPath, ...extra] = process.argv.slice(2);
    insist(
      !extra.length &&
        (command === 'inspect'
          ? !approvalPath && !signingPath
          : command === 'verify'
            ? approvalPath && !signingPath
            : command === 'apply' && approvalPath && signingPath),
      'Usage: legacy-migration.mjs inspect REQUEST | apply REQUEST APPROVAL AUTHORITY_PRIVATE_KEY | verify REQUEST RETAINED_PLAN_SHA256',
    );
    const request = jsonFile(requestPath),
      passphrase = process.env.SIEPMU_BACKUP_PASSPHRASE;
    const result =
      command === 'inspect'
        ? inspectLegacyMigration(request, { passphrase })
        : command === 'verify'
          ? verifyLegacyMigration(request, { passphrase, expectedPlanDigest: approvalPath })
          : await applyLegacyMigration(request, {
              passphrase,
              approval: jsonFile(approvalPath),
              signingKey: jsonFile(signingPath),
            });
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    console.error(
      'MIGRATION_REJECTED: inspect private inputs, independent evidence and operator approval; no automatic retry',
    );
    process.exitCode = 1;
  }
}
