// Synthetic legacy schema/receipt format from PR #40 (62b8e66). No production data.
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { initDemo } from '../../scripts/bootstrap.mjs';
import { backup, readBackup } from '../../scripts/backup.mjs';
import { Authority } from '../../services/control/core.mjs';
import { createRelayServer } from '../../services/relay/server.mjs';
import { CheckpointCustodian, authoritySnapshot } from '../../services/evidence/custody.mjs';
import { packet, hash, canonical } from '../../services/control/primitives.mjs';
import { pair, ApiClient, coreTransport } from './client.mjs';
import { inspectLegacyMigration } from '../../scripts/legacy-migration.mjs';
export const privateJson = (path, value) => writeFileSync(path, canonical(value), { mode: 0o600 });
export async function legacyFixture(t, schema = 6) {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-migration-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const data = join(root, 'source'),
    provisioned = await initDemo(data);
  const key = JSON.parse(readFileSync(join(data, 'server-key.json')));
  const a = new Authority({
    dbPath: join(data, 'control.sqlite'),
    signingKey: key,
    masterKey: readFileSync(join(data, 'master.key')),
  });
  const alice = new ApiClient(
    coreTransport(a),
    provisioned.profiles.find((p) => p.username === 'alice'),
  );
  await alice.authenticate();
  await alice.grant();
  await alice.request('POST', '/api/auth/logout', {});
  a.tx(() => {
    a.run(
      "UPDATE devices SET status='revoked' WHERE id=?",
      provisioned.profiles.find((p) => p.username === 'eve').deviceId,
    );
    a.run('UPDATE authority SET epoch=epoch+1,revocation_version=revocation_version+1');
    const policy = a.crypto.policy();
    a.run(
      'UPDATE crypto_policy SET value=?',
      canonical({ ...policy, revision: 2, newSuites: [], legacySuites: [] }),
    );
    a.event('LEGACY_FIXTURE_POLICY', 'synthetic');
  });
  const state = hash(
    canonical({
      authority: a.epoch(),
      users: a.all('SELECT id,unit_id,role,missions,active,duty_role FROM users ORDER BY id'),
      devices: a.all(
        'SELECT id,user_id,signing_key,encryption_key,status FROM devices ORDER BY id',
      ),
      policies: a.all('SELECT * FROM policies ORDER BY from_unit,to_unit,mission_id'),
    }),
  );
  const custodyKeys = pair(),
    reviewer = pair(),
    writer = pair();
  const custody = new CheckpointCustodian({
    database: ':memory:',
    authorityKey: a.publicKey,
    signingKey: custodyKeys.privateKey,
    allowBootstrap: true,
  });
  t.after(() => custody.close());
  const checkpoint = a.checkpoint(),
    policyDigest = hash(canonical(a.crypto.policy()));
  const lease = await custody.accept(
    packet(key, {
      version: 1,
      nonce: 'synthetic-legacy',
      issuedAt: Date.now(),
      stateDigest: state,
      evidence: authoritySnapshot(a),
    }),
  );
  a.close();
  const db = new DatabaseSync(join(data, 'control.sqlite'));
  if (schema === 6)
    db.exec(
      "DROP TABLE authorization_commit; DELETE FROM schema_migrations WHERE version='007-authorization-commit.sql';",
    );
  else db.exec('DELETE FROM authorization_commit');
  db.close();
  const relay = createRelayServer({
    database: join(data, 'relay', 'relay.sqlite'),
    secret: Buffer.from(readFileSync(join(data, 'relay.secret'), 'utf8'), 'hex'),
  });
  relay.close();
  const archive = join(root, 'legacy.backup.json'),
    passphrase = 'synthetic migration fixture passphrase';
  const { manifest } = backup(data, archive, passphrase);
  const decoded = readBackup(archive, passphrase, provisioned.serverPublicKey, checkpoint);
  const source = join(root, 'legacy.sqlite');
  writeFileSync(source, decoded.decoded.get('control.sqlite'), { mode: 0o600 });
  const trust = {
    version: 1,
    scope: 'SYNTHETIC_ONLY',
    authorityKey: provisioned.serverPublicKey,
    custodianKey: custodyKeys.publicKey,
    reviewerKey: reviewer.publicKey,
    checkpoint,
    lease,
    manifest,
    retainedManifestSha256: hash(canonical(manifest)),
    expectedPolicyDigest: policyDigest,
    allowPqcLab: false,
  };
  const request = {
    sourceType: 'database',
    source,
    destination: join(root, 'candidate'),
    trust: join(root, 'trust.json'),
    writerPublicKey: join(root, 'writer-public.json'),
  };
  privateJson(request.trust, trust);
  privateJson(request.writerPublicKey, writer.publicKey);
  const review = () => {
    const { plan, planDigest } = inspectLegacyMigration(request, { passphrase });
    return packet(reviewer.privateKey, {
      version: 1,
      kind: 'LEGACY_MIGRATION_APPROVAL',
      planDigest,
      stateDigest: plan.stateDigest,
      reviewer: 'Synthetic offline reviewer',
      scope: 'SYNTHETIC_ONLY',
      independentSnapshotConfirmed: true,
      latestCheckpointConfirmed: true,
      currentPolicyConfirmed: true,
      maintenanceConfirmed: true,
      expiresAt: Date.now() + 60000,
    });
  };
  // For negative tests only: model independently retained evidence which is itself inconsistent.
  const repin = () => {
    trust.manifest = packet(key, {
      ...trust.manifest.payload,
      files: { ...trust.manifest.payload.files, 'control.sqlite': hash(readFileSync(source)) },
    });
    trust.retainedManifestSha256 = hash(canonical(trust.manifest));
    privateJson(request.trust, trust);
  };
  return {
    root,
    data,
    key,
    trust,
    request,
    review,
    repin,
    custody,
    custodyKeys,
    reviewer,
    writer,
    archive,
    passphrase,
    provisioned,
  };
}
