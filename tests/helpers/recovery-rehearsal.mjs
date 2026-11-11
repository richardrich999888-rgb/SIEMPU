// Synthetic operator driver only; independent administration is not simulated.
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
  chmodSync,
  copyFileSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { initDemo } from '../../scripts/bootstrap.mjs';
import { backup } from '../../scripts/backup.mjs';
import { Authority } from '../../services/control/core.mjs';
import { createControlServer } from '../../services/control/server.mjs';
import { createRelayServer } from '../../services/relay/server.mjs';
import { createRelayClient } from '../../services/relay/client.mjs';
import {
  CheckpointCustodian,
  createRecoveryGuard,
  authoritySnapshot,
  authorizationDigest,
} from '../../services/evidence/custody.mjs';
import { SecurityCollector, redactSecurityEvents } from '../../services/monitoring/collector.mjs';
import {
  canonical,
  hash,
  packet,
  keyId,
  verifyPacket,
} from '../../services/control/primitives.mjs';
import { verifyEvidence } from '../../apps/verifier/verify.mjs';
import {
  inspectGuardedRecovery,
  stageGuardedRecovery,
  reviewRecoveryResume,
  reconcileRecoveryHandover,
  verifyRecoveryWorkingSet,
  checkRecoveryApproval,
} from '../../scripts/guarded-recovery.mjs';
import {
  inspectLegacyMigration,
  applyLegacyMigration,
  verifyLegacyMigration,
  readMigrationFile,
} from '../../scripts/legacy-migration.mjs';
import {
  ApiClient,
  pair,
  coreTransport,
  httpTransport,
  createObject,
  decryptObject,
} from './client.mjs';
export const putJson = (p, v) => writeFileSync(p, canonical(v), { mode: 0o600 });
export const getJson = (p) => JSON.parse(readFileSync(p));
export async function closeServer(s) {
  if (!s) return;
  const done = once(s, 'close');
  s.close();
  s.closeAllConnections?.();
  await done;
}
async function relayAt(dir) {
  const secret = Buffer.from(readFileSync(join(dir, 'relay.secret'), 'utf8'), 'hex');
  const server = createRelayServer({
    database: join(dir, 'relay/relay.sqlite'),
    secret,
    tls: null,
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    server,
    client: createRelayClient({ baseUrl: `http://127.0.0.1:${server.address().port}`, secret }),
  };
}
async function send(clients, profiles, a, payload) {
  const object = createObject(profiles.alice, profiles.bob, await clients.alice.grant(), {
    data: payload,
  });
  await clients.alice.submit(object);
  const claim = await clients.bob.claim(object.envelope.objectId, a.epoch().epoch);
  assert.equal(claim.status, 200);
  assert.equal(
    Buffer.from(decryptObject(claim.body, profiles.bob).data, 'base64url').toString(),
    payload,
  );
  const receiptId = claim.body.receipt.payload.eventId;
  assert.equal(
    (
      await clients.bob.request('POST', `/api/objects/${object.envelope.objectId}/ack`, {
        receiptId,
        proof: await clients.bob.proof('ack:' + object.envelope.objectId, { receiptId }),
      })
    ).status,
    200,
  );
  return { objectId: object.envelope.objectId, receiptId };
}
export async function recoveryFixture(t, { migrated = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-dr-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = join(root, 'source'),
    witness = join(root, 'independent');
  mkdirSync(witness, { mode: 0o700 });
  const provisioned = await initDemo(source),
    profiles = Object.fromEntries(provisioned.profiles.map((p) => [p.username, p]));
  const key = getJson(join(source, 'server-key.json')),
    authorityKey = provisioned.serverPublicKey;
  const custodian = pair(),
    collector = pair(),
    reviewer = pair(),
    oldWriter = pair(),
    newWriter = pair();
  const custodyConfig = {
    database: join(witness, 'custody.sqlite'),
    authorityKey,
    signingKey: custodian.privateKey,
    requireFencing: false,
    allowBootstrap: true,
  };
  let custody = new CheckpointCustodian(custodyConfig),
    relay = await relayAt(source),
    a,
    monitor;
  const open = () =>
    new Authority({
      dbPath: join(source, 'control.sqlite'),
      signingKey: key,
      masterKey: readFileSync(join(source, 'master.key')),
      relay: relay.client,
    });
  try {
    a = open();
    const clients = Object.fromEntries(
      Object.entries(profiles).map(([n, p]) => [n, new ApiClient(coreTransport(a), p)]),
    );
    for (const c of Object.values(clients)) await c.authenticate();
    const baseline = await send(clients, profiles, a, 'SYNTHETIC: acknowledged before snapshot');
    a.tx(() => {
      a.run("UPDATE devices SET status='revoked' WHERE id=?", profiles.eve.deviceId);
      a.run('UPDATE users SET active=0 WHERE id=?', profiles.bravo.userId);
      a.run('UPDATE authority SET epoch=epoch+1,revocation_version=revocation_version+1');
      a.event('RECOVERY_FIXTURE_REVOCATIONS', 'synthetic');
    });
    const policyDigest = hash(canonical(a.crypto.policy()));
    const stateDigest = migrated
      ? hash(
          canonical({
            authority: a.epoch(),
            users: a.all('SELECT id,unit_id,role,missions,active,duty_role FROM users ORDER BY id'),
            devices: a.all(
              'SELECT id,user_id,signing_key,encryption_key,status FROM devices ORDER BY id',
            ),
            policies: a.all('SELECT * FROM policies ORDER BY from_unit,to_unit,mission_id'),
          }),
        )
      : authorizationDigest(a);
    const checkpoint = a.checkpoint(),
      lease = await custody.accept(
        packet(key, {
          version: 1,
          nonce: crypto.randomUUID(),
          issuedAt: Date.now(),
          stateDigest,
          evidence: authoritySnapshot(a),
        }),
      );
    const epoch = a.epoch();
    if (migrated) {
      a.close();
      a = null;
      await closeServer(relay.server);
      relay = null;
      const db = new DatabaseSync(join(source, 'control.sqlite'));
      db.exec('DELETE FROM authorization_commit');
      db.close();
      const archive = join(root, 'legacy.backup'),
        passphrase = 'synthetic legacy recovery passphrase';
      const { manifest } = backup(source, archive, passphrase);
      const trust = {
        version: 1,
        scope: 'SYNTHETIC_ONLY',
        authorityKey,
        custodianKey: custodian.publicKey,
        reviewerKey: reviewer.publicKey,
        checkpoint,
        lease,
        manifest,
        retainedManifestSha256: hash(canonical(manifest)),
        expectedPolicyDigest: policyDigest,
        allowPqcLab: false,
      };
      const request = {
        sourceType: 'backup',
        source: archive,
        destination: join(root, 'migration'),
        trust: join(witness, 'legacy-trust.json'),
        writerPublicKey: join(witness, 'old-writer.json'),
      };
      putJson(request.trust, trust);
      putJson(request.writerPublicKey, oldWriter.publicKey);
      const { plan, planDigest } = inspectLegacyMigration(request, { passphrase });
      const approval = packet(reviewer.privateKey, {
        version: 1,
        kind: 'LEGACY_MIGRATION_APPROVAL',
        planDigest,
        stateDigest: plan.stateDigest,
        reviewer: 'Synthetic operator',
        scope: 'SYNTHETIC_ONLY',
        independentSnapshotConfirmed: true,
        latestCheckpointConfirmed: true,
        currentPolicyConfirmed: true,
        maintenanceConfirmed: true,
        expiresAt: Date.now() + 600000,
      });
      await applyLegacyMigration(request, { passphrase, approval, signingKey: key });
      assert.equal(
        verifyLegacyMigration(request, { passphrase, expectedPlanDigest: planDigest }).status,
        'VERIFIED_QUARANTINED',
      );
      custody.transferWriter(getJson(join(request.destination, 'handover-request.json')));
      copyFileSync(join(request.destination, 'control.sqlite'), join(source, 'control.sqlite'));
      relay = await relayAt(source);
      a = open();
    } else
      custody.transferWriter({
        writerKey: oldWriter.publicKey,
        expectedGeneration: 0,
        expectedAnchor: {
          sequence: checkpoint.payload.sequence,
          headHash: checkpoint.payload.headHash,
          stateDigest,
        },
        authority: { epoch: epoch.epoch, revocationVersion: epoch.revocation_version },
      });
    let retainedLease;
    const guard = createRecoveryGuard({
      custodianKey: custodian.publicKey,
      writer: { key: oldWriter.privateKey, generation: 1 },
      exchange: async (r) => {
        retainedLease = await custody.accept(r);
        return retainedLease;
      },
    });
    a.recoveryGuard = guard;
    await guard.authorize(a);
    const head = a.checkpoint();
    monitor = new SecurityCollector({
      database: join(witness, 'collector.sqlite'),
      sourceKey: authorityKey,
      signingKey: collector.privateKey,
    });
    monitor.ingest(packet(key, redactSecurityEvents(a)));
    baseline.monitorId = monitor.list()[0].event.eventId;
    baseline.monitorAck = monitor.acknowledge(
      { eventId: baseline.monitorId, disposition: 'INVESTIGATING' },
      'synthetic',
    );
    const monitorSnapshot = join(witness, 'monitor-snapshot.sqlite');
    monitor.db.prepare('VACUUM INTO ?').run(monitorSnapshot);
    chmodSync(monitorSnapshot, 0o600);
    const tokens = Object.fromEntries(Object.entries(clients).map(([n, c]) => [n, c.token]));
    a.close();
    a = null;
    await closeServer(relay.server);
    relay = null;
    custody.close();
    custody = null;
    monitor.close();
    monitor = null;
    chmodSync(custodyConfig.database, 0o600);
    const archive = join(root, 'recovery.backup'),
      passphrase = 'synthetic recovery passphrase';
    const { manifest } = backup(source, archive, passphrase);
    const monitorWitness = packet(collector.privateKey, {
      version: 1,
      kind: 'SYNTHETIC_MONITOR_RECOVERY_SNAPSHOT',
      authorityKeyId: keyId(authorityKey),
      checkpoint: { sequence: head.payload.sequence, headHash: head.payload.headHash },
      databaseSha256: hash(readFileSync(monitorSnapshot)),
    });
    const trust = {
      authorityKey,
      custodianKey: custodian.publicKey,
      collectorKey: collector.publicKey,
      reviewerKey: reviewer.publicKey,
      manifestSha256: hash(canonical(manifest)),
      checkpoint: head,
      lease: retainedLease,
      monitorWitness,
      monitorWitnessSha256: hash(canonical(monitorWitness)),
      policyDigest,
    };
    const request = {
      version: 1,
      scope: 'SYNTHETIC_ONLY',
      archive,
      monitor: monitorSnapshot,
      trust: join(witness, 'recovery-trust.json'),
      writerPublicKey: join(witness, 'new-writer.json'),
      destination: join(root, 'recovered'),
    };
    putJson(request.trust, trust);
    putJson(request.writerPublicKey, newWriter.publicKey);
    const { plan, planDigest } = inspectGuardedRecovery(request, { passphrase });
    const approval = packet(reviewer.privateKey, {
      version: 1,
      kind: 'SYNTHETIC_RECOVERY_APPROVAL',
      planDigest,
      reviewer: 'Synthetic operator',
      currentPolicyConfirmed: true,
      latestCustodyConfirmed: true,
      independentSnapshotsConfirmed: true,
      writersStoppedConfirmed: true,
      expiresAt: Date.now() + 600000,
    });
    const config = {
      request,
      trust,
      passphrase,
      approval,
      expectedPlanDigest: planDigest,
      custodyConfig: { ...custodyConfig, requireFencing: true, allowBootstrap: false },
      collectorKey: collector.privateKey,
      writer: { key: newWriter.privateKey, generation: 2 },
      oldWriter: { key: oldWriter.privateKey, generation: 1 },
      profiles,
      tokens,
      baseline,
      source,
      migrated,
    };
    const configPath = join(witness, 'operator-fixture.json');
    putJson(configPath, config);
    return {
      root,
      source,
      request,
      trust,
      passphrase,
      approval,
      plan,
      config,
      configPath,
      reviewer,
      custodian,
      collector,
      openCustody: () => new CheckpointCustodian(config.custodyConfig),
    };
  } finally {
    a?.close();
    custody?.close();
    monitor?.close();
    await closeServer(relay?.server);
  }
}
export async function runRecoveryFixture(
  c,
  {
    resume = false,
    onPhase = () => {},
    exchangeFailure = false,
    loseHandoverResponse = false,
  } = {},
) {
  const started = performance.now();
  let custody, authority, monitor, relay, control;
  try {
    const { plan } = resume
      ? reviewRecoveryResume(c.request, c)
      : await stageGuardedRecovery(c.request, {
          passphrase: c.passphrase,
          approval: c.approval,
          onPhase,
        });
    await onPhase('staged');
    verifyRecoveryWorkingSet(plan, c.trust);
    readMigrationFile(c.custodyConfig.database, 64 * 1024 * 1024);
    custody = new CheckpointCustodian(c.custodyConfig);
    const receipt = reconcileRecoveryHandover(custody, plan, c.approval, c.trust, {
      perform: !resume,
    });
    await onPhase('handover-committed');
    if (loseHandoverResponse) throw new Error('SYNTHETIC_LOST_HANDOVER_RESPONSE');
    const path = join(dirname(c.request.trust), 'retained-handover.json');
    if (existsSync(path)) assert.equal(canonical(getJson(path)), canonical(receipt));
    else putJson(path, receipt);
    await onPhase('handover-retained');
    relay = await relayAt(c.request.destination);
    const guard = createRecoveryGuard({
      custodianKey: c.trust.custodianKey,
      writer: c.writer,
      exchange: (r) => {
        if (exchangeFailure) throw new Error('SYNTHETIC_CUSTODY_OUTAGE');
        return custody.accept(r);
      },
    });
    authority = new Authority({
      dbPath: join(c.request.destination, 'control.sqlite'),
      signingKey: getJson(join(c.request.destination, 'server-key.json')),
      masterKey: readFileSync(join(c.request.destination, 'master.key')),
      relay: relay.client,
      recoveryGuard: guard,
    });
    assert.equal(guard.state, 'QUARANTINED');
    checkRecoveryApproval(plan, c.approval, c.trust.reviewerKey);
    await guard.authorize(authority);
    await onPhase('leased');
    checkRecoveryApproval(plan, c.approval, c.trust.reviewerKey);
    assert.equal(guard.allows(authority), true);
    monitor = new SecurityCollector({
      database: join(c.request.destination, 'monitor/collector.sqlite'),
      sourceKey: c.trust.authorityKey,
      signingKey: c.collectorKey,
    });
    assert.equal(
      canonical(monitor.list().find((r) => r.event.eventId === c.baseline.monitorId).ack),
      canonical(c.baseline.monitorAck),
    );
    const telemetry = {
      deliver: async (a) => {
        assert.ok(
          verifyPacket(
            c.trust.collectorKey,
            monitor.ingest(packet(a.key, redactSecurityEvents(a))),
          ),
        );
        return true;
      },
    };
    control = createControlServer({ authority, tls: null, telemetry });
    control.listen(0, '127.0.0.1');
    await once(control, 'listening');
    const recoveryMs = performance.now() - started;
    const api = httpTransport(`http://127.0.0.1:${control.address().port}`),
      clients = Object.fromEntries(
        Object.entries(c.profiles).map(([n, p]) => {
          const v = new ApiClient(api, p);
          v.token = c.tokens[n];
          return [n, v];
        }),
      );
    await onPhase('before-message');
    checkRecoveryApproval(plan, c.approval, c.trust.reviewerKey);
    assert.equal(
      JSON.parse(
        authority.get('SELECT receipt FROM issuances WHERE object_id=?', c.baseline.objectId)
          .receipt,
      ).payload.eventId,
      c.baseline.receiptId,
    );
    assert.equal(
      authority.get('SELECT state FROM objects WHERE id=?', c.baseline.objectId).state,
      'DELIVERED',
    );
    await send(clients, c.profiles, authority, 'SYNTHETIC: encrypted post-recovery message');
    await onPhase('message-acknowledged');
    const revoked = (await clients.eve.request('GET', '/api/objects')).status,
      inactive = (await clients.bravo.request('GET', '/api/objects')).status;
    assert.equal(revoked, 403);
    assert.equal(inactive, 401);
    await telemetry.deliver(authority);
    const evidence = authoritySnapshot(authority);
    await verifyEvidence(evidence, c.trust.authorityKey, { checkpoint: c.trust.checkpoint });
    const old = new Authority({
      dbPath: join(c.source, 'control.sqlite'),
      signingKey: getJson(join(c.source, 'server-key.json')),
      masterKey: readFileSync(join(c.source, 'master.key')),
      relay: relay.client,
      recoveryGuard: createRecoveryGuard({
        custodianKey: c.trust.custodianKey,
        writer: c.oldWriter,
        exchange: (r) => custody.accept(r),
      }),
    });
    try {
      const [stale, current] = await Promise.all([
        coreTransport(old)('GET', '/api/control', {}, c.tokens.alice),
        clients.alice.request('GET', '/api/control'),
      ]);
      assert.equal(stale.status, 503);
      assert.equal(current.status, 200);
    } finally {
      old.close();
    }
    assert.equal(custody.db.prepare('SELECT generation FROM writer_fence').get().generation, 2);
    return {
      outcome: 'PASS',
      profile: c.migrated ? 'MIGRATED_THEN_FENCED' : 'SEALED_FENCED',
      recoveryMs,
      totalMs: performance.now() - started,
      acknowledgedObjectsBefore: 1,
      acknowledgedObjectsRecovered: 1,
      acknowledgedObjectsLost: 0,
      firstMessageVerified: true,
      revokedDeviceDenied: revoked,
      inactiveUserDenied: inactive,
      staleWriterStatus: 503,
      generation: 2,
      monitoringEvents: monitor.list().length,
      evidence,
      publicKey: c.trust.authorityKey,
    };
  } finally {
    await closeServer(control);
    authority?.close();
    await closeServer(relay?.server);
    monitor?.close();
    custody?.close();
  }
}
