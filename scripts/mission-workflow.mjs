// SIEPMU Core Mission Workflow: executable end-to-end acceptance scenario.
//
// Runs the 18 workflow steps of the continuation directive (section 9) against the real
// five-process secure stack (TLS 1.3 gateway, control authority, ciphertext relay, checkpoint
// custodian, telemetry collector; mTLS between services), once per cryptographic profile:
//   classical  - schema v2 objects sealed and opened by the browser endpoint module
//                packages/crypto (WebCrypto P-256 ECDH + AES-256-GCM), PQC lab gate closed;
//   pqc-lab    - schema v3 objects with the laboratory ML-KEM-768 + ML-DSA-65 composition
//                (packages/pqc-lab), lab gate explicitly opened for this run only.
// Each step records PASS/FAIL with evidence; a failure stops that profile.
//
// Synthetic data only. Engineering evidence on one host: not a relevant-environment trial,
// representative demonstration, independent assessment, SAG grading or TRL decision.
// Output: artifacts/mission-workflow/{report.json,report.md}. Requires the Rust verifier
// (npm run build:native) because step 15 cross-checks both independent verifiers.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { provision, root } from '../tests/helpers/fixture.mjs';
import { ApiClient, enrollUser, pair, sign, verify } from '../tests/helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { createTransportServer } from '../packages/transport/tls.mjs';
import { createFaultProxy } from '../deployment/testbed/fault-proxy.mjs';
import {
  createFilePayload,
  createTextPayload,
  decryptObject,
  encryptObject,
  keyId,
  unpackPayload,
} from '../packages/crypto/crypto.mjs';
import { createNativePqcProvider } from '../packages/pqc-lab/native-provider.mjs';
import { createProviderObject, openProviderObject } from '../packages/pqc-lab/envelope.mjs';
import { createLabEndpoint, labContext } from '../packages/pqc-lab/endpoint.mjs';
import {
  NATIVE_PQC_PROVIDER_ID,
  NATIVE_MLKEM768_SUITE,
  NATIVE_MLKEM1024_SUITE,
} from '../packages/crypto-provider/pqc-identifiers.mjs';
import {
  CLASSICAL_PROVIDER_ID,
  CLASSICAL_SUITE_ID,
} from '../packages/crypto-provider/classical.mjs';
import { buildOfflineBundle, installOfflineBundle } from '../packages/release/offline.mjs';
import { verifyEvidence, verifyReleaseReceipt } from '../apps/verifier/verify.mjs';
import { sourceRevision, syntheticBytes, tlsFetch, waitReady } from './trust-before-release.mjs';

const OUTPUT = resolve(process.env.SIEPMU_EVIDENCE_DIR || 'artifacts/mission-workflow');
const PROFILES = ['classical', 'pqc-lab'];
const FILE_BYTES = 65536;
const MISSION = 'DEMO-MISSION';
const CLASSICAL = { providerId: CLASSICAL_PROVIDER_ID, suiteId: CLASSICAL_SUITE_ID };
const MLKEM768 = { providerId: NATIVE_PQC_PROVIDER_ID, suiteId: NATIVE_MLKEM768_SUITE };
const RUST_VERIFIER = resolve(
  process.env.SIEPMU_RUST_VERIFIER ?? join(root, 'native/target/release/siepmu-evidence-verify'),
);

/** Parses `METHOD PATH: STATUS {"code":"X"}` errors thrown by ApiClient.ok into "STATUS X". */
const refusal = (error) =>
  error.message
    .match(/: (\d{3}) .*"code":"([A-Z_]+)"/)
    ?.slice(1, 3)
    .join(' ') ?? error.message;

/** Consistent online copy of a WAL-mode SQLite database (readers do not block the writer). */
function snapshotDatabase(source, destination) {
  const db = new DatabaseSync(source);
  try {
    db.exec('PRAGMA busy_timeout=5000');
    db.prepare('VACUUM INTO ?').run(destination);
  } finally {
    db.close();
  }
}
function replaceDatabase(target, replacement) {
  for (const suffix of ['', '-wal', '-shm']) rmSync(target + suffix, { force: true });
  copyFileSync(replacement, target);
}
/** Every file under `dir` whose name matches, read as raw bytes (SQLite main file and WAL). */
function storeBytes(dir, pattern) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true })
    .map(String)
    .filter((name) => pattern.test(name))
    .map((name) => ({ name, bytes: readFileSync(join(dir, name)) }));
}

/** Classical profile: the browser endpoint module, schema v2 with mission labels. */
function classicalProfile(f) {
  return {
    name: 'classical',
    labGate: false,
    async prepareKeys(admin) {
      const crypto = await admin.ok('GET', '/api/admin/crypto');
      const admitted = crypto.policy.newSuites.some((s) => s.suiteId === CLASSICAL_SUITE_ID);
      assert.ok(admitted, 'classical suite must be admitted by the default policy');
      return { suite: CLASSICAL_SUITE_ID, privateKeysExported: false, policy: crypto.policy };
    },
    async seal(recipientName, recipientProfile, grant, payload) {
      const now = Date.now();
      const context = {
        schemaVersion: 2,
        objectId: randomUUID(),
        senderUserId: f.profiles.alice.userId,
        senderDeviceId: f.profiles.alice.deviceId,
        senderUnitId: f.profiles.alice.unitId,
        recipientUserId: recipientProfile.userId,
        recipientDeviceId: recipientProfile.deviceId,
        recipientUnitId: recipientProfile.unitId,
        recipientKeyId: await keyId(recipientProfile.keys.encryption.publicKey),
        missionId: MISSION,
        classification: 'DEMO',
        action: 'deliver',
        createdAt: now,
        expiresAt: now + 10 * 60 * 1000,
        creationGrant: grant,
        cryptoSuite: CLASSICAL_SUITE_ID,
        keyVersion: 1,
        messagePriority: 'IMMEDIATE',
        messageDomain: 'GENERAL',
      };
      return encryptObject(
        context,
        payload,
        recipientProfile.keys.encryption.publicKey,
        f.profiles.alice.keys.signing.privateKey,
      );
    },
    async open(recipientName, recipientProfile, claim) {
      return unpackPayload(
        await decryptObject(
          claim,
          recipientProfile.keys.encryption.privateKey,
          claim.senderSigningPublicKey,
        ),
      );
    },
    /** Altered metadata, re-signed by the genuine sender: must still be refused. */
    tamperings(object) {
      const resign = (envelope) => ({
        ...object,
        envelope,
        signature: sign(envelope, f.profiles.alice.keys.signing.privateKey),
      });
      return {
        unknownSchemaVersion: resign({ ...object.envelope, schemaVersion: 9 }),
        substitutedSuite: resign({ ...object.envelope, cryptoSuite: 'P256-HKDF-SHA1-AES128GCM' }),
      };
    },
  };
}

/** Laboratory PQC profile: schema v3, ML-KEM-768 + ML-DSA-65 lab composition. */
function pqcProfile(f) {
  const endpoints = {};
  let policyRevision;
  return {
    name: 'pqc-lab',
    labGate: true,
    async prepareKeys(admin, clients) {
      for (const [name, client] of Object.entries(clients)) {
        endpoints[name] = await createLabEndpoint({
          provider: createNativePqcProvider(),
          ...MLKEM768,
        });
        const key =
          name === 'alice' ? endpoints[name].signingKey : endpoints[name].encapsulationKey;
        const registered = await client.request('POST', '/api/crypto/keys', {
          key,
          proof: await client.proof('crypto-key:register', { key }),
        });
        assert.equal(registered.status, 200, JSON.stringify(registered.body));
        const active = await admin.admin('PATCH', `/api/admin/crypto/keys/${key.keyId}`, {
          status: 'active',
        });
        assert.equal(active.status, 200, JSON.stringify(active.body));
      }
      const current = (await admin.ok('GET', '/api/admin/crypto')).policy;
      const policy = {
        schemaVersion: 1,
        revision: current.revision + 1,
        mode: 'laboratory',
        newSuites: [CLASSICAL, MLKEM768],
        legacySuites: [CLASSICAL, MLKEM768],
      };
      const r = await admin.admin('PUT', '/api/admin/crypto/policy', { policy });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      policyRevision = policy.revision;
      return { suite: NATIVE_MLKEM768_SUITE, privateKeysExported: false, policyRevision };
    },
    async seal(recipientName, recipientProfile, grant, payload) {
      const context = labContext({
        sender: f.profiles.alice,
        recipient: recipientProfile,
        creationGrant: grant,
        selection: MLKEM768,
        senderCryptoKeyId: endpoints.alice.signingKey.keyId,
        recipientKeyId: endpoints[recipientName].encapsulationKey.keyId,
        suitePolicyRevision: policyRevision,
        objectId: randomUUID(),
        now: Date.now(),
      });
      return createProviderObject({
        engine: endpoints.alice.engine,
        context,
        payload,
        recipientKey: endpoints[recipientName].encapsulationKey,
        senderKey: endpoints.alice.signingKey,
        identitySigningKey: f.profiles.alice.keys.signing.privateKey,
      });
    },
    async open(recipientName, recipientProfile, claim) {
      return unpackPayload(
        await openProviderObject({
          engine: endpoints[recipientName].engine,
          claim,
          senderKey: claim.senderCryptoKey,
          senderIdentityPublicKey: claim.senderSigningPublicKey,
          expected: { suiteId: NATIVE_MLKEM768_SUITE },
        }),
      );
    },
    tamperings(object) {
      const envelope = { ...object.envelope, cryptoSuite: NATIVE_MLKEM1024_SUITE };
      return {
        substitutedSuite: {
          ...object,
          envelope,
          signature: sign(envelope, f.profiles.alice.keys.signing.privateKey),
        },
      };
    },
  };
}

export async function runMissionWorkflow(profileName) {
  const steps = [];
  const report = {
    schemaVersion: 1,
    kind: 'siepmu-core-mission-workflow',
    profile: profileName,
    synthetic: true,
    startedAt: new Date().toISOString(),
    source: sourceRevision(),
    runtime: { node: process.version, openssl: process.versions.openssl },
    steps,
  };
  const step = async (number, name, fn) => {
    const started = performance.now();
    try {
      const evidence = (await fn()) ?? {};
      steps.push({
        number,
        step: name,
        outcome: 'PASS',
        durationMs: Math.round(performance.now() - started),
        ...evidence,
      });
      console.log(`[${profileName}] PASS ${number}: ${name}`);
    } catch (error) {
      steps.push({
        number,
        step: name,
        outcome: 'FAIL',
        durationMs: Math.round(performance.now() - started),
        error: error.message,
      });
      console.log(`[${profileName}] FAIL ${number}: ${name}: ${error.message}`);
      throw error;
    }
  };

  const previousLab = process.env.SIEPMU_ALLOW_PQC_LAB;
  const scratch = mkdtempSync(join(tmpdir(), 'siepmu-mission-'));
  let f, stack, proxy, profile;
  try {
    // ---- 1. Provision ------------------------------------------------------------------------
    await step(
      1,
      'Provision synthetic users, devices, units and the five-process secure stack',
      async () => {
        f = await provision();
        profile = profileName === 'classical' ? classicalProfile(f) : pqcProfile(f);
        if (profile.labGate) process.env.SIEPMU_ALLOW_PQC_LAB = '1';
        else delete process.env.SIEPMU_ALLOW_PQC_LAB;
        stack = await startSecureStack(f.dir);
        return {
          services: Object.keys(stack.ports),
          pqcLabGate: profile.labGate ? 'open' : 'closed',
        };
      },
    );
    const direct = secureApiTransport(stack.baseUrl, stack.tls);
    const proxyIdentity = stack.pki.issue('mission-fault-proxy');
    proxy = createFaultProxy({
      serverFactory: (handler) =>
        createTransportServer(handler, { ...proxyIdentity, requestCert: false }),
      upstream: stack.baseUrl,
      fetchImpl: tlsFetch(stack.tls),
      profile: 'constrained',
    });
    await new Promise((r) => proxy.server.listen(0, '127.0.0.1', r));
    const unitAPath = secureApiTransport(`https://127.0.0.1:${proxy.server.address().port}`, {
      ca: proxyIdentity.ca,
    });
    const alice = new ApiClient(unitAPath, f.profiles.alice);
    const bob = new ApiClient(direct, f.profiles.bob);
    const eve = new ApiClient(direct, f.profiles.eve);
    const admin = new ApiClient(direct, f.profiles.admin);
    const epochOf = async (client) => (await client.ok('GET', '/api/control')).payload.epoch;
    let colleague;

    // ---- 2. Enrol ----------------------------------------------------------------------------
    await step(
      2,
      'Enrol endpoint: administrator creates, enrols and approves a second Unit B user/device',
      async () => {
        await admin.authenticate();
        colleague = await enrollUser(admin, {
          username: 'bob-backup',
          unitId: f.provisioned.units.B,
        });
        return { enrolledDevice: colleague.profile.deviceId };
      },
    );

    // ---- 3. MFA ------------------------------------------------------------------------------
    let keyEvidence;
    await step(
      3,
      'Authenticate Units A, B, C with password + TOTP + signed device challenge; endpoint keys stay local',
      async () => {
        for (const c of [alice, bob, eve]) await c.authenticate();
        keyEvidence = await profile.prepareKeys(admin, {
          alice,
          bob,
          colleague: colleague.client,
        });
        return { units: { alice: 'A', bob: 'B', eve: 'C' }, ...keyEvidence };
      },
    );
    const snapshotBeforeRevocation = join(scratch, 'control-before-revocation.sqlite');
    snapshotDatabase(join(f.dir, 'control.sqlite'), snapshotBeforeRevocation);

    // ---- 4. Policy ---------------------------------------------------------------------------
    await step(
      4,
      'Apply unit and mission policy: Unit A -> Unit B allowed for the mission; Unit C has no edge',
      async () => {
        const before = await epochOf(admin);
        const r = await admin.admin('PUT', '/api/admin/policies', {
          fromUnit: f.provisioned.units.A,
          toUnit: f.provisioned.units.B,
          missionId: MISSION,
          allow: true,
        });
        assert.equal(r.status, 200, JSON.stringify(r.body));
        const after = await epochOf(admin);
        assert.ok(after > before, 'a policy change must advance the authority epoch');
        return { epochBefore: before, epochAfter: after };
      },
    );

    // ---- 5/6. Create and submit ----------------------------------------------------------------
    const canary = `SIEPMU-CANARY-${randomUUID()}`;
    const fileBytes = syntheticBytes(17, FILE_BYTES);
    const baseline = {};
    await step(5, 'Sender endpoint encrypts a text object and a 64 KiB file object', async () => {
      const grant = await alice.grant();
      baseline.text = await profile.seal('bob', f.profiles.bob, grant, createTextPayload(canary));
      baseline.file = await profile.seal(
        'bob',
        f.profiles.bob,
        grant,
        createFilePayload('logistics-manifest.bin', 'application/octet-stream', fileBytes),
      );
      return {
        schemaVersion: baseline.file.envelope.schemaVersion,
        suite: baseline.file.envelope.cryptoSuite,
      };
    });
    await step(
      6,
      'Submit over TLS 1.3 (gateway, mTLS behind it); Unit C cannot claim; Unit B opens both objects',
      async () => {
        for (const o of [baseline.text, baseline.file]) {
          await alice.submit(o);
          await alice.prepare(o.envelope.objectId);
        }
        const unrelated = await eve.claim(baseline.file.envelope.objectId, await epochOf(eve));
        assert.equal(unrelated.status, 404);
        const text = await bob.claim(baseline.text.envelope.objectId, await epochOf(bob));
        assert.equal(text.status, 200, JSON.stringify(text.body));
        assert.equal((await profile.open('bob', f.profiles.bob, text.body)).text, canary);
        const file = await bob.claim(baseline.file.envelope.objectId, await epochOf(bob));
        assert.equal(file.status, 200, JSON.stringify(file.body));
        const opened = await profile.open('bob', f.profiles.bob, file.body);
        assert.deepEqual(Buffer.from(opened.bytes), fileBytes);
        assert.equal(opened.name, 'logistics-manifest.bin');
        return { unitCClaimStatus: unrelated.status, fileBytes: fileBytes.length };
      },
    );

    // ---- 7. Interruption ---------------------------------------------------------------------
    const queued = {};
    let epochBeforeRevocation;
    await step(
      7,
      'Network interruption: Unit A offline; objects sealed locally with a cached grant; submission fails',
      async () => {
        const cachedGrant = await alice.grant();
        proxy.state.offline = true;
        const payload = (seed) =>
          createFilePayload(
            `queued-${seed}.bin`,
            'application/octet-stream',
            syntheticBytes(seed, FILE_BYTES),
          );
        queued.toBob = await profile.seal('bob', f.profiles.bob, cachedGrant, payload(2));
        queued.toColleague = await profile.seal(
          'colleague',
          colleague.profile,
          cachedGrant,
          payload(3),
        );
        await assert.rejects(alice.submit(queued.toBob));
        epochBeforeRevocation = await epochOf(admin);
        return { proxyCuts: proxy.state.cuts };
      },
    );

    // ---- 8. Authorization change ---------------------------------------------------------------
    await step(
      8,
      'Change recipient authorisation while Unit A is offline: revoke Unit B user bob',
      async () => {
        const r = await admin.admin('PATCH', `/api/admin/users/${f.profiles.bob.userId}`, {
          active: false,
        });
        assert.equal(r.status, 200, JSON.stringify(r.body));
        const epoch = await epochOf(admin);
        assert.ok(epoch > epochBeforeRevocation);
        return { epochBefore: epochBeforeRevocation, epochAfter: epoch };
      },
    );

    // ---- 9/10. Reconnect and revalidate ------------------------------------------------------------
    let held;
    await step(9, 'Restore connectivity; the queued objects are submitted', async () => {
      proxy.state.offline = false;
      await alice.submit(queued.toBob);
      await alice.submit(queued.toColleague);
      return { submitted: 2 };
    });
    await step(
      10,
      'Revalidate current policy at release: revoked recipient HELD (USER_REVOKED); eligible one READY',
      async () => {
        held = await alice.prepare(queued.toBob.envelope.objectId);
        assert.equal(held.body.object.state, 'HELD');
        assert.equal(held.body.object.reason, 'USER_REVOKED');
        const ready = await alice.prepare(queued.toColleague.envelope.objectId);
        assert.equal(ready.body.object.state, 'READY');
        return { heldReason: held.body.object.reason };
      },
    );

    // ---- 11. Stale denial ------------------------------------------------------------------------
    await step(
      11,
      'Deny stale release: revoked user refused before any key route; stale expected epoch fenced',
      async () => {
        let revokedRefusal;
        try {
          await bob.claim(queued.toBob.envelope.objectId, await epochOf(admin));
          revokedRefusal = 'CLAIM_UNEXPECTEDLY_SUCCEEDED';
        } catch (error) {
          revokedRefusal = refusal(error);
        }
        assert.equal(revokedRefusal, '401 USER_REVOKED');
        const stale = await colleague.client.claim(
          queued.toColleague.envelope.objectId,
          epochBeforeRevocation,
        );
        assert.equal(stale.status, 409, JSON.stringify(stale.body));
        assert.equal(stale.body.object.reason, 'EPOCH_MISMATCH');
        assert.equal(stale.body.envelope, undefined, 'a fenced claim must not carry key material');
        return {
          revokedRecipient: revokedRefusal,
          staleEpochStatus: stale.status,
          staleReason: stale.body.object.reason,
        };
      },
    );

    // ---- 12/13. Legitimate delivery ----------------------------------------------------------------
    let delivered;
    await step(
      12,
      'Separate legitimate delivery: second Unit B recipient claims with the current epoch',
      async () => {
        delivered = await colleague.client.claim(
          queued.toColleague.envelope.objectId,
          await epochOf(colleague.client),
        );
        assert.equal(delivered.status, 200, JSON.stringify(delivered.body));
        assert.equal(delivered.body.receipt.payload.decision, 'RELEASED');
        return { decision: delivered.body.receipt.payload.decision };
      },
    );
    await step(13, 'Recipient endpoint decrypts exact bytes, name and media type', async () => {
      const opened = await profile.open('colleague', colleague.profile, delivered.body);
      assert.deepEqual(Buffer.from(opened.bytes), syntheticBytes(3, FILE_BYTES));
      assert.equal(opened.name, 'queued-3.bin');
      assert.equal(opened.mime, 'application/octet-stream');
      return { bytes: opened.bytes.length };
    });

    // ---- 14. Signed decisions ------------------------------------------------------------------------
    await step(
      14,
      'Signed authorisation evidence: HELD and RELEASED decisions verify under the authority key; tampering rejected',
      async () => {
        const key = f.provisioned.serverPublicKey;
        const releasedReceipt = delivered.body.receipt;
        assert.ok(verify(held.body.receipt.payload, held.body.receipt.signature, key));
        assert.ok(verify(releasedReceipt.payload, releasedReceipt.signature, key));
        const tampered = { ...releasedReceipt.payload, actorId: f.profiles.bob.userId };
        assert.equal(verify(tampered, releasedReceipt.signature, key), false);
        for (const [label, forged] of Object.entries(profile.tamperings(queued.toColleague))) {
          const r = await alice.request('POST', '/api/objects', {
            ...forged,
            proof: await alice.proof('submit', forged),
          });
          assert.ok([400, 403, 409].includes(r.status), `${label}: ${r.status}`);
        }
        return {
          heldDecision: held.body.receipt.payload.decision,
          releasedDecision: releasedReceipt.payload.decision,
        };
      },
    );

    // ---- 15. Independent verification ------------------------------------------------------------------
    await mkdir(OUTPUT, { recursive: true });
    await step(
      15,
      'Independent verification: strict receipt + replay rejection; full chain; Node and Rust verifiers agree byte-for-byte',
      async () => {
        const receipt = delivered.body.receipt;
        const replay = join(scratch, 'replay.sqlite');
        const bindings = {
          objectDigest: delivered.body.object.ciphertextHash,
          epoch: receipt.payload.epoch,
          objectId: queued.toColleague.envelope.objectId,
          replayStore: replay,
        };
        assert.equal(
          (await verifyReleaseReceipt(receipt, f.provisioned.serverPublicKey, bindings))
            .strictReleaseVerified,
          true,
        );
        await assert.rejects(
          verifyReleaseReceipt(receipt, f.provisioned.serverPublicKey, bindings),
          /replay/i,
        );
        const evidence = await admin.ok('GET', '/api/evidence/export');
        assert.equal((await verifyEvidence(evidence, f.provisioned.serverPublicKey)).valid, true);
        writeFileSync(join(scratch, 'evidence.json'), JSON.stringify(evidence));
        writeFileSync(join(scratch, 'receipt.json'), JSON.stringify(receipt));
        writeFileSync(join(scratch, 'key.json'), JSON.stringify(f.provisioned.serverPublicKey));
        assert.ok(
          existsSync(RUST_VERIFIER),
          `Rust verifier missing at ${RUST_VERIFIER}; run npm run build:native`,
        );
        const both = (args) => {
          const node = spawnSync(
            process.execPath,
            [join(root, 'apps/verifier/verify.mjs'), ...args],
            { cwd: scratch, encoding: 'utf8' },
          );
          const rust = spawnSync(RUST_VERIFIER, args, { cwd: scratch, encoding: 'utf8' });
          assert.equal(node.status, 0, node.stderr);
          assert.equal(rust.status, 0, rust.stderr);
          assert.equal(rust.stdout, node.stdout);
          return JSON.parse(rust.stdout);
        };
        writeFileSync(join(scratch, 'checkpoint.json'), JSON.stringify(evidence.checkpoint));
        const chain = both(['evidence.json', 'key.json', '--checkpoint', 'checkpoint.json']);
        assert.equal(chain.externalCheckpointVerified, true);
        const bound = both([
          'receipt.json',
          'key.json',
          '--object-digest',
          bindings.objectDigest,
          '--epoch',
          String(bindings.epoch),
          '--object-id',
          bindings.objectId,
        ]);
        await writeFile(
          join(OUTPUT, `${profileName}-evidence.json`),
          JSON.stringify(evidence, null, 2),
        );
        return {
          records: chain.records,
          headHash: chain.headHash,
          bindingVerified: bound.bindingVerified,
          verifiersAgree: true,
        };
      },
    );

    // ---- 16. Snapshot restore ----------------------------------------------------------------------
    await step(
      16,
      'Restore a prior database snapshot: authority quarantined (503) until the current state is reinstated',
      async () => {
        const controlDb = join(f.dir, 'control.sqlite');
        const current = join(scratch, 'control-current.sqlite');
        await stack.stopRole('control');
        snapshotDatabase(controlDb, current);
        replaceDatabase(controlDb, snapshotBeforeRevocation);
        stack.start('control');
        await waitReady(stack.baseUrl, stack.tls);
        const quarantined = await admin.request('GET', '/api/admin/overview');
        assert.equal(quarantined.status, 503, JSON.stringify(quarantined.body));
        assert.equal(quarantined.body.code, 'RECOVERY_QUARANTINED');
        // The restored snapshot predates bob's revocation; quarantine must stop him too.
        const bobAttempt = await bob.request('GET', '/api/control');
        assert.equal(bobAttempt.status, 503);
        await stack.stopRole('control');
        replaceDatabase(controlDb, current);
        stack.start('control');
        await waitReady(stack.baseUrl, stack.tls);
        const retry = await colleague.client.claim(
          queued.toColleague.envelope.objectId,
          await epochOf(colleague.client),
        );
        assert.equal(retry.status, 200, JSON.stringify(retry.body));
        assert.equal(retry.body.receipt.payload.eventId, delivered.body.receipt.payload.eventId);
        const overview = await admin.ok('GET', '/api/admin/overview');
        assert.equal(
          overview.objects.find((o) => o.id === queued.toBob.envelope.objectId).state,
          'HELD',
        );
        return {
          staleSnapshotStatus: quarantined.status,
          staleSnapshotCode: quarantined.body.code,
          resumedSameIssuance: true,
        };
      },
    );

    // ---- 17. Signed update -----------------------------------------------------------------------
    await step(
      17,
      'Signed update: offline bundle installs and its runtime verifies evidence; tampered and rollback bundles rejected',
      async () => {
        const keys = pair();
        const revision = report.source.commit ?? '0'.repeat(40);
        const ledger = join(scratch, 'release-ledger', 'floor.json');
        const destination = join(scratch, 'installed');
        const bundle = (version) => {
          const path = join(scratch, `bundle-v${version}`);
          buildOfflineBundle({
            source: root,
            destination: path,
            signingKey: keys.privateKey,
            version,
            revision,
          });
          return path;
        };
        const v2 = bundle(2);
        const installed = installOfflineBundle({
          bundle: v2,
          destination,
          ledger,
          trustedKey: keys.publicKey,
          initialize: true,
        });
        const run = spawnSync(
          join(installed.release, 'runtime/node'),
          [join(installed.release, 'app/apps/verifier/verify.mjs'), 'evidence.json', 'key.json'],
          { cwd: scratch, encoding: 'utf8', env: { PATH: '/nonexistent' } },
        );
        assert.equal(run.status, 0, run.stderr);
        assert.throws(
          () =>
            installOfflineBundle({ bundle: v2, destination, ledger, trustedKey: pair().publicKey }),
          /RELEASE_SIGNATURE/,
        );
        const v1 = bundle(1);
        assert.throws(
          () =>
            installOfflineBundle({ bundle: v1, destination, ledger, trustedKey: keys.publicKey }),
          /RELEASE_ROLLBACK_DENIED/,
        );
        const target = join(v2, 'files', 'app', 'apps', 'verifier', 'verify.mjs');
        // Same-size substitution: only the per-file digest can detect it.
        const tampered = readFileSync(target);
        tampered[0] ^= 0x01;
        writeFileSync(target, tampered);
        assert.throws(
          () =>
            installOfflineBundle({ bundle: v2, destination, ledger, trustedKey: keys.publicKey }),
          /RELEASE_DIGEST/,
        );
        for (const p of [v1, v2, destination]) rmSync(p, { recursive: true, force: true });
        return {
          installedVersion: installed.version,
          wrongKey: 'RELEASE_SIGNATURE',
          rollback: 'RELEASE_ROLLBACK_DENIED',
          tamper: 'RELEASE_DIGEST',
        };
      },
    );

    // ---- 18. Monitoring confidentiality -----------------------------------------------------------
    await step(
      18,
      'Monitoring and service stores contain no plaintext, private keys, session tokens or wrapped keys',
      async () => {
        const collector = storeBytes(join(f.dir, 'monitor'), /collector\.sqlite(-wal)?$/);
        const relay = storeBytes(join(f.dir, 'relay'), /\.sqlite(-wal)?$/);
        const control = storeBytes(f.dir, /^control\.sqlite(-wal)?$/);
        assert.ok(
          collector.length > 0 && relay.length > 0 && control.length > 0,
          'stores must exist',
        );
        const events = new DatabaseSync(join(f.dir, 'monitor', 'collector.sqlite'), {
          readOnly: true,
        });
        const eventCount = events.prepare('SELECT count(*) n FROM events').get().n;
        events.close();
        assert.ok(
          eventCount > 0,
          'collector must have received telemetry for the check to be meaningful',
        );
        const plaintextSlice = syntheticBytes(3, FILE_BYTES).subarray(4096, 4160);
        const secrets = [
          ['plaintext canary', Buffer.from(canary)],
          ['file plaintext', plaintextSlice],
          ...Object.entries(f.profiles).flatMap(([name, p]) => [
            [`${name} signing private key`, Buffer.from(p.keys.signing.privateKey.d)],
            [`${name} encryption private key`, Buffer.from(p.keys.encryption.privateKey.d)],
            [`${name} TOTP secret`, Buffer.from(p.totpSecret)],
            [`${name} password`, Buffer.from(p.password)],
          ]),
          ...[alice, bob, eve, admin].map((c) => [
            `${c.profile.username} session token`,
            Buffer.from(c.token),
          ]),
        ];
        if (profile.name === 'classical')
          secrets.push([
            'wrapped content key',
            Buffer.from(queued.toColleague.envelope.wrappedKey.ciphertext),
          ]);
        const leaks = [];
        for (const [store, files, names] of [
          ['collector', collector, secrets.map((s) => s[0])],
          ['relay', relay, secrets.map((s) => s[0])],
          ['control', control, ['plaintext canary', 'file plaintext']],
        ])
          for (const [label, needle] of secrets.filter(([l]) => names.includes(l)))
            for (const file of files)
              if (file.bytes.includes(needle)) leaks.push(`${store}:${file.name}:${label}`);
        assert.deepEqual(leaks, []);
        // Positive controls: values that must be present prove the scan reads the live stores.
        const contains = (files, text) =>
          files.some((file) => file.bytes.includes(Buffer.from(text)));
        for (const expected of ['RELEASE_ISSUED', 'USER_REVOKED'])
          assert.ok(contains(collector, expected), `collector lacks ${expected}`);
        assert.ok(
          contains(relay, queued.toColleague.envelope.ciphertextHash),
          'relay lacks ciphertext',
        );
        return {
          collectorEvents: eventCount,
          secretsChecked: secrets.length,
          storesScanned: collector.length + relay.length + control.length,
        };
      },
    );
    report.outcome = 'PASS';
  } catch {
    report.outcome = 'FAIL';
  } finally {
    if (proxy) await new Promise((r) => proxy.server.close(r));
    if (stack) await stack.stop();
    if (f) rmSync(f.dir, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
    if (previousLab === undefined) delete process.env.SIEPMU_ALLOW_PQC_LAB;
    else process.env.SIEPMU_ALLOW_PQC_LAB = previousLab;
    report.finishedAt = new Date().toISOString();
  }
  return report;
}

function markdown(reports) {
  const lines = ['# SIEPMU Core Mission Workflow — synthetic run report', ''];
  for (const r of reports) {
    lines.push(
      `## Profile \`${r.profile}\`: **${r.outcome}**`,
      '',
      `Commit \`${r.source.commit}\`${r.source.dirty ? ' (dirty tree)' : ''}; Node ${r.runtime.node}, OpenSSL ${r.runtime.openssl}; ${r.startedAt} → ${r.finishedAt}.`,
      '',
      '| # | Step | Outcome | ms |',
      '| --- | --- | --- | --- |',
      ...r.steps.map(
        (s) =>
          `| ${s.number} | ${s.step} | ${s.outcome}${s.error ? ': ' + s.error : ''} | ${s.durationMs} |`,
      ),
      '',
    );
  }
  lines.push(
    '## Limitations',
    '',
    '- One host; all zones share a kernel and clock. Fault injection is a userspace proxy, not a radio or WAN.',
    '- Software keys only; no TPM/HSM custody. The PQC profile is a laboratory composition without independent review.',
    '- A key released before revocation committed cannot be recalled; the workflow does not claim otherwise.',
    '- Engineering evidence only: not a relevant-environment trial, independent assessment, SAG grading or TRL decision.',
    '',
  );
  return lines.join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  const requested = (process.env.SIEPMU_MISSION_PROFILES ?? PROFILES.join(',')).split(',');
  if (!requested.every((p) => PROFILES.includes(p)))
    throw new Error(`Profiles: ${PROFILES.join(', ')}`);
  const reports = [];
  for (const p of requested) reports.push(await runMissionWorkflow(p));
  await mkdir(OUTPUT, { recursive: true });
  await writeFile(join(OUTPUT, 'report.json'), JSON.stringify(reports, null, 2) + '\n');
  await writeFile(join(OUTPUT, 'report.md'), markdown(reports));
  const outcome = reports.every((r) => r.outcome === 'PASS' && r.steps.length === 18)
    ? 'PASS'
    : 'FAIL';
  console.log(`SIEPMU Core Mission Workflow ${outcome}: ${join(OUTPUT, 'report.json')}`);
  if (outcome !== 'PASS') process.exitCode = 1;
}
