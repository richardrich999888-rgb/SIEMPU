// Synthetic negative-control comparison, not a model of any named messaging product.
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { cpus, totalmem } from 'node:os';
import { coreFixture } from '../tests/helpers/fixture.mjs';
import { createObject, decryptObject, pair } from '../tests/helpers/client.mjs';
import { verifyEvidence } from '../apps/verifier/verify.mjs';
import { packet } from '../services/control/primitives.mjs';
import {
  CheckpointCustodian,
  createRecoveryGuard,
  authoritySnapshot,
  authorizationDigest,
} from '../services/evidence/custody.mjs';
import { join } from 'node:path';

export async function comparePolicyRelease({ iterations = 20, custody = 'none' } = {}) {
  if (!Number.isSafeInteger(iterations) || iterations < 3 || iterations > 30)
    throw new Error('Comparison iterations must be 3..30');
  if (!['none', 'fenced'].includes(custody)) throw new Error('Unknown custody profile');
  const cleanup = [];
  const f = await coreFixture({ after: (fn) => cleanup.push(fn) });
  if (custody === 'fenced') {
    const keys = pair(),
      writer = pair();
    const custodian = new CheckpointCustodian({
      database: join(f.dir, 'benchmark-custody.sqlite'),
      authorityKey: f.provisioned.serverPublicKey,
      signingKey: keys.privateKey,
      allowBootstrap: true,
    });
    cleanup.push(() => custodian.close());
    const evidence = authoritySnapshot(f.authority),
      stateDigest = authorizationDigest(f.authority);
    await custodian.accept(
      packet(f.authority.key, {
        version: 1,
        nonce: crypto.randomUUID(),
        issuedAt: Date.now(),
        stateDigest,
        evidence,
      }),
    );
    const cp = evidence.checkpoint.payload,
      row = f.authority.epoch();
    custodian.transferWriter({
      writerKey: writer.publicKey,
      expectedGeneration: 0,
      expectedAnchor: { sequence: cp.sequence, headHash: cp.headHash, stateDigest },
      authority: { epoch: row.epoch, revocationVersion: row.revocation_version },
    });
    f.authority.recoveryGuard = createRecoveryGuard({
      custodianKey: keys.publicKey,
      writer: { key: writer.privateKey, generation: 1 },
      exchange: (r) => custodian.accept(r),
      anchorQuery: (r) => custodian.anchor(r),
    });
  }
  const samples = {
    encryptAndSign: [],
    admitAndPrepare: [],
    policyRelease: [],
    candidateDecrypt: [],
    predeliveredDecrypt: [],
    verifyEvidence: [],
  };
  const measure = async (name, fn) => {
    const begin = performance.now();
    const value = await fn();
    samples[name].push(performance.now() - begin);
    return value;
  };
  const memoryBefore = process.memoryUsage();
  try {
    const { alice, bob, admin } = f.clients;
    await alice.authenticate();
    await bob.authenticate();
    await admin.authenticate();
    const grant = await alice.grant();
    const data = 'SYNTHETIC policy comparison '.padEnd(4096, 'x');
    const cpuBefore = process.cpuUsage(),
      begin = performance.now();
    let previouslyReleased;
    for (let i = 0; i < iterations; i++) {
      const object = await measure('encryptAndSign', () =>
        createObject(f.profiles.alice, f.profiles.bob, grant, { data }),
      );
      await measure('admitAndPrepare', async () => {
        await alice.submit(object);
        assert.equal((await alice.prepare(object.envelope.objectId)).status, 200);
      });
      const control = await bob.ok('GET', '/api/control');
      const release = await measure('policyRelease', () =>
        bob.claim(object.envelope.objectId, control.payload.epoch),
      );
      assert.equal(release.status, 200);
      previouslyReleased = release.body;
      const baseline = {
        ...object,
        senderSigningPublicKey: f.profiles.alice.keys.signing.publicKey,
      };
      // Alternate ordering to reduce a systematic first-run bias. Both use the same crypto peer.
      for (const which of i % 2 ? ['baseline', 'candidate'] : ['candidate', 'baseline']) {
        const payload = await measure(
          which === 'baseline' ? 'predeliveredDecrypt' : 'candidateDecrypt',
          () => decryptObject(which === 'baseline' ? baseline : release.body, f.profiles.bob),
        );
        assert.equal(payload.bytes.toString(), data);
      }
    }
    const elapsedMs = performance.now() - begin,
      cpuMicroseconds = process.cpuUsage(cpuBefore);
    // One pending object: the reference gives the recipient its wrapped key before policy changes.
    const pending = createObject(f.profiles.alice, f.profiles.bob, grant, { data });
    await alice.submit(pending);
    assert.equal((await alice.prepare(pending.envelope.objectId)).status, 200);
    const oldControl = await bob.ok('GET', '/api/control');
    const before = Number(f.authority.get('SELECT COUNT(*) n FROM issuances').n);
    const revoke = await admin.admin('PUT', '/api/admin/policies', {
      fromUnit: f.provisioned.units.A,
      toUnit: f.provisioned.units.B,
      missionId: 'DEMO-MISSION',
      allow: false,
    });
    assert.equal(revoke.status, 200);
    const stale = await bob.claim(pending.envelope.objectId, oldControl.payload.epoch);
    assert.equal(stale.status, 409);
    const fresh = await bob.ok('GET', '/api/control');
    const denied = await bob.claim(pending.envelope.objectId, fresh.payload.epoch);
    assert.equal(denied.status, 409);
    assert.equal(denied.body.object.reason, 'POLICY_DENIED');
    assert.equal(denied.body.object.state, 'HELD');
    const after = Number(f.authority.get('SELECT COUNT(*) n FROM issuances').n);
    assert.equal(after, before);
    const reference = {
      ...pending,
      senderSigningPublicKey: f.profiles.alice.keys.signing.publicKey,
    };
    assert.equal(decryptObject(reference, f.profiles.bob).bytes.toString(), data);
    assert.equal(decryptObject(previouslyReleased, f.profiles.bob).bytes.toString(), data);
    const evidence = await admin.ok('GET', '/api/evidence/export');
    for (let i = 0; i < 5; i++) {
      const verified = await measure('verifyEvidence', () =>
        verifyEvidence(evidence, f.provisioned.serverPublicKey, {
          checkpoint: evidence.checkpoint,
        }),
      );
      assert.equal(verified.valid, true);
    }
    const corrupt = structuredClone(evidence);
    corrupt.records.pop();
    await assert.rejects(
      verifyEvidence(corrupt, f.provisioned.serverPublicKey, { checkpoint: evidence.checkpoint }),
    );
    const summarize = (values) => {
      const sorted = [...values].sort((a, b) => a - b);
      return {
        count: sorted.length,
        p50Ms: sorted[Math.ceil(sorted.length * 0.5) - 1],
        p95Ms: sorted[Math.ceil(sorted.length * 0.95) - 1],
        minMs: sorted[0],
        maxMs: sorted.at(-1),
      };
    };
    return {
      report: {
        schemaVersion: 1,
        status: 'MEASURED_SYNTHETIC',
        environment: {
          node: process.version,
          openssl: process.versions.openssl,
          platform: process.platform,
          arch: process.arch,
          cpu: cpus()[0]?.model,
          logicalCpus: cpus().length,
          hostMemoryBytes: totalmem(),
        },
        workload: {
          iterations,
          payloadBytes: 4096,
          concurrency: 1,
          custody,
          transport: 'in-process dispatch; temporary SQLite; in-memory ciphertext relay',
          baseline:
            'same signed encrypted object, wrapped key delivered in advance, no subsequent policy contact',
          percentileMethod: 'nearest-rank',
        },
        samplesMs: samples,
        measurements: Object.fromEntries(
          Object.entries(samples).map(([k, v]) => [k, summarize(v)]),
        ),
        elapsedMs,
        sequentialObjectsPerSecond: iterations / (elapsedMs / 1000),
        cpuMicroseconds,
        memoryBefore,
        memoryAfter: process.memoryUsage(),
        processMaxRssKiB: process.resourceUsage().maxRSS,
        policyExperiment: {
          pendingObjects: 1,
          staleEpochStatus: stale.status,
          currentPolicyStatus: denied.status,
          currentPolicyReason: denied.body.object.reason,
          newIssuancesAfterRevocation: after - before,
          predeliveredReferenceDecrypts: true,
          previouslyReleasedCandidateStillDecrypts: true,
        },
        audit: {
          records: evidence.records.length,
          bytes: Buffer.byteLength(JSON.stringify(evidence)),
          tamperedExportRejected: true,
          checkpoint:
            'same-run local retained checkpoint; not an independently administered custodian',
        },
        limitations: [
          'The reference deliberately lacks a fresh-policy boundary; it does not represent Sandes, SAMVAD, Signal or every secure messenger.',
          'This compares a release property and measures its cost; it establishes neither novelty nor superior overall performance.',
          'Objects and keys already released cannot be recalled by either approach.',
          'Timings include helper-generated device proofs and signed evidence; setup/authentication excluded.',
          'Process RSS peak includes setup; CPU spans sequential exchange plus reference decryption, not isolated service CPU.',
          'No WAN, load ceiling, HA, HSM or field performance is measured. Network/recovery evidence belongs to separate named CI matrices.',
          'Fenced profile, when selected, uses a separately keyed SQLite custodian in this same process; timing excludes inter-host custody RTT and independent administration.',
        ],
      },
      evidence,
      publicKey: f.provisioned.serverPublicKey,
    };
  } finally {
    for (const fn of cleanup.reverse()) await fn();
  }
}
