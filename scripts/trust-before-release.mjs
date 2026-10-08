// Trust Before Release: scripted synthetic demonstration on the real secure stack.
//
// Five separate service processes (TLS 1.3 gateway, control authority, ciphertext relay,
// checkpoint custodian, telemetry collector; mTLS between services), Unit A / Unit B /
// Unit C synthetic identities, MFA and device binding, laboratory schema-v3 PQC content,
// a userspace fault proxy that genuinely interrupts Unit A's connection, revocation while
// Unit A is disconnected, selective release on reconnection, downgrade rejection,
// independent evidence verification, control-authority restart, and measured timings.
//
// Synthetic data only. Engineering evidence, not an acceptance test, TRL decision, SAG grading
// or operational trial. Output: artifacts/trust-before-release/{report.json,report.md}.
// Reset: the run uses temporary directories it deletes; remove the artifacts directory to reset.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { cpus, platform, release, totalmem } from 'node:os';
import { join, resolve } from 'node:path';
import { provision } from '../tests/helpers/fixture.mjs';
import { ApiClient, createObject, enrollUser, sign, verify } from '../tests/helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { createTransportServer, requestBytes } from '../packages/transport/tls.mjs';
import { createFaultProxy } from '../deployment/testbed/fault-proxy.mjs';
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
import { createFilePayload, unpackPayload } from '../packages/crypto/crypto.mjs';
import { verifyEvidence, verifyReleaseReceipt } from '../apps/verifier/verify.mjs';

const OUTPUT = resolve(process.env.SIEPMU_EVIDENCE_DIR || 'artifacts/trust-before-release');
const ITERATIONS_DEFAULT = 20;
const ITERATIONS_MIN = 5;
const ITERATIONS_MAX = 200;
const PAYLOAD_BYTES = 16384;
const READY_POLL_MS = 50;
const READY_ATTEMPTS = 200;
const CLASSICAL = { providerId: CLASSICAL_PROVIDER_ID, suiteId: CLASSICAL_SUITE_ID };
const MLKEM768 = { providerId: NATIVE_PQC_PROVIDER_ID, suiteId: NATIVE_MLKEM768_SUITE };

/** Bounded integer from the environment; invalid input fails closed. */
export function iterationsFromEnv(value) {
  if (value === undefined) return ITERATIONS_DEFAULT;
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < ITERATIONS_MIN || n > ITERATIONS_MAX)
    throw new Error(`SIEPMU_TBR_ITERATIONS must be ${ITERATIONS_MIN}-${ITERATIONS_MAX}`);
  return n;
}

/** Nearest-rank percentile over a sorted copy. */
export function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.max(1, Math.ceil((p / 100) * sorted.length));
  return sorted[rank - 1];
}

export const syntheticBytes = (seed, length) =>
  Buffer.from(Array.from({ length }, (_, i) => (i * 131 + seed) % 256));
const ms = (start) => Math.round((performance.now() - start) * 100) / 100;

export function sourceRevision() {
  const git = (args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
  try {
    return { commit: git(['rev-parse', 'HEAD']), dirty: git(['status', '--porcelain']) !== '' };
  } catch {
    return { commit: null, dirty: null };
  }
}

/** Adapts the bounded TLS 1.3 client to the minimal fetch contract used by the fault proxy. */
export function tlsFetch(tls) {
  return async (url, { method, headers, body }) => {
    const r = await requestBytes(url, { method, headers, body, tls });
    return {
      status: r.status,
      headers: { get: (name) => r.headers[name.toLowerCase()] ?? null },
      arrayBuffer: async () => r.body,
    };
  };
}

export async function waitReady(baseUrl, tls) {
  for (let i = 0; i < READY_ATTEMPTS; i++) {
    try {
      if ((await requestBytes(baseUrl + '/health/ready', { tls, timeoutMs: 500 })).status === 200)
        return;
    } catch {}
    await new Promise((r) => setTimeout(r, READY_POLL_MS));
  }
  throw new Error('Stack did not become ready');
}

export async function runTrustBeforeRelease({ iterations = ITERATIONS_DEFAULT } = {}) {
  const steps = [];
  const report = {
    schemaVersion: 1,
    kind: 'trust-before-release',
    synthetic: true,
    startedAt: new Date().toISOString(),
    source: sourceRevision(),
    runtime: {
      node: process.version,
      openssl: process.versions.openssl,
      platform: `${platform()} ${release()}`,
      cpu: cpus()[0]?.model ?? null,
      cpuCount: cpus().length,
      memoryBytes: totalmem(),
    },
    configuration: {
      transport: 'TLS 1.3 client-to-gateway; mTLS between services',
      contentSuite: NATIVE_MLKEM768_SUITE,
      faultInjection: 'userspace HTTP fault proxy on Unit A path (not netem, not radio)',
      iterations,
      payloadBytes: PAYLOAD_BYTES,
    },
    steps,
    limitations: [
      'Single host; all zones share one kernel and clock. Not a WAN, radio or relevant-environment trial.',
      'Laboratory PQC composition; no independent cryptographic review, SAG grading or module validation.',
      'Software device keys and software PQC handles; no TPM/HSM custody.',
      'An issuance committed before revocation cannot be recalled; the demonstration does not claim otherwise.',
      'Timings are for this host only and are not capacity or acceptance figures.',
      'Each HTTP request opens a new TLS 1.3 connection (bounded client, no keep-alive); round-trip timings include handshakes.',
    ],
  };
  const step = async (name, fn) => {
    const started = performance.now();
    try {
      const evidence = (await fn()) ?? {};
      steps.push({ step: name, outcome: 'PASS', durationMs: ms(started), ...evidence });
      console.log(`PASS: ${name}`);
    } catch (error) {
      steps.push({ step: name, outcome: 'FAIL', durationMs: ms(started), error: error.message });
      console.log(`FAIL: ${name}: ${error.message}`);
      throw error;
    }
  };

  const previousLab = process.env.SIEPMU_ALLOW_PQC_LAB;
  process.env.SIEPMU_ALLOW_PQC_LAB = '1';
  const f = await provision();
  let stack, proxy;
  try {
    await step(
      'Start five-process secure stack (TLS 1.3, mTLS, custody, collector; PQC lab on)',
      async () => {
        stack = await startSecureStack(f.dir);
        return { ports: stack.ports };
      },
    );
    const direct = secureApiTransport(stack.baseUrl, stack.tls);
    const proxyIdentity = stack.pki.issue('tbr-fault-proxy');
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
    let colleague;

    await step(
      'Unit A, Unit B, Unit C and admin: password + TOTP MFA + signed device binding',
      async () => {
        for (const c of [alice, bob, eve, admin]) await c.authenticate();
        return { units: { alice: 'A', bob: 'B', eve: 'C' } };
      },
    );
    await step('Enrol and approve a second Unit B device/user (bob-backup)', async () => {
      colleague = await enrollUser(admin, {
        username: 'bob-backup',
        unitId: f.provisioned.units.B,
      });
    });

    const endpoints = {};
    await step(
      'Endpoints generate PQC keys locally; devices register public keys; admin activates',
      async () => {
        for (const [name, client] of [
          ['alice', alice],
          ['bob', bob],
          ['colleague', colleague.client],
        ]) {
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
        return { privateKeysExported: false };
      },
    );

    let policy;
    const setPolicy = async (newSuites, legacySuites) => {
      const current = (await admin.ok('GET', '/api/admin/crypto')).policy;
      policy = {
        schemaVersion: 1,
        revision: current.revision + 1,
        mode: 'laboratory',
        newSuites,
        legacySuites,
      };
      const r = await admin.admin('PUT', '/api/admin/crypto/policy', { policy });
      assert.equal(r.status, 200, JSON.stringify(r.body));
    };
    await step('Crypto policy admits classical and ML-KEM-768 laboratory suite', async () => {
      await setPolicy([CLASSICAL, MLKEM768], [CLASSICAL, MLKEM768]);
      return { policyRevision: policy.revision };
    });

    const v3 = async (recipientName, recipientProfile, seed, { grant, ...extra } = {}) => {
      const bytes = syntheticBytes(seed, PAYLOAD_BYTES);
      const context = labContext({
        sender: f.profiles.alice,
        recipient: recipientProfile,
        creationGrant: grant ?? (await alice.grant()),
        selection: MLKEM768,
        senderCryptoKeyId: endpoints.alice.signingKey.keyId,
        recipientKeyId: endpoints[recipientName].encapsulationKey.keyId,
        suitePolicyRevision: policy.revision,
        objectId: randomUUID(),
        now: Date.now(),
        ...extra,
      });
      const object = await createProviderObject({
        engine: endpoints.alice.engine,
        context,
        payload: createFilePayload('synthetic.bin', 'application/octet-stream', bytes),
        recipientKey: endpoints[recipientName].encapsulationKey,
        senderKey: endpoints.alice.signingKey,
        identitySigningKey: f.profiles.alice.keys.signing.privateKey,
      });
      return { object, bytes };
    };
    const open = (name, claim) =>
      openProviderObject({
        engine: endpoints[name].engine,
        claim,
        senderKey: claim.senderCryptoKey,
        senderIdentityPublicKey: claim.senderSigningPublicKey,
        expected: { suiteId: NATIVE_MLKEM768_SUITE },
      });
    const epochOf = async (client) => (await client.ok('GET', '/api/control')).payload.epoch;

    await step(
      'Baseline: Unit A -> Unit B end-to-end encrypted exchange with exact bytes',
      async () => {
        const { object, bytes } = await v3('bob', f.profiles.bob, 1);
        await alice.submit(object);
        await alice.prepare(object.envelope.objectId);
        const unrelated = await eve.claim(object.envelope.objectId, await epochOf(eve));
        assert.equal(unrelated.status, 404);
        const claim = await bob.claim(object.envelope.objectId, await epochOf(bob));
        assert.equal(claim.status, 200, JSON.stringify(claim.body));
        assert.deepEqual(Buffer.from(unpackPayload(await open('bob', claim.body)).bytes), bytes);
        return { unitCClaimStatus: unrelated.status, bytes: bytes.length };
      },
    );

    const queued = {};
    await step(
      'Unit A loses connectivity; two objects are encrypted locally and cannot be sent',
      async () => {
        // The endpoint holds a bounded creation grant obtained while connected; it permits
        // local creation only and does not authorise any later release.
        const cachedGrant = await alice.grant();
        proxy.state.offline = true;
        queued.toBob = await v3('bob', f.profiles.bob, 2, { grant: cachedGrant });
        queued.toColleague = await v3('colleague', colleague.profile, 3, { grant: cachedGrant });
        await assert.rejects(alice.submit(queued.toBob.object));
        return { proxyCuts: proxy.state.cuts };
      },
    );
    await step(
      'While Unit A is disconnected, Unit B recipient bob is revoked (committed first)',
      async () => {
        const r = await admin.admin('PATCH', `/api/admin/users/${f.profiles.bob.userId}`, {
          active: false,
        });
        assert.equal(r.status, 200, JSON.stringify(r.body));
        return { epochAfterRevocation: await epochOf(admin) };
      },
    );
    let colleagueClaim;
    await step(
      'Reconnect: queue submitted; current policy re-checked; revoked recipient HELD with signed evidence',
      async () => {
        proxy.state.offline = false;
        await alice.submit(queued.toBob.object);
        await alice.submit(queued.toColleague.object);
        const held = await alice.prepare(queued.toBob.object.envelope.objectId);
        assert.equal(held.body.object.state, 'HELD');
        assert.equal(held.body.object.reason, 'USER_REVOKED');
        const ready = await alice.prepare(queued.toColleague.object.envelope.objectId);
        assert.equal(ready.body.object.state, 'READY');
        // A revoked user cannot even obtain an operation-proof challenge, so the key-bearing
        // claim route is never reached. Record the refusal as observed.
        let refusal;
        try {
          await bob.claim(queued.toBob.object.envelope.objectId, await epochOf(admin));
          refusal = 'CLAIM_UNEXPECTEDLY_SUCCEEDED';
        } catch (error) {
          refusal = error.message
            .match(/: (\d{3}) .*"code":"([A-Z_]+)"/)
            ?.slice(1, 3)
            .join(' ');
        }
        assert.equal(refusal, '401 USER_REVOKED');
        const receipt = held.body.receipt;
        assert.equal(receipt.payload.decision, 'HELD');
        assert.equal(receipt.payload.reason, 'USER_REVOKED');
        assert.ok(verify(receipt.payload, receipt.signature, f.provisioned.serverPublicKey));
        return { heldReason: held.body.object.reason, revokedRecipientRefusal: refusal };
      },
    );
    await step('Eligible Unit B recipient receives key and decrypts exact bytes', async () => {
      colleagueClaim = await colleague.client.claim(
        queued.toColleague.object.envelope.objectId,
        await epochOf(colleague.client),
      );
      assert.equal(colleagueClaim.status, 200, JSON.stringify(colleagueClaim.body));
      const payload = await open('colleague', colleagueClaim.body);
      assert.deepEqual(Buffer.from(unpackPayload(payload).bytes), queued.toColleague.bytes);
      return { provenance: colleagueClaim.body.receipt.payload.details.crypto };
    });
    await step(
      'Downgrade rejected: suite substitution and classical object after policy excludes it',
      async () => {
        const { object } = await v3('colleague', colleague.profile, 4);
        const substituted = { ...object.envelope, cryptoSuite: NATIVE_MLKEM1024_SUITE };
        const forged = {
          ...object,
          envelope: substituted,
          signature: sign(substituted, f.profiles.alice.keys.signing.privateKey),
        };
        const r1 = await alice.request('POST', '/api/objects', {
          ...forged,
          proof: await alice.proof('submit', forged),
        });
        assert.ok([400, 403].includes(r1.status));
        await setPolicy([MLKEM768], [CLASSICAL, MLKEM768]);
        const classical = createObject(f.profiles.alice, colleague.profile, await alice.grant());
        const r2 = await alice.request('POST', '/api/objects', {
          ...classical,
          proof: await alice.proof('submit', classical),
        });
        assert.equal(r2.status, 403);
        assert.equal(r2.body.code, 'CRYPTO_SUITE_FORBIDDEN');
        return { suiteSubstitution: r1.body.code, classicalAfterPolicy: r2.body.code };
      },
    );

    await mkdir(OUTPUT, { recursive: true });
    await step(
      'Independent verifier: strict release receipt and full signed chain with checkpoint',
      async () => {
        const receipt = colleagueClaim.body.receipt;
        const replay = join(OUTPUT, `replay-${Date.now()}.sqlite`);
        const strict = await verifyReleaseReceipt(receipt, f.provisioned.serverPublicKey, {
          objectDigest: colleagueClaim.body.object.ciphertextHash,
          epoch: receipt.payload.epoch,
          objectId: queued.toColleague.object.envelope.objectId,
          replayStore: replay,
        });
        assert.equal(strict.strictReleaseVerified, true);
        await assert.rejects(
          verifyReleaseReceipt(receipt, f.provisioned.serverPublicKey, {
            objectDigest: colleagueClaim.body.object.ciphertextHash,
            epoch: receipt.payload.epoch,
            objectId: queued.toColleague.object.envelope.objectId,
            replayStore: replay,
          }),
        );
        const evidence = await admin.ok('GET', '/api/evidence/export');
        const chain = await verifyEvidence(evidence, f.provisioned.serverPublicKey, {
          checkpoint: evidence.checkpoint,
        });
        assert.equal(chain.valid, true);
        await writeFile(join(OUTPUT, 'evidence.json'), JSON.stringify(evidence, null, 2));
        await writeFile(join(OUTPUT, 'receipt.json'), JSON.stringify(receipt, null, 2));
        await writeFile(
          join(OUTPUT, 'public-key.json'),
          JSON.stringify(f.provisioned.serverPublicKey, null, 2),
        );
        await rm(replay, { force: true });
        return { records: evidence.records.length, replayRejected: true };
      },
    );
    await step(
      'Restart control authority: decisions persist; retry replays the one issuance',
      async () => {
        await stack.stopRole('control');
        stack.start('control');
        await waitReady(stack.baseUrl, stack.tls);
        const retry = await colleague.client.claim(
          queued.toColleague.object.envelope.objectId,
          await epochOf(colleague.client),
        );
        assert.equal(retry.status, 200, JSON.stringify(retry.body));
        assert.equal(
          retry.body.receipt.payload.eventId,
          colleagueClaim.body.receipt.payload.eventId,
        );
        const evidence = await admin.ok('GET', '/api/evidence/export');
        const issued = evidence.records.filter(
          (r) =>
            r.payload.objectId === queued.toColleague.object.envelope.objectId &&
            r.payload.eventType === 'RELEASE_ISSUED',
        );
        assert.equal(issued.length, 1);
        const overview = await admin.ok('GET', '/api/admin/overview');
        const held = overview.objects.find((o) => o.id === queued.toBob.object.envelope.objectId);
        assert.equal(held.state, 'HELD');
        return { issuancesForObject: issued.length, revokedObjectState: held.state };
      },
    );

    await step(
      `Measured v3 exchange timings over the secure stack (${iterations} iterations)`,
      async () => {
        await setPolicy([CLASSICAL, MLKEM768], [CLASSICAL, MLKEM768]);
        const stages = {
          grant: [],
          endpointSeal: [],
          submitAndPrepare: [],
          claim: [],
          endpointOpen: [],
          total: [],
        };
        const sender = new ApiClient(direct, f.profiles.alice);
        sender.token = alice.token;
        for (let i = 0; i < iterations; i++) {
          const tg = performance.now();
          // Direct (unimpaired) path, so endpointSeal measures endpoint cryptography only.
          const grant = await sender.grant();
          const t0 = performance.now();
          const { object, bytes } = await v3('colleague', colleague.profile, 100 + i, { grant });
          const t1 = performance.now();
          await sender.submit(object);
          await sender.prepare(object.envelope.objectId);
          const t2 = performance.now();
          const claim = await colleague.client.claim(
            object.envelope.objectId,
            await epochOf(sender),
          );
          assert.equal(claim.status, 200);
          const t3 = performance.now();
          const payload = await open('colleague', claim.body);
          assert.deepEqual(Buffer.from(unpackPayload(payload).bytes), bytes);
          const t4 = performance.now();
          stages.grant.push(t0 - tg);
          stages.endpointSeal.push(t1 - t0);
          stages.submitAndPrepare.push(t2 - t1);
          stages.claim.push(t3 - t2);
          stages.endpointOpen.push(t4 - t3);
          stages.total.push(t4 - tg);
        }
        const summary = Object.fromEntries(
          Object.entries(stages).map(([k, v]) => [
            k,
            {
              p50Ms: Math.round(percentile(v, 50) * 10) / 10,
              p95Ms: Math.round(percentile(v, 95) * 10) / 10,
              maxMs: Math.round(Math.max(...v) * 10) / 10,
            },
          ]),
        );
        return { timings: summary, note: 'Includes grant and operation-proof round trips.' };
      },
    );
    report.outcome = 'PASS';
  } catch {
    report.outcome = 'FAIL';
  } finally {
    if (proxy) await new Promise((r) => proxy.server.close(r));
    if (stack) await stack.stop();
    await rm(f.dir, { recursive: true, force: true });
    if (previousLab === undefined) delete process.env.SIEPMU_ALLOW_PQC_LAB;
    else process.env.SIEPMU_ALLOW_PQC_LAB = previousLab;
    report.finishedAt = new Date().toISOString();
    await mkdir(OUTPUT, { recursive: true });
    await writeFile(join(OUTPUT, 'report.json'), JSON.stringify(report, null, 2) + '\n');
    await writeFile(join(OUTPUT, 'report.md'), markdownReport(report));
  }
  return report;
}

export function markdownReport(report) {
  const lines = [
    '# Trust Before Release — synthetic demonstration report',
    '',
    `Outcome: **${report.outcome}**. Commit \`${report.source.commit}\`${report.source.dirty ? ' (dirty tree)' : ''}.`,
    `Run ${report.startedAt} → ${report.finishedAt}. Node ${report.runtime.node}, OpenSSL ${report.runtime.openssl}, ${report.runtime.platform}, ${report.runtime.cpuCount}× ${report.runtime.cpu}.`,
    '',
    '| # | Step | Outcome | ms |',
    '| --- | --- | --- | --- |',
    ...report.steps.map((s, i) => `| ${i + 1} | ${s.step} | ${s.outcome} | ${s.durationMs} |`),
    '',
  ];
  const timing = report.steps.find((s) => s.timings)?.timings;
  if (timing) {
    lines.push('| Stage | p50 ms | p95 ms | max ms |', '| --- | --- | --- | --- |');
    for (const [k, v] of Object.entries(timing))
      lines.push(`| ${k} | ${v.p50Ms} | ${v.p95Ms} | ${v.maxMs} |`);
    lines.push('');
  }
  lines.push('## Limitations', '', ...report.limitations.map((l) => `- ${l}`), '');
  return lines.join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  const report = await runTrustBeforeRelease({
    iterations: iterationsFromEnv(process.env.SIEPMU_TBR_ITERATIONS),
  });
  console.log(`Trust Before Release ${report.outcome}: ${join(OUTPUT, 'report.json')}`);
  if (report.outcome !== 'PASS') process.exitCode = 1;
}
