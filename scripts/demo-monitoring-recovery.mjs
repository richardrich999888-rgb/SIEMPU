// HPSC Demo 4 — monitoring, disruption and recovery (synthetic).
//
// On the five-process secure stack: failed MFA login, wrong-role access, policy denial at
// release, policy restoration, ciphertext-relay outage and restart, control-authority restart,
// device revocation, redacted security telemetry at the independent collector with operator
// acknowledgement, and independent verification of the signed evidence chain (Node reference
// verifier, plus the Rust reference verifier when built).
//
// Synthetic data only. Output: artifacts/demo-monitoring-recovery/{report.json,report.md,
// evidence.json,public-key.json}. Reset: remove that directory.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { provision } from '../tests/helpers/fixture.mjs';
import { ApiClient, createObject } from '../tests/helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { requestBytes } from '../packages/transport/tls.mjs';
import { totp } from '../services/control/primitives.mjs';
import { verifyEvidence } from '../apps/verifier/verify.mjs';
import { createDemoReport, writeDemoReport } from './lib/demo-report.mjs';

const OUTPUT = resolve(process.env.SIEPMU_EVIDENCE_DIR || 'artifacts/demo-monitoring-recovery');
const RUST_VERIFIER = resolve('native/target/release/siepmu-evidence-verify');
const CANARY = 'SYNTHETIC_MONITORING_CANARY';
/** Bounded polling: 200 x 50 ms = 10 s for telemetry export and service restarts. */
const POLL_ATTEMPTS = 200;
const POLL_MS = 50;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function rustVerify(evidencePath, keyPath) {
  if (!existsSync(RUST_VERIFIER)) return null;
  try {
    execFileSync(RUST_VERIFIER, [evidencePath, keyPath], { stdio: 'pipe' });
    return 'ACCEPT';
  } catch {
    return 'REJECT';
  }
}

/** Polls `fn` until it returns a truthy value; throws `label` after the bounded wait. */
async function until(label, fn) {
  for (let i = 0; i < POLL_ATTEMPTS; i++) {
    try {
      const value = await fn();
      if (value) return value;
    } catch {}
    await sleep(POLL_MS);
  }
  throw new Error(label);
}

export async function runMonitoringRecoveryDemo() {
  const { report, step } = createDemoReport({
    kind: 'demo-monitoring-recovery',
    title: 'Demo 4 — monitoring, disruption and recovery',
    configuration: {
      platform: 'five-process secure stack (TLS 1.3 gateway; mTLS between services)',
      telemetry: 'control exports signed, redacted events to the independent collector (mTLS)',
      faults: 'process stop/start of the relay and the control authority (SIGTERM)',
    },
    limitations: [
      'Single host; process stop/start stands in for service failure. Not a WAN, power or hardware fault test.',
      'Gateway readiness reflects the control authority only; a relay outage is visible as refused work and in the authority, not as gateway unreadiness.',
      'The collector is a laboratory sink with operator acknowledgement; no external SIEM, correlation or paging.',
      'Detection rules are the implemented alert kinds only (AUTH_FAILURE, ACCESS_DENIED, ADMISSION_HELD, RELEASE_DENIED, AUTHORITY_CHANGED).',
      'Software device keys; no hardware custody. Classical endpoint suite; no SAG grading.',
    ],
  });
  const f = await provision();
  const work = mkdtempSync(join(tmpdir(), 'siepmu-demo4-'));
  let stack;
  try {
    const { alice, bob, admin: adminProfile } = f.profiles;
    let api, admin, aliceClient, bobClient, heldId, heldReleaseEventId;
    const epoch = async (client) => (await client.ok('GET', '/api/control')).payload.epoch;
    const send = async (data) => {
      const object = createObject(alice, bob, await aliceClient.grant(), { data });
      return {
        object,
        result: await aliceClient.request('POST', '/api/objects', {
          ...object,
          proof: await aliceClient.proof('submit', object),
        }),
      };
    };
    const collectorEvents = async () => {
      const r = await requestBytes(`https://127.0.0.1:${stack.ports.collector}/v1/events`, {
        tls: stack.pki.material('operator-client'),
      });
      return JSON.parse(r.body).events;
    };

    await step(
      'Start the five-process secure stack; authenticate Unit A, Unit B and admin',
      async () => {
        stack = await startSecureStack(f.dir);
        api = secureApiTransport(stack.baseUrl, stack.tls);
        admin = new ApiClient(api, adminProfile);
        aliceClient = new ApiClient(api, alice);
        bobClient = new ApiClient(api, bob);
        for (const c of [admin, aliceClient, bobClient]) await c.authenticate();
      },
    );

    await step('Failed MFA login is refused and recorded', async () => {
      const correct = totp(alice.totpSecret);
      const wrong = correct === '000000' ? '000001' : '000000';
      const r = await requestBytes(stack.baseUrl + '/api/auth/login', {
        method: 'POST',
        tls: stack.tls,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: alice.username, password: alice.password, otp: wrong }),
      });
      assert.equal(r.status, 401);
      return { httpStatus: r.status };
    });

    await step('Wrong-role access to an administrative route is refused and recorded', async () => {
      const r = await bobClient.request('GET', '/api/admin/overview');
      assert.equal(r.status, 403);
      return { httpStatus: r.status, code: r.body.code };
    });

    await step('Unit policy withdrawn: release is held with a signed decision', async () => {
      const { object, result } = await send(`${CANARY}: held`);
      assert.equal(result.status, 200);
      heldId = object.envelope.objectId;
      const change = await admin.admin('PUT', '/api/admin/policies', {
        fromUnit: alice.unitId,
        toUnit: bob.unitId,
        missionId: 'DEMO-MISSION',
        allow: false,
      });
      assert.equal(change.status, 200, JSON.stringify(change.body));
      const claim = await bobClient.claim(heldId, await epoch(bobClient));
      assert.equal(claim.status, 409);
      assert.ok(claim.body.receipt?.signature, 'held decision carries a signed receipt');
      return { httpStatus: claim.status, reason: claim.body.code };
    });

    await step(
      'Policy restored: held object re-evaluated under current policy and released',
      async () => {
        const change = await admin.admin('PUT', '/api/admin/policies', {
          fromUnit: alice.unitId,
          toUnit: bob.unitId,
          missionId: 'DEMO-MISSION',
          allow: true,
        });
        assert.equal(change.status, 200);
        const { object, result } = await send(`${CANARY}: delivered`);
        assert.equal(result.status, 200);
        const claim = await bobClient.claim(object.envelope.objectId, await epoch(bobClient));
        assert.equal(claim.status, 200, JSON.stringify(claim.body));
        // Release follows current policy: the earlier HELD decision is not a permanent block.
        const again = await bobClient.claim(heldId, await epoch(bobClient));
        assert.equal(again.status, 200, JSON.stringify(again.body));
        heldReleaseEventId = again.body.receipt.payload.eventId;
        return {
          newObjectReleased: object.envelope.objectId,
          previouslyHeldObject: {
            id: heldId,
            status: again.status,
            releaseEventId: heldReleaseEventId,
          },
        };
      },
    );

    await step('Ciphertext relay outage: submission refused, nothing half-written', async () => {
      const before = (await aliceClient.ok('GET', '/api/objects')).objects.length;
      await stack.stopRole('relay');
      const { result } = await send(`${CANARY}: during outage`);
      assert.ok(result.status >= 500, `expected a server-side refusal, got ${result.status}`);
      const after = (await aliceClient.ok('GET', '/api/objects')).objects.length;
      assert.equal(after, before, 'no object recorded without its ciphertext');
      return { httpStatus: result.status, objectsBefore: before, objectsAfter: after };
    });

    await step('Relay restarted: submission accepted again', async () => {
      stack.start('relay');
      const status = await until('relay did not recover', async () => {
        const { result } = await send(`${CANARY}: after recovery`);
        return result.status === 200 ? result.status : null;
      });
      return { httpStatus: status };
    });

    await step(
      'Control authority restart: unready while down; same issuance on retry after',
      async () => {
        await stack.stopRole('control');
        const down = await requestBytes(stack.baseUrl + '/health/ready', {
          tls: stack.tls,
          timeoutMs: 2000,
        }).then((r) => r.status);
        assert.notEqual(down, 200);
        stack.start('control');
        await until(
          'control did not recover',
          async () =>
            (await requestBytes(stack.baseUrl + '/health/ready', { tls: stack.tls })).status ===
            200,
        );
        // Sessions and issuances are durable: a retried claim returns the same signed issuance.
        const claim = await until('claim retry failed after restart', async () => {
          const r = await bobClient.claim(heldId, await epoch(bobClient));
          return r.status === 200 ? r : null;
        });
        assert.equal(
          claim.body.receipt.payload.eventId,
          heldReleaseEventId,
          'no duplicate issuance',
        );
        return { readinessWhileDown: down, retriedIssuanceEventId: heldReleaseEventId };
      },
    );

    await step('Device revocation takes effect at the next request', async () => {
      const r = await admin.admin('POST', `/api/admin/devices/${bob.deviceId}/revoke`);
      assert.equal(r.status, 200, JSON.stringify(r.body));
      const after = await bobClient.request('GET', '/api/objects');
      assert.ok([401, 403].includes(after.status), String(after.status));
      return { httpStatus: after.status, code: after.body.code };
    });

    await step(
      'Independent collector shows redacted security events; operator acknowledges',
      async () => {
        const wanted = ['AUTH_FAILURE', 'ACCESS_DENIED', 'RELEASE_DENIED', 'AUTHORITY_CHANGED'];
        let seen = [];
        const events = await until('telemetry did not arrive', async () => {
          // Telemetry is pushed after each control request; make one so a batch is exported.
          await admin.request('GET', '/api/auth/me');
          const list = await collectorEvents();
          seen = [...new Set(list.map((x) => x.event.eventType))];
          return wanted.every((k) => seen.includes(k)) ? list : null;
        }).catch((error) => {
          throw new Error(`${error.message}; kinds seen: ${seen.join(',')}`);
        });
        assert.equal(JSON.stringify(events).includes(CANARY), false, 'no content in telemetry');
        const target = events.find((x) => x.event.eventType === 'ACCESS_DENIED');
        const ack = await requestBytes(`https://127.0.0.1:${stack.ports.collector}/v1/ack`, {
          method: 'POST',
          tls: stack.pki.material('operator-client'),
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ eventId: target.event.eventId, disposition: 'INVESTIGATING' }),
        });
        assert.equal(ack.status, 200);
        const outsider = await requestBytes(
          `https://127.0.0.1:${stack.ports.collector}/v1/events`,
          {
            tls: stack.pki.material('control-client'),
          },
        );
        assert.equal(outsider.status, 403);
        const counts = Object.fromEntries(
          wanted.map((k) => [k, events.filter((x) => x.event.eventType === k).length]),
        );
        return { eventCounts: counts, operatorAck: ack.status, nonOperatorRead: outsider.status };
      },
    );

    await step('Signed evidence verifies independently; a tampered copy is rejected', async () => {
      const evidence = await admin.ok('GET', '/api/evidence/export');
      await verifyEvidence(evidence, f.provisioned.serverPublicKey);
      const tampered = structuredClone(evidence);
      tampered.records[1].payload.decision = 'TAMPERED';
      await assert.rejects(verifyEvidence(tampered, f.provisioned.serverPublicKey));
      mkdirSync(OUTPUT, { recursive: true });
      const evidencePath = join(OUTPUT, 'evidence.json');
      const keyPath = join(OUTPUT, 'public-key.json');
      writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));
      writeFileSync(keyPath, JSON.stringify(f.provisioned.serverPublicKey, null, 2));
      const tamperedPath = join(work, 'tampered.json');
      writeFileSync(tamperedPath, JSON.stringify(tampered));
      const rust = rustVerify(evidencePath, keyPath);
      const rustTampered = rustVerify(tamperedPath, keyPath);
      if (rust !== null) {
        assert.equal(rust, 'ACCEPT');
        assert.equal(rustTampered, 'REJECT');
      }
      return {
        records: evidence.records.length,
        nodeVerifier: 'ACCEPT; tampered REJECT',
        rustVerifier: rust === null ? 'NOT_BUILT' : { genuine: rust, tampered: rustTampered },
      };
    });
    report.outcome = 'PASS';
  } catch {
    report.outcome = 'FAIL';
  } finally {
    await stack?.stop();
    rmSync(work, { recursive: true, force: true });
    rmSync(f.dir, { recursive: true, force: true });
    await writeDemoReport(OUTPUT, report);
  }
  return report;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const report = await runMonitoringRecoveryDemo();
  console.log(`Demo 4 ${report.outcome}: ${join(OUTPUT, 'report.json')}`);
  if (report.outcome !== 'PASS') process.exitCode = 1;
}
