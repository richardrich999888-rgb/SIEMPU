import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
export const benchmarkProtocol = Object.freeze({
  repetitions: 3,
  exchangesPerRepetition: 10,
  bytes: 4096,
  concurrency: 1,
  timeoutMs: 30000,
  successfulFraction: 1,
  integrityFailures: 0,
  p95MinimumSamples: 20,
  p99MinimumSamples: 1000,
  duration: 'fixed-work short experiment, not endurance',
  latencyBoundary: 'sender process start through recipient ACK process exit',
});
export function quantiles(values) {
  assert.ok(
    values.every((value) => Number.isFinite(value) && value >= 0),
    'INVALID_LATENCY_SAMPLE',
  );
  const sorted = [...values].sort((a, b) => a - b);
  const q = (p) => sorted[Math.ceil(sorted.length * p) - 1] ?? null;
  return {
    count: sorted.length,
    p50Ms: q(0.5),
    p95Ms: sorted.length >= 20 ? q(0.95) : null,
    p99Ms: sorted.length >= 1000 ? q(0.99) : null,
  };
}
export async function campaign({ unit, failure, hooks = {}, record }) {
  const rows = [];
  const run = async (id, label, fn) => {
    const row = { id, label, startedAt: new Date().toISOString() },
      t = performance.now();
    try {
      row.result = await fn();
      row.outcome = 'PASS';
    } catch (error) {
      row.outcome = 'FAIL';
      row.error = String(error.message).slice(0, 200);
      row.errorCode = error.code ?? null;
      if (error.partial) row.partial = error.partial;
    }
    row.elapsedMs = performance.now() - t;
    rows.push(row);
    await record?.(row);
    return row;
  };
  const block = async (id, reason) => {
    const row = { id, outcome: 'BLOCKED', reason };
    rows.push(row);
    await record?.(row);
  };
  const exchange = async (size) => {
    const a = await unit('unit-a', 'send', size),
      b = await unit('unit-b', 'receive', a.result.objectId);
    assert.equal(b.result.sha256, a.result.sha256);
    assert.equal(b.result.bytes, a.result.bytes);
    return { sent: a, received: b };
  };
  for (const role of ['unit-a', 'unit-b', 'unit-denied', 'unit-admin'])
    await unit(role, role === 'unit-a' ? 'init' : 'login');
  await run('NET-01', 'encrypted text with signed release and delivery acknowledgement', () =>
    exchange('text'),
  );
  await run('NET-02', '256 KiB file integrity and delivery acknowledgement', () =>
    exchange(262144),
  );
  if (hooks.inspectRelay)
    await run('NET-04', 'controlled relay store inspection', hooks.inspectRelay);
  else
    await block(
      'NET-04',
      'Relay host inspection and independent filesystem inventory not supplied',
    );
  await run(
    'NET-05',
    'durable encrypted queue reopened by separate endpoint processes',
    async () => {
      const a = await unit('unit-a', 'queue', 4096),
        before = await unit('unit-a', 'queue-status');
      assert.ok(
        before.result.entries.some((x) => x.id === a.result.objectId && x.state === 'PENDING'),
      );
      const submitted = await unit('unit-a', 'submit', a.result.objectId);
      const b = await unit('unit-b', 'receive', a.result.objectId);
      assert.equal(b.result.sha256, a.result.sha256);
      const duplicate = await unit('unit-a', 'submit', a.result.objectId);
      assert.deepEqual(duplicate.result.receipt, submitted.result.receipt);
      const listing = await unit('unit-a', 'list');
      assert.equal(listing.result.objectIds.filter((id) => id === a.result.objectId).length, 1);
      return {
        objectId: a.result.objectId,
        sha256: b.result.sha256,
        duplicate,
        linkFaults: 'NOT_EXERCISED_BY_THIS_ROW',
      };
    },
  );
  if (hooks.stopAuthority && hooks.startAuthority)
    await run('NET-06', 'active authority process outage and manual restart', async () => {
      const pending = await unit('unit-a', 'queue', 4096);
      await hooks.stopAuthority();
      let denied, claim, recoveryMs;
      try {
        denied = await failure('unit-a', 'submit', pending.result.objectId);
        assert.equal(denied.status, 503);
        claim = await failure('unit-b', 'control');
        assert.equal(claim.status, 503);
        const retained = await unit('unit-a', 'queue-status');
        assert.ok(
          retained.result.entries.some(
            (x) => x.id === pending.result.objectId && x.state === 'PENDING',
          ),
        );
      } finally {
        const recoveryStarted = performance.now();
        await hooks.startAuthority();
        recoveryMs = performance.now() - recoveryStarted;
      }
      await unit('unit-a', 'submit', pending.result.objectId);
      const received = await unit('unit-b', 'receive', pending.result.objectId);
      assert.equal(received.result.sha256, pending.result.sha256);
      return {
        denied,
        claim,
        automaticHA: false,
        queueRetained: true,
        objectId: pending.result.objectId,
        recoveryMs,
        recoveryBoundary:
          'manual process restart to readiness only; single observation, not production RTO',
      };
    });
  else await block('NET-06', 'No authorised authority fault-control hook supplied');
  await block(
    'NET-07',
    'Separate active and standby hosts, controlled partition and reviewed handover required; existing local writer-fencing suite is separate evidence',
  );
  await block(
    'NET-08',
    'Independent-host recovery orchestration unavailable; unchanged recovery suites and rehearsals are local evidence',
  );
  await block(
    'NET-09',
    'Offline verifier available; separately administered observer with independently retained key/checkpoint has not run it',
  );
  await run('NET-10', 'predeclared three fixed-work repetitions', async () => {
    const repetitions = [];
    let currentSamples = [];
    try {
      for (let repetition = 0; repetition < benchmarkProtocol.repetitions; repetition++) {
        const samples = [],
          t = performance.now();
        currentSamples = samples;
        for (let i = 0; i < benchmarkProtocol.exchangesPerRepetition; i++) {
          const begin = performance.now();
          const result = await exchange(benchmarkProtocol.bytes);
          samples.push({
            index: i,
            elapsedMs: performance.now() - begin,
            sender: result.sent.resources,
            recipient: result.received.resources,
            senderRss: result.sent.rss,
            recipientRss: result.received.rss,
            queueDepth: result.sent.result.queueDepth,
            objectId: result.sent.result.objectId,
          });
        }
        const elapsedMs = performance.now() - t;
        repetitions.push({
          repetition,
          samples,
          elapsedMs,
          objectsPerSecond: samples.length / (elapsedMs / 1000),
          ...quantiles(samples.map((x) => x.elapsedMs)),
        });
        currentSamples = [];
      }
      return {
        protocol: benchmarkProtocol,
        repetitions,
        pooled: quantiles(repetitions.flatMap((r) => r.samples.map((s) => s.elapsedMs))),
        endurance: 'BLOCKED_NOT_EXECUTED',
        productionRto: null,
        baselineComparison: 'NONE',
      };
    } catch (error) {
      error.partial = { protocol: benchmarkProtocol, repetitions, currentSamples };
      throw error;
    }
  });
  await run(
    'NET-03',
    'ciphertext accepted by relay before device revocation, then fresh claim denied',
    async () => {
      const sent = await unit('unit-a', 'send', 4096);
      const prepared = await unit('unit-b', 'prepare-claim', sent.result.objectId);
      const revocation = await unit('unit-admin', 'revoke-recipient');
      const denied = await unit('unit-b', 'deny', sent.result.objectId);
      assert.equal(denied.result.denied, true);
      return {
        objectId: sent.result.objectId,
        prepared: prepared.result,
        revocation: revocation.result,
        denied: denied.result,
        boundary:
          'revocation response preceded fresh claim; previously released plaintext is not recalled',
      };
    },
  );
  await block(
    'NET-11',
    'No physical token, approved enrollment and representative endpoint sandbox available',
  );
  await block('NET-12', 'No external evaluator or independent reproduction has been supplied');
  return rows;
}
