// D-T5-01 re-test on the three-namespace relevant environment after the incremental-custody fix
// (ADR-014). Pins the frozen run docs/trl5/evidence/1a0218d byte for byte and checks the recorded
// outcome against the pre-fix run 1348b86. The TRL decision is unchanged (provisional TRL 4).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { root } from './helpers/fixture.mjs';

const AFTER = join(root, 'docs/trl5/evidence/1a0218d');
const BEFORE = join(root, 'docs/trl5/evidence/1348b86');
const json = (dir, file) => JSON.parse(readFileSync(join(dir, file), 'utf8'));

test('frozen post-fix TRL 5 run matches its manifest byte for byte', () => {
  const manifest = json(AFTER, 'evidence-manifest.json');
  assert.equal(manifest.source.commit, '1a0218db8684e363f7dc3000b5f1bce396571f22');
  assert.ok(Object.keys(manifest.files).length > 0);
  for (const [file, digest] of Object.entries(manifest.files))
    assert.equal(
      createHash('sha256')
        .update(readFileSync(join(AFTER, file)))
        .digest('hex'),
      digest,
      file,
    );
});

test('post-fix run passes the full declared matrix and removes the custody bottleneck', () => {
  const results = json(AFTER, 'test-results.json');
  assert.equal(results.outcome, 'PASS');
  assert.equal(results.passed, 33);
  assert.equal(results.total, 33);
  const after = json(AFTER, 'metrics.json').load;
  const before = json(BEFORE, 'metrics.json').load;
  // Same declared workload in both runs.
  for (const k of ['senders', 'workersPerSender', 'payloadBytes'])
    assert.equal(after[k], before[k], k);
  assert.equal(after.receivePhase.mismatched + after.receivePhase.failed, 0);
  // Recorded values, not thresholds chosen after the fact: 1.56 -> 5.93 exchanges/s,
  // custodian average CPU 72.3 % -> 17.1 %.
  assert.equal(before.sendPhase.exchangesPerSecond, 1.56);
  assert.equal(after.sendPhase.exchangesPerSecond, 5.93);
  assert.equal(before.hostB.processes.checkpoint.avgCpuPercent, 72.3);
  assert.equal(after.hostB.processes.checkpoint.avgCpuPercent, 17.1);
});
