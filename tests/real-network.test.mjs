import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, symlinkSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { quantiles } from '../deployment/real-network/campaign.mjs';
import { validateInventory } from '../deployment/real-network/inventory.mjs';
import { provision, placement } from '../deployment/real-network/provision.mjs';

test('symlinked workspace uses canonical private state without weakening database guards', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'p047-private-path-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'real'), { mode: 0o700 });
  symlinkSync(join(root, 'real'), join(root, 'alias'));
  const state = join(root, 'alias', 'nodes');
  await provision(state, { mode: 'local-process' });
  for (const [node, roles] of Object.entries(placement)) {
    for (const role of roles) {
      const stat = statSync(join(state, node, role, 'state'));
      assert.equal(stat.mode & 0o777, 0o700);
      assert.equal(stat.uid, process.getuid());
    }
  }
  const result = spawnSync(
    process.execPath,
    ['deployment/real-network/endpoint.mjs', join(state, 'A/unit-a'), 'queue-status'],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(result.status, 0, result.stderr);
  const observation = JSON.parse(result.stdout.trim());
  assert.equal(observation.ok, true);
  assert.deepEqual(observation.result.entries, []);
});

test('benchmark suppresses tail estimates with insufficient samples and rejects invalid measurements', () => {
  assert.deepEqual(quantiles([]), { count: 0, p50Ms: null, p95Ms: null, p99Ms: null });
  assert.deepEqual(quantiles([30, 10, 20]), { count: 3, p50Ms: 20, p95Ms: null, p99Ms: null });
  assert.equal(quantiles(Array.from({ length: 20 }, (_, i) => i + 1)).p95Ms, 19);
  assert.equal(quantiles(Array.from({ length: 1000 }, (_, i) => i + 1)).p99Ms, 990);
  for (const value of [-1, NaN, Infinity])
    assert.throws(() => quantiles([value]), /INVALID_LATENCY_SAMPLE/);
});

test('remote inventory refuses unauthorised execution, source mismatch, duplicate hosts and shell/path injection', () => {
  const example = JSON.parse(readFileSync('deployment/real-network/inventory.example.json'));
  assert.throws(
    () => validateInventory(example, example.sourceCommit),
    /EXPLICIT_HOST_AUTHORISATION_REQUIRED/,
  );
  const valid = { ...example, authorisedSyntheticExperiment: true, sourceCommit: 'a'.repeat(40) };
  assert.equal(validateInventory(valid, valid.sourceCommit), valid);
  assert.throws(() => validateInventory(valid, 'b'.repeat(40)), /SOURCE_COMMIT_MISMATCH/);
  for (const [field, value] of [
    ['host', '-oProxyCommand=id'],
    ['host', '$(id)'],
    ['user', 'x;id'],
    ['root', '/tmp/../private'],
    ['state', '/tmp/x\nwhoami'],
  ]) {
    const bad = structuredClone(valid);
    bad.nodes.A[field] = value;
    assert.throws(() => validateInventory(bad, valid.sourceCommit));
  }
  const duplicate = structuredClone(valid);
  duplicate.nodes.E.host = duplicate.nodes.A.host.toUpperCase();
  assert.throws(
    () => validateInventory(duplicate, valid.sourceCommit),
    /DISTINCT_HOST_ADDRESSES_REQUIRED/,
  );
});
