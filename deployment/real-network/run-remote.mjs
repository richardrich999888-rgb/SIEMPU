// Runs only endpoint commands on explicitly authorised, already provisioned hosts.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import { campaign } from './campaign.mjs';
import { validateInventory } from './inventory.mjs';
import { snapshot } from '../../assurance/sag/package.mjs';
const exec = promisify(execFile),
  source = snapshot(resolve('.'));
const inventory = JSON.parse(readFileSync(process.argv[2])),
  out = resolve(process.argv[3] ?? 'artifacts/p0-047/remote');
validateInventory(inventory, source.commit);
mkdirSync(resolve(out, '..'), { recursive: true });
mkdirSync(out, { mode: 0o700 });
const quote = (s) => "'" + s.replaceAll("'", "'\\''") + "'";
async function remote(node, args) {
  const n = inventory.nodes[node];
  const command = 'cd ' + quote(n.root) + ' && ' + args.map(quote).join(' ');
  let stdout;
  try {
    ({ stdout } = await exec(
      'ssh',
      [
        '-o',
        'BatchMode=yes',
        '-o',
        'StrictHostKeyChecking=yes',
        '-o',
        'ConnectTimeout=5',
        '-l',
        n.user,
        n.host,
        command,
      ],
      { timeout: 30000, maxBuffer: 1024 * 1024 },
    ));
  } catch (e) {
    if (!e.stdout) throw new Error('SSH_OR_REMOTE_PROCESS_FAILED');
    stdout = e.stdout;
  }
  return JSON.parse(stdout.trim());
}
const records = {};
const roles = { 'unit-a': 'A', 'unit-b': 'E', 'unit-denied': 'E', 'unit-admin': 'B' };
async function invoke(role, op, arg) {
  const node = roles[role];
  return remote(node, [
    'node',
    'deployment/real-network/endpoint.mjs',
    inventory.nodes[node].state + '/' + role,
    op,
    ...(arg === undefined ? [] : [String(arg)]),
  ]);
}
const report = {
  source: { commit: source.commit, tree: source.tree },
  evidenceClass: 'INDEPENDENT_HOST_CANDIDATE',
  hostRecords: records,
  independentAdministration: 'NOT_ATTESTED',
  managedCompanion: 'NOT_EXERCISED',
  startedAt: new Date().toISOString(),
  rows: [],
};
const save = () => writeFileSync(out + '/campaign.json', JSON.stringify(report, null, 2) + '\n');
try {
  for (const node of Object.keys(inventory.nodes)) {
    records[node] = await remote(node, ['python3', 'deployment/real-network/preflight.py']);
    assert.equal(records[node].sourceCommit.stdout, source.commit);
    assert.equal(records[node].sourceTree.stdout, source.tree);
    assert.equal(records[node].sourceVerification.exit, 0, 'HOST_CLEAN_SOURCE_REQUIRED');
    assert.equal(JSON.parse(records[node].sourceVerification.stdout).tree, source.tree);
  }
  const boots = Object.values(records).map((r) => r.bootIdSha256);
  assert.ok(
    boots.every(Boolean) && new Set(boots).size === 6,
    'DISTINCT_KERNEL_BOOT_RECORDS_REQUIRED',
  );

  await campaign({
    unit: async (...a) => {
      const r = await invoke(...a);
      assert.equal(r.ok, true);
      return r;
    },
    failure: async (...a) => {
      const r = await invoke(...a);
      assert.equal(r.ok, false);
      return r;
    },
    record: async (r) => {
      report.rows.push(r);
      save();
    },
  });
} catch (e) {
  report.runnerFailure = String(e.message).slice(0, 200);
}
for (let n = 1; n <= 12; n++) {
  const id = 'NET-' + String(n).padStart(2, '0');
  if (!report.rows.some((r) => r.id === id))
    report.rows.push({
      id,
      outcome: 'BLOCKED',
      reason: 'Runner prerequisite failed; experiment not executed',
    });
}
report.finishedAt = new Date().toISOString();
report.overall =
  report.runnerFailure || report.rows.some((r) => r.outcome === 'FAIL')
    ? 'FAIL'
    : 'BLOCKED_REMAINING_CAMPAIGNS';
save();
console.log(JSON.stringify({ outcome: report.overall, report: out + '/campaign.json' }));
process.exitCode = report.overall === 'FAIL' ? 1 : 2;
