import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { cpus, totalmem, platform, release } from 'node:os';
import assert from 'node:assert/strict';
const exec = promisify(execFile),
  out = resolve(process.argv[2] ?? 'artifacts/testbed'),
  compose = join(out, 'compose.json');
const profiles = JSON.parse(readFileSync(new URL('./profiles.json', import.meta.url)));
const rows = [],
  failures = [];
const report = {
  format: 'SIEPMU_TESTBED_EXECUTION_V1',
  startedAt: new Date().toISOString(),
  revision: process.env.GITHUB_SHA ?? 'LOCAL_UNBOUND',
  environment: {
    platform: platform(),
    kernel: release(),
    cpus: cpus().length,
    cpuModel: cpus()[0].model,
    memory: totalmem(),
    node: process.version,
  },
  synthetic: true,
  rows,
  failures,
  limitations: [
    'Docker zones share one host kernel; not an IAF deployment',
    'Provisional workload, no sponsor SLA',
    'Timing includes container command overhead',
    'No claim of hardware-backed identity, SAG grading, or TRL award',
  ],
};
mkdirSync(out, { recursive: true });
const save = () =>
  writeFileSync(join(out, 'measurements.json'), JSON.stringify(report, null, 2) + '\n');
const run = async (program, args, timeout = 30000) =>
  (await exec(program, args, { timeout, maxBuffer: 8 * 1024 * 1024 })).stdout.trim();
const docker = (args) => run('docker', ['compose', '-f', compose, ...args]);
const unit = async (role, command, arg) =>
  JSON.parse(
    (
      await docker([
        'exec',
        '-T',
        role,
        'node',
        'deployment/testbed/unit.mjs',
        command,
        ...(arg === undefined ? [] : [String(arg)]),
      ])
    )
      .split('\n')
      .at(-1),
  );
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const containerId = async (role) => await docker(['ps', '-q', role]);
async function network(profile, apply = true) {
  const id = await containerId('unit-a'),
    pid = await run('docker', ['inspect', '-f', '{{.State.Pid}}', id]);
  const ns = async (args) => run('sudo', ['nsenter', '-t', pid, '-n', ...args]);
  const links = JSON.parse(await ns(['ip', '-j', 'link', 'show'])).filter((l) => l.ifname !== 'lo');
  const targetLinks = profile === 'N8' ? links.filter((link) => link.ifname === 'eth1') : links;
  if (apply)
    for (const link of targetLinks) {
      await ns(['tc', 'qdisc', 'del', 'dev', link.ifname, 'root']).catch(() => {});
      if (profiles[profile].args.length)
        await ns([
          'tc',
          'qdisc',
          'replace',
          'dev',
          link.ifname,
          'root',
          'netem',
          ...profiles[profile].args,
        ]);
    }
  return {
    profile,
    requested: profiles[profile],
    interfaces: links.map((x) => x.ifname),
    observed: JSON.parse(await ns(['tc', '-s', '-j', 'qdisc', 'show'])),
  };
}
async function sample(label, fn, conditions = {}) {
  const start = performance.now(),
    row = { label, conditions, startedAt: Date.now() };
  try {
    row.result = await fn();
    row.outcome = 'PASS';
  } catch (error) {
    row.outcome = 'FAIL';
    row.error = error.message.slice(0, 1000);
    failures.push(label);
  }
  row.elapsedMs = performance.now() - start;
  rows.push(row);
  save();
  return row;
}
try {
  await docker([
    'up',
    '-d',
    'relay',
    'checkpoint',
    'collector',
    'control',
    'web',
    'unit-a',
    'unit-b',
    'unit-denied',
    'unit-admin',
  ]);
  for (const role of ['unit-a', 'unit-b', 'unit-denied', 'unit-admin']) {
    let ready = false;
    for (let i = 0; i < 40; i++) {
      try {
        const response = await docker([
          'exec',
          '-T',
          role,
          'node',
          '--input-type=module',
          '-e',
          "import {requestBytes} from './packages/transport/tls.mjs'; import {readFileSync} from 'node:fs'; const r=await requestBytes('https://web:8080/health/ready',{tls:{ca:readFileSync('/keys/ca.crt')}}); if(r.status!==200)process.exit(1);",
        ]);
        ready = response !== undefined;
        break;
      } catch {
        await pause(500);
      }
    }
    assert.equal(ready, true, 'Service readiness');
    await unit(role, 'init');
  }
  await docker(['up', '-d', 'adapter']);
  await sample('WAN egress blocked while enclave services remain reachable', async () => {
    const result = await docker([
      'exec',
      '-T',
      'unit-b',
      'node',
      '--input-type=module',
      '-e',
      "import {request} from 'node:https'; const req=request('https://1.1.1.1',{timeout:1500},()=>{console.error('EGRESS_UNEXPECTED');process.exit(1);});req.on('timeout',()=>req.destroy());req.on('error',()=>console.log(JSON.stringify({wanBlocked:true})));req.end();",
    ]);
    assert.equal(JSON.parse(result).wanBlocked, true);
    return unit('unit-b', 'control');
  });
  const repetitions = Number(process.env.SIEPMU_TESTBED_REPETITIONS ?? 3),
    count = Number(process.env.SIEPMU_TESTBED_MESSAGES ?? 5);
  assert.ok(repetitions >= 1 && repetitions <= 10 && count >= 1 && count <= 1000);
  for (const profile of ['N0', 'N1', 'N2', 'N3', 'N8']) {
    const conditions = await network(profile);
    for (let rep = 0; rep < repetitions; rep++)
      for (let i = 0; i < count; i++)
        await sample(
          `${profile}/exchange/${rep}/${i}`,
          async () => {
            const sent = await unit('unit-a', 'send', profile === 'N0' && i === 0 ? 262144 : 4096);
            const denied = await unit('unit-denied', 'deny', sent.objectId);
            assert.equal(denied.denied, true);
            const received = await unit('unit-b', 'receive', sent.objectId);
            assert.equal(received.sha256, sent.sha256);
            assert.equal(received.bytes, sent.bytes);
            return { sent, received, unauthorizedRejected: true };
          },
          conditions,
        );
    rows.push({
      label: profile + '/observed-final',
      outcome: 'OBSERVATION',
      conditions: await network(profile, false),
    });
    save();
  }
  await network('N0');
  for (const role of ['relay', 'control', 'checkpoint'])
    await sample('restart/' + role, async () => {
      await docker(['restart', role]);
      let ready = false;
      for (let i = 0; i < 40; i++) {
        try {
          await unit('unit-b', 'control');
          ready = true;
          break;
        } catch {
          await pause(250);
        }
      }
      assert.equal(ready, true);
      return { recovered: true };
    });
  for (let cycle = 0; cycle < 3; cycle++)
    await sample('intermittent/' + cycle, async () => {
      await network('N5');
      await assert.rejects(unit('unit-a', 'control'));
      await network('N0');
      return unit('unit-a', 'control');
    });
  const conditions = await network('N4');
  await sample(
    'offline queue, retained state, revocation and controlled reconnection',
    async () => {
      const queued = await unit('unit-a', 'queue', 4096);
      await assert.rejects(unit('unit-a', 'submit'));
      const outageMs = process.env.SIEPMU_TESTBED_LONG === '1' ? 1800000 : 5000;
      const start = performance.now();
      for (let elapsed = 0; elapsed < outageMs; elapsed += 10000)
        await pause(Math.min(10000, outageMs - elapsed));
      await unit('unit-admin', 'revoke-sender');
      await network('N0');
      await assert.rejects(unit('unit-a', 'submit'));
      const denied = await unit('unit-b', 'deny', queued.objectId);
      assert.equal(denied.denied, true);
      return {
        queued: queued.objectId,
        observedOutageMs: performance.now() - start,
        revokedDeviceRejected: true,
        original30MinuteMatrixTargetExecuted: outageMs === 1800000,
      };
    },
    conditions,
  );
  report.resources = {
    dockerStats: await run('docker', ['stats', '--no-stream', '--format', '{{json .}}']),
    controlDiskBytes: await docker([
      'exec',
      '-T',
      'control',
      'node',
      '--input-type=module',
      '-e',
      "import{statSync}from'node:fs';console.log(JSON.stringify({database:statSync('/state/control.sqlite').size,wal:statSync('/state/control.sqlite-wal').size}));",
    ]),
  };
} catch (error) {
  failures.push('runner');
  report.error = error.message.slice(0, 2000);
} finally {
  await network('N0').catch(() => {});
  report.finishedAt = new Date().toISOString();
  const durations = rows
    .filter((r) => r.outcome === 'PASS' && r.label.includes('/exchange/'))
    .map((r) => r.elapsedMs)
    .sort((a, b) => a - b);
  const percentile = (q) =>
    durations[Math.min(durations.length - 1, Math.ceil(durations.length * q) - 1)] ?? null;
  report.summary = {
    attempts: rows.filter((r) => ['PASS', 'FAIL'].includes(r.outcome)).length,
    failed: failures.length,
    successfulExchanges: durations.length,
    p50Ms: percentile(0.5),
    p95Ms: durations.length >= 20 ? percentile(0.95) : null,
    p99Ms: durations.length >= 1000 ? percentile(0.99) : null,
    comparableSponsorSLA: false,
  };
  save();
  await docker(['down', '--remove-orphans']).catch(() => {});
}
// Failure rows are echoed to the job log as well: the uploaded artefact can be unreachable
// for reviewers, and a summary count alone cannot identify the failing profile or cause.
const MAX_FAILURE_ROWS = 20;
for (const row of rows.filter((r) => r.outcome === 'FAIL').slice(0, MAX_FAILURE_ROWS))
  console.log(
    JSON.stringify({
      failed: row.label,
      error: row.error,
      elapsedMs: Math.round(row.elapsedMs),
      profile: row.conditions?.profile ?? null,
    }),
  );
if (report.error) console.log(JSON.stringify({ runnerError: report.error }));
console.log(
  JSON.stringify({
    status: failures.length ? 'FAIL' : 'PASS',
    summary: report.summary,
    report: join(out, 'measurements.json'),
  }),
);
if (failures.length) process.exitCode = 1;
