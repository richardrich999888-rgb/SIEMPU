// TRL 5 advancement validation on the three-host relevant environment.
//
// Executes the matrix declared in docs/trl5/ACCEPTANCE_MATRIX.md (committed before the first run)
// on deployment/relevant-env: Host A (sender unit), Host B (platform), Host C (recipient unit,
// document system + adapter, verifier) in separate network namespaces on one kernel. Every
// criterion is recorded PASS/FAIL with its observation; a failure never stops later tests.
//
// Requires root and iproute2 (namespaces, veth, tc). Kernel netem is used when present; otherwise
// latency/jitter come from deployment/relevant-env/wan-relay.mjs and loss is not emulated.
// Output: artifacts/trl5/{test-results,metrics,environment-inventory,evidence-manifest}.json and
// logs/. Synthetic, unclassified data only. Reset: remove artifacts/trl5.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { cpus, totalmem, tmpdir, release } from 'node:os';
import { join, resolve, relative } from 'node:path';
import { provision } from '../tests/helpers/fixture.mjs';
import * as topology from '../deployment/relevant-env/topology.mjs';
import {
  PORTS,
  GATEWAY_URL,
  agent,
  createPlatform,
  distributeProfiles,
  installIdentities,
  provisionEnvironment,
  startInHost,
  stopChild,
  publicDescriptor,
} from '../deployment/relevant-env/platform.mjs';
import { syntheticBytes } from '../deployment/relevant-env/payload.mjs';
import { generateLabPKI } from '../deployment/secure/lab-pki.mjs';
import { buildOfflineBundle, installOfflineBundle } from '../packages/release/offline.mjs';
import { pair } from '../tests/helpers/client.mjs';
import { sourceDigest } from './audit-claims.mjs';
import { sourceRevision } from './lib/demo-report.mjs';

const OUT = resolve(process.env.SIEPMU_TRL5_OUT || 'artifacts/trl5');
const RUST_VERIFIER = resolve('native/target/release/siepmu-evidence-verify');
const LOAD_SECONDS = Number(process.env.SIEPMU_TRL5_LOAD_SECONDS ?? 30);
// Debug aid: run only the listed test-ID prefixes. A filtered run is reported as PARTIAL, never PASS.
const ONLY = process.env.SIEPMU_TRL5_ONLY ? process.env.SIEPMU_TRL5_ONLY.split(',') : null;
const RACE_TRIALS = 20;
const RACE_STEP_MS = 50;
const OUTAGE_SECONDS = 20;
const RECOVERY_LIMIT_MS = 10000;
const TELEMETRY_LIMIT_MS = 10000;
const CANARY = 'SYNTHETIC_TRL5_DOCUMENT_CANARY';
const MISSION = 'DEMO-MISSION';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/** Nearest-rank percentile; null for an empty sample. */
export function percentile(values, p) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(1, Math.ceil((p / 100) * sorted.length)) - 1];
}
/** Summary statistics over a latency sample (ms). */
export const summary = (values) => ({
  n: values.length,
  p50: percentile(values, 50),
  p95: percentile(values, 95),
  p99: values.length >= 100 ? percentile(values, 99) : null,
  max: values.length ? Math.max(...values) : null,
});

/** Impairment profiles (P0-P4 match the declared matrix; loss profiles only with kernel netem). */
export const PROFILES = Object.freeze([
  { id: 'P0', label: 'baseline', delayMs: 0, jitterMs: 0, rateKbit: null },
  { id: 'P1', label: '100 ms ± 20 ms', delayMs: 100, jitterMs: 20, rateKbit: null },
  { id: 'P2', label: '300 ms ± 100 ms', delayMs: 300, jitterMs: 100, rateKbit: null },
  { id: 'P3', label: '1 Mbit/s', delayMs: 0, jitterMs: 0, rateKbit: 1000 },
  { id: 'P4', label: '200 ms ± 50 ms + 2 Mbit/s', delayMs: 200, jitterMs: 50, rateKbit: 2000 },
]);
export const LOSS_PROFILES = Object.freeze([
  { id: 'L1', label: '50 ms, 1 % loss', netem: ['delay', '50ms', 'loss', '1%'] },
  { id: 'L2', label: '100 ms ± 20 ms, 3 % loss', netem: ['delay', '100ms', '20ms', 'loss', '3%'] },
]);

/** Milliseconds until the next 30-second TOTP step boundary (+1 s margin). */
const untilNextTotpStep = () => 31000 - (Date.now() % 30000);

/** Searches every regular file under `dir` for each needle; returns the files that contain one. */
function filesContaining(dir, needles) {
  const hits = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) {
        const content = readFileSync(p);
        if (needles.some((n) => content.includes(n))) hits.push(relative(dir, p));
      }
    }
  };
  walk(dir);
  return hits;
}

/** CPU seconds (user+system) and RSS bytes of a process, from /proc. */
function procSample(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    const ticks = Number(fields[11]) + Number(fields[12]);
    const rssKb = Number(
      /VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))?.[1] ?? 0,
    );
    return { cpuSeconds: ticks / 100, rssBytes: rssKb * 1024 };
  } catch {
    return null;
  }
}

/** Total size of SQLite files (incl. WAL) under a directory. */
function databaseBytes(dir) {
  let total = 0;
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.sqlite(-wal|-shm)?$/.test(e.name)) total += statSync(p).size;
    }
  };
  walk(dir);
  return total;
}

function runtimeVersions() {
  const tryRun = (cmd, args) => {
    try {
      return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
        .trim()
        .split('\n')[0];
    } catch {
      return null;
    }
  };
  return {
    node: process.version,
    openssl: process.versions.openssl,
    rustc: tryRun('rustc', ['--version']),
    iproute2: tryRun('ip', ['-V']),
    kernel: release(),
  };
}

export async function runTrl5Validation() {
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(join(OUT, 'logs'), { recursive: true });
  const results = [];
  const metrics = { impairment: [], outage: null, load: null, race: null, timings: {} };
  const capability = topology.probe();
  const startedAt = new Date().toISOString();
  const record = (id, requirement, criterion, pass, observed, measurements = null) => {
    results.push({
      id,
      requirement,
      criterion,
      outcome: pass ? 'PASS' : 'FAIL',
      observed,
      measurements,
    });
    console.log(`${pass ? 'PASS' : 'FAIL'} ${id}: ${criterion}`);
  };
  const check = async (id, requirement, criterion, fn) => {
    if (ONLY && !ONLY.some((prefix) => id.startsWith(prefix))) return;
    try {
      const r = await fn();
      record(id, requirement, criterion, r.pass, r.observed, r.measurements ?? null);
    } catch (error) {
      record(id, requirement, criterion, false, { error: error.message });
    }
  };
  if (!capability.namespaces) {
    record('ENV', '-', 'Network namespaces available', false, capability);
    return finish({ results, metrics, capability, startedAt, environment: null });
  }

  const work = mkdtempSync(join(tmpdir(), 'siepmu-trl5-'));
  const logs = join(OUT, 'logs');
  const f = await provision();
  const P = f.profiles;
  const placement = { a: ['alice'], b: ['admin'], c: ['bob', 'bravo', 'eve'] };
  const { lab, env, states } = await provisionEnvironment({
    work,
    authorityDir: f.dir,
    provisioned: f.provisioned,
    profiles: P,
    placement,
  });
  installIdentities(states.b, lab.pki.dir, ['operator-client', 'control-client']);
  installIdentities(states.c, lab.pki.dir, ['adapter', 'adapter-client', 'unit-b', 'unit-denied']);
  const wanProfile = join(work, 'wan-profile.json');
  const setRelay = (delayMs, jitterMs) =>
    writeFileSync(wanProfile, JSON.stringify({ delayMs, jitterMs, seed: 69 }));
  setRelay(0, 0);
  topology.apply();
  const platform = createPlatform(env, logs);
  let relay, adapter;
  const A = (cmd, args, t) => agent(states, 'a', cmd, args, t);
  const B = (cmd, args, t) => agent(states, 'b', cmd, args, t);
  const C = (cmd, args, t) => agent(states, 'c', cmd, args, t);
  const exportEvidence = async (name) => {
    await B('exportEvidence', { user: 'admin', file: name });
    return JSON.parse(readFileSync(join(states.b, name), 'utf8'));
  };
  const objectEvents = (evidence, objectId, type) =>
    evidence.records.filter(
      (r) => r.payload.objectId === objectId && (!type || r.payload.eventType === type),
    );
  const setPolicy = (from, to, allow) =>
    B('admin', {
      user: 'admin',
      method: 'PUT',
      path: '/api/admin/policies',
      body: { fromUnit: from, toUnit: to, missionId: MISSION, allow },
    });
  const unitA = P.alice.unitId;
  const unitB = P.bob.unitId;
  const environment = {
    topology: { hosts: topology.HOSTS, links: topology.LINKS },
    isolation:
      'Linux network namespaces on one kernel (shared CPU, clock and file system); per-host state directories; not separate machines or VMs',
    kernelCapabilities: capability,
    impairment: capability.netem
      ? 'kernel netem (delay, jitter, loss) and TBF on the A-B veth pair'
      : 'kernel TBF (bandwidth) and link down (outage); userspace relay for delay/jitter; loss NOT emulated',
  };

  try {
    platform.startAll();
    relay = startInHost(
      'a',
      [
        'deployment/relevant-env/wan-relay.mjs',
        '127.0.0.1',
        String(PORTS.web),
        topology.HOSTS.a.gatewayAddress,
        String(PORTS.web),
        wanProfile,
      ],
      process.env,
      join(logs, 'wan-relay.log'),
    );
    for (const [h, run] of [
      ['b', B],
      ['a', A],
      ['c', C],
    ]) {
      const r = await run('ready');
      if (!r.ok) throw new Error(`Host ${h} cannot reach the gateway: ${JSON.stringify(r)}`);
    }

    // ---- T1 secure information exchange ----------------------------------------------------
    await check('T1.1', 'R5', 'MFA login on each host', async () => {
      const r = {
        alice: await A('login', { user: 'alice' }),
        admin: await B('login', { user: 'admin' }),
      };
      for (const u of ['bob', 'bravo', 'eve']) r[u] = await C('login', { user: u });
      return { pass: Object.values(r).every((x) => x.ok), observed: r };
    });

    // Additional synthetic users: R2/R3 recipients, a document-system unit and load users.
    const enrolled = await B(
      'enroll',
      {
        user: 'admin',
        users: [
          { username: 'rcp2', unitId: unitB },
          { username: 'rcp3', unitId: unitB },
          { username: 'dmsc', unitId: unitB },
          ...[1, 2, 3, 4].map((i) => ({ username: `snd${i}`, unitId: unitA })),
          ...[1, 2, 3, 4].map((i) => ({ username: `lrx${i}`, unitId: unitB })),
        ],
      },
      300000,
    );
    if (!enrolled.ok)
      throw new Error('Enrolment failed: ' + JSON.stringify(enrolled).slice(0, 400));
    for (const { profile, token } of enrolled.profiles) {
      P[profile.username] = profile;
      const host = /^snd\d$/.test(profile.username) ? 'a' : 'c';
      mkdirSync(join(states[host], 'sessions'), { recursive: true });
      writeFileSync(
        join(states[host], 'sessions', `${profile.username}.json`),
        JSON.stringify({ token }),
        { mode: 0o600 },
      );
    }
    distributeProfiles(states, P, {
      a: ['snd1', 'snd2', 'snd3', 'snd4'],
      c: ['rcp2', 'rcp3', 'dmsc', 'lrx1', 'lrx2', 'lrx3', 'lrx4'],
    });
    await setPolicy(unitB, unitA, true); // documents flow from Unit B (Host C) to Unit A (Host A)

    await check('T1.2', 'R5', 'Wrong one-time password refused (401)', async () => {
      const r = await A('loginWrongOtp', { user: 'alice' });
      return { pass: r.status === 401, observed: r };
    });

    await check('T1.3', 'R6', 'Client trusting another CA cannot connect', async () => {
      const other = generateLabPKI(join(work, 'other-pki'));
      cpSync(join(other.dir, 'ca.crt'), join(states.a, 'wrong-ca.crt'));
      const r = await A('wrongTrustRoot', { caPath: join(states.a, 'wrong-ca.crt') });
      return { pass: !r.ok, observed: r };
    });

    const exchanges = {};
    await check(
      'T1.4',
      'R1, R2, R5',
      'A→C exchange, 64 KiB and 512 KiB, exact bytes and signed receipts',
      async () => {
        const out = {};
        for (const [bytes, seed] of [
          [65536, 11],
          [524288, 12],
        ]) {
          const s = await A('send', { user: 'alice', to: 'bob', bytes, seed });
          const r = s.ok
            ? await C('receive', { user: 'bob', objectId: s.objectId, from: 'alice' })
            : null;
          out[bytes] = { send: s, receive: r, match: !!r?.ok && r.sha256 === s.sha256 };
          exchanges[bytes] = s.objectId;
        }
        const pass = Object.values(out).every(
          (x) => x.match && x.receive.releaseEventId && x.receive.ackEventId,
        );
        return { pass, observed: out };
      },
    );

    await check('T1.5', 'R7', 'Unauthorised party on Host C cannot obtain the object', async () => {
      const s = await A('send', { user: 'alice', to: 'bob', bytes: 4096, seed: 13 });
      const r = await C('receive', { user: 'eve', objectId: s.objectId, from: 'alice' });
      return { pass: !r.ok && [403, 404, 409].includes(r.status), observed: r };
    });

    await check('T1.6', 'R5, R10', 'No plaintext window in Host B storage', async () => {
      const needles = [
        Buffer.from(syntheticBytes(65536, 11).subarray(1000, 1064)),
        Buffer.from(syntheticBytes(524288, 12).subarray(300000, 300064)),
      ];
      const hits = filesContaining(f.dir, needles);
      return {
        pass: hits.length === 0,
        observed: { filesScanned: 'all files under Host B state', hits },
      };
    });

    // ---- T2 revocation and release ---------------------------------------------------------
    await check(
      'T2.1',
      'R7',
      'Policy withdrawn before issuance: claim refused with signed HELD decision',
      async () => {
        const s = await A('send', { user: 'alice', to: 'bob', bytes: 4096, seed: 21 });
        await setPolicy(unitA, unitB, false);
        const r = await C('receive', { user: 'bob', objectId: s.objectId, from: 'alice' });
        await setPolicy(unitA, unitB, true);
        const ev = await exportEvidence('evidence-t21.json');
        const decisions = objectEvents(ev, s.objectId).map((x) => [
          x.payload.eventType,
          x.payload.decision,
        ]);
        const held = decisions.some(([, d]) => d && d !== 'RELEASED' && d !== 'PENDING');
        return { pass: !r.ok && r.status === 409 && held, observed: { claim: r, decisions } };
      },
    );

    await check(
      'T2.2',
      'R7, R2',
      'Revocation during disconnection: revoked recipient never released, eligible recipient delivered',
      async () => {
        await A('grant', { user: 'alice' });
        topology.setWanLink(false);
        const during = await A('send', { user: 'alice', to: 'rcp3', bytes: 1024, seed: 22 }, 30000);
        const q2 = await A('queue', {
          user: 'alice',
          to: 'rcp2',
          bytes: 32768,
          seed: 23,
          name: 'q2',
        });
        const q3 = await A('queue', {
          user: 'alice',
          to: 'rcp3',
          bytes: 32768,
          seed: 24,
          name: 'q3',
        });
        const revoke = await B('admin', {
          user: 'admin',
          method: 'PATCH',
          path: `/api/admin/users/${P.rcp2.userId}`,
          body: { active: false },
        });
        topology.setWanLink(true);
        const sub2 = await A('submitQueued', { user: 'alice', name: 'q2' });
        const sub3 = await A('submitQueued', { user: 'alice', name: 'q3' });
        const r2 = await C('receive', { user: 'rcp2', objectId: q2.objectId, from: 'alice' });
        const r3 = await C('receive', { user: 'rcp3', objectId: q3.objectId, from: 'alice' });
        const ev = await exportEvidence('evidence-t22.json');
        const r2Issued = objectEvents(ev, q2.objectId, 'RELEASE_ISSUED').length;
        const pass =
          !during.ok &&
          revoke.ok &&
          sub2.ok &&
          sub3.ok &&
          !r2.ok &&
          r2Issued === 0 &&
          r3.ok &&
          r3.sha256 === q3.sha256;
        return {
          pass,
          observed: {
            sendDuringOutage: during,
            revoke: revoke.status,
            r2,
            r2Issued,
            r3: { ok: r3.ok, match: r3.sha256 === q3.sha256 },
          },
        };
      },
    );

    await check(
      'T2.3',
      'R7',
      `Concurrent release vs policy withdrawal (${RACE_TRIALS} trials): no issuance at a withdrawn epoch`,
      async () => {
        const before = (await exportEvidence('evidence-pre-race.json')).records.length;
        const outcomes = [];
        for (let i = 0; i < RACE_TRIALS; i++) {
          const s = await A('send', { user: 'alice', to: 'bob', bytes: 2048, seed: 100 + i });
          // Each request is a fresh agent process, and the claim does more work than the policy
          // write, so the withdrawal is delayed by a varying offset: small offsets let the
          // withdrawal commit first, large ones let the issuance commit first. Both orders occur.
          const withdrawDelayMs = (i % 5) * RACE_STEP_MS;
          const [claim] = await Promise.all([
            C('receive', { user: 'bob', objectId: s.objectId, from: 'alice' }),
            sleep(withdrawDelayMs).then(() => setPolicy(unitA, unitB, false)),
          ]);
          await setPolicy(unitA, unitB, true);
          outcomes.push({ withdrawDelayMs, released: claim.ok, status: claim.status ?? null });
        }
        const ev = await exportEvidence('evidence-race.json');
        const window = ev.records.slice(before);
        const changes = window.filter((r) => r.payload.eventType === 'POLICY_CHANGED');
        // Within the race window only this test changes authority, alternating withdraw, restore.
        // A change record carries the epoch it created, so the withdrawn epochs are those of the
        // even-indexed records.
        const withdrawnEpochs = new Set(
          changes.filter((_, k) => k % 2 === 0).map((r) => r.payload.epoch),
        );
        const violations = window.filter(
          (r) => r.payload.eventType === 'RELEASE_ISSUED' && withdrawnEpochs.has(r.payload.epoch),
        );
        metrics.race = {
          trials: RACE_TRIALS,
          released: outcomes.filter((o) => o.released).length,
          refused: outcomes.filter((o) => !o.released).length,
          authorityChanges: changes.length,
          violations: violations.length,
          outcomes,
        };
        return {
          pass: violations.length === 0 && changes.length === 2 * RACE_TRIALS,
          observed: metrics.race,
        };
      },
    );

    await check('T2.4', 'R7', 'Claim with a stale epoch is refused', async () => {
      const e = await C('epoch', { user: 'bob' });
      const s = await A('send', { user: 'alice', to: 'bob', bytes: 2048, seed: 31 });
      await setPolicy(unitA, unitB, true); // advances the epoch without changing the decision
      const stale = await C('claimStale', { user: 'bob', objectId: s.objectId, epoch: e.epoch });
      const fresh = await C('receive', { user: 'bob', objectId: s.objectId, from: 'alice' });
      return {
        pass: !stale.ok && fresh.ok,
        observed: { staleEpoch: e.epoch, stale, freshAfter: fresh.ok },
      };
    });

    await check(
      'T2.5',
      'R2',
      'Duplicate submission returns the same object; one SUBMITTED record',
      async () => {
        await A('grant', { user: 'alice' });
        await A('queue', { user: 'alice', to: 'bob', bytes: 2048, seed: 32, name: 'dup' });
        const first = await A('submitQueued', { user: 'alice', name: 'dup' });
        const second = await A('submitQueued', { user: 'alice', name: 'dup' });
        const ev = await exportEvidence('evidence-t25.json');
        const submitted = objectEvents(ev, first.objectId, 'SUBMITTED').length;
        return {
          pass: first.ok && second.ok && first.objectId === second.objectId && submitted === 1,
          observed: { first, second, submitted },
        };
      },
    );

    // ---- T3 network impairment -------------------------------------------------------------
    const impair = (p) => {
      if (p.netem) {
        setRelay(0, 0);
        topology.setWanNetem(p.netem);
      } else if (capability.netem && (p.delayMs || p.rateKbit)) {
        setRelay(0, 0);
        const args = [];
        if (p.delayMs) args.push('delay', `${p.delayMs}ms`, `${p.jitterMs}ms`);
        if (p.rateKbit) args.push('rate', `${p.rateKbit}kbit`);
        topology.setWanNetem(args);
      } else {
        if (capability.netem) topology.setWanNetem(null);
        setRelay(p.delayMs ?? 0, p.jitterMs ?? 0);
        topology.setWanBandwidth(p.rateKbit ?? null);
      }
      return execFileSync(
        'ip',
        ['netns', 'exec', topology.HOSTS.a.ns, 'tc', 'qdisc', 'show', 'dev', 'sa0'],
        { encoding: 'utf8' },
      ).trim();
    };
    const profiles = [...PROFILES, ...(capability.netem ? LOSS_PROFILES : [])];
    for (const [k, p] of profiles.entries()) {
      await check(
        // P0–P4 are T3.1–T3.5 (matrix); loss profiles L1/L2 (netem kernels only) are T3.L1/T3.L2.
        p.id.startsWith('L') ? `T3.${p.id}` : `T3.${k + 1}`,
        'R2, R3',
        `Profile ${p.id} (${p.label}): 5 exchanges of 64 KiB, all delivered intact`,
        async () => {
          const qdisc = impair(p);
          const rtt = [];
          for (let i = 0; i < 3; i++) {
            const t0 = performance.now();
            const e = await A('epoch', { user: 'alice' });
            if (e.ok) rtt.push(Math.round(performance.now() - t0));
          }
          const exchangeMs = [];
          const failures = [];
          let intact = 0;
          for (let i = 0; i < 5; i++) {
            const t0 = performance.now();
            const s = await A(
              'send',
              { user: 'alice', to: 'bob', bytes: 65536, seed: 200 + k * 10 + i },
              180000,
            );
            const r = s.ok
              ? await C('receive', { user: 'bob', objectId: s.objectId, from: 'alice' }, 180000)
              : { ok: false };
            if (r.ok && r.sha256 === s.sha256) intact++;
            else failures.push({ i, send: s.ok ? 'ok' : s, receive: r.ok ? 'digest' : r });
            exchangeMs.push(Math.round(performance.now() - t0));
          }
          const m = {
            profile: p,
            appliedQdiscOnHostA: qdisc,
            relayProfile: capability.netem
              ? 'none (kernel netem)'
              : JSON.parse(readFileSync(wanProfile, 'utf8')),
            controlRequestMs: summary(rtt),
            exchangeMs: summary(exchangeMs),
            intact,
          };
          metrics.impairment.push(m);
          return { pass: intact === 5, observed: { intact, of: 5, failures }, measurements: m };
        },
      );
    }
    impair(PROFILES[0]);

    await check(
      'T3.6',
      'R2',
      `Link outage ${OUTAGE_SECONDS} s: requests fail, recovery ≤ ${RECOVERY_LIMIT_MS / 1000} s, queued object delivered`,
      async () => {
        await A('grant', { user: 'alice' });
        topology.setWanLink(false);
        const downAt = Date.now();
        const during = await A('epoch', { user: 'alice' }, 30000);
        const queued = await A('queue', {
          user: 'alice',
          to: 'bob',
          bytes: 65536,
          seed: 300,
          name: 'outage',
        });
        await sleep(Math.max(0, OUTAGE_SECONDS * 1000 - (Date.now() - downAt)));
        topology.setWanLink(true);
        const upAt = Date.now();
        let recoveredAt = null;
        while (Date.now() - upAt < 60000) {
          const r = await A('epoch', { user: 'alice' }, 15000);
          if (r.ok) {
            recoveredAt = Date.now();
            break;
          }
          await sleep(200);
        }
        const sub = await A('submitQueued', { user: 'alice', name: 'outage' });
        const rec = sub.ok
          ? await C('receive', { user: 'bob', objectId: sub.objectId, from: 'alice' })
          : { ok: false };
        metrics.outage = {
          outageMs: upAt - downAt,
          recoveryMs: recoveredAt ? recoveredAt - upAt : null,
          requestDuringOutage: during,
          queuedDelivered: rec.ok && rec.sha256 === queued.sha256,
        };
        return {
          pass:
            !during.ok &&
            recoveredAt !== null &&
            recoveredAt - upAt <= RECOVERY_LIMIT_MS &&
            metrics.outage.queuedDelivered,
          observed: metrics.outage,
        };
      },
    );

    // ---- T4 existing-system interoperability -----------------------------------------------
    const adapterUrl = `https://127.0.0.1:${PORTS.adapter}`;
    const adapterEnv = {
      ...process.env,
      SIEPMU_PROFILE: 'isolated',
      SIEPMU_TLS_CA: join(states.c, 'ca.crt'),
      SIEPMU_PLATFORM_URL: GATEWAY_URL,
      SIEPMU_ADAPTER_PORT: String(PORTS.adapter),
      SIEPMU_ADAPTER_PROFILE: join(states.c, 'adapter-profile.json'),
      SIEPMU_ADAPTER_DESTINATIONS: join(states.c, 'adapter-destinations.json'),
      SIEPMU_ADAPTER_DB: join(states.c, 'adapter.sqlite'),
      SIEPMU_AUTHORITY_PUBLIC_KEY: join(states.c, 'authority-public.json'),
      SIEPMU_ADAPTER_TLS_CERT: join(states.c, 'tls', 'adapter.crt'),
      SIEPMU_ADAPTER_TLS_KEY: join(states.c, 'tls', 'adapter.key'),
      SIEPMU_ADAPTER_TLS_CLIENT_PINS: lab.pki.pin('adapter-client'),
      SIEPMU_ADAPTER_CLIENT_TLS_CERT: join(states.c, 'tls', 'unit-b.crt'),
      SIEPMU_ADAPTER_CLIENT_TLS_KEY: join(states.c, 'tls', 'unit-b.key'),
    };
    writeFileSync(adapterEnv.SIEPMU_ADAPTER_PROFILE, JSON.stringify(P.dmsc), { mode: 0o600 });
    const { signingPublicKey: _s, username: _u, ...aliceDestination } = publicDescriptor(P.alice);
    writeFileSync(adapterEnv.SIEPMU_ADAPTER_DESTINATIONS, JSON.stringify([aliceDestination]), {
      mode: 0o600,
    });
    const startAdapter = async () => {
      await sleep(untilNextTotpStep()); // the adapter logs in itself; never replay a TOTP step
      adapter = startInHost(
        'c',
        ['services/integration/server.mjs'],
        adapterEnv,
        join(logs, 'adapter.log'),
      );
      for (let i = 0; i < 100; i++) {
        if ((await C('external', { host: '127.0.0.1', port: PORTS.adapter })).ok) return true;
        await sleep(100);
      }
      return false;
    };
    const doc = (overrides = {}) => ({
      version: 1,
      documentId: crypto.randomUUID(),
      reference: 'SYN/TRL5/2026/001',
      title: 'Synthetic stores transfer note',
      marking: 'SYNTHETIC-UNCLASSIFIED',
      body: `${CANARY}: transfer two synthetic pallets.`,
      originatorUserId: P.dmsc.userId,
      destinationUserId: P.alice.userId,
      ...overrides,
    });
    const d1 = doc();
    let d1Object;
    await check(
      'T4.1',
      'R8',
      'Document from Host C system delivered to Host A unit with signed acknowledgement',
      async () => {
        if (!(await startAdapter())) return { pass: false, observed: { adapter: 'did not start' } };
        const s = await C('dmsSubmit', { document: d1, identity: 'adapter-client', adapterUrl });
        d1Object = s.objectId;
        const r = await A('dmsReceive', { user: 'alice', senders: ['dmsc'] });
        const st = await C('dmsStatus', {
          documentId: d1.documentId,
          identity: 'adapter-client',
          adapterUrl,
        });
        const delivered = r.outcomes?.find((o) => o.objectId === s.objectId);
        return {
          pass:
            s.ok &&
            delivered?.outcome === 'DELIVERED' &&
            !!delivered.ackEventId &&
            st.state === 'DELIVERED',
          observed: { submit: s, delivered, status: st },
        };
      },
    );
    await check(
      'T4.2',
      'R8, R2',
      'Duplicate document returns the same object; one SUBMITTED record',
      async () => {
        const again = await C('dmsSubmit', {
          document: d1,
          identity: 'adapter-client',
          adapterUrl,
        });
        const ev = await exportEvidence('evidence-t42.json');
        const n = objectEvents(ev, d1Object, 'SUBMITTED').length;
        return {
          pass: again.ok && again.objectId === d1Object && n === 1,
          observed: { again, submitted: n },
        };
      },
    );
    await check(
      'T4.3',
      'R8',
      'Altered replay under the same request ID refused (409)',
      async () => {
        const r = await C('dmsReplayAltered', {
          documentId: d1.documentId,
          identity: 'adapter-client',
          adapterUrl,
        });
        return { pass: r.status === 409, observed: r };
      },
    );
    await check('T4.4', 'R8, R7', 'Document for an unauthorised destination refused', async () => {
      const r = await C('dmsSubmit', {
        document: doc({ destinationUserId: P.bob.userId }),
        identity: 'adapter-client',
        adapterUrl,
      });
      return { pass: !r.ok, observed: r };
    });
    await check(
      'T4.5',
      'R8, R6',
      'Source with an unpinned client certificate refused',
      async () => {
        const r = await C('dmsSubmit', { document: doc(), identity: 'unit-denied', adapterUrl });
        return { pass: !r.ok && r.code === 'SOURCE_NOT_AUTHENTICATED', observed: r };
      },
    );
    await check(
      'T4.6',
      'R8, R2',
      'Adapter interruption: refused while down; after restart delivered exactly once',
      async () => {
        await stopChild(adapter);
        const d2 = doc();
        const down = await C('dmsSubmit', { document: d2, identity: 'adapter-client', adapterUrl });
        const restarted = await startAdapter();
        const up = await C('dmsSubmit', { document: d2, identity: 'adapter-client', adapterUrl });
        const r = await A('dmsReceive', { user: 'alice', senders: ['dmsc'] });
        const ev = await exportEvidence('evidence-t46.json');
        const n = up.ok ? objectEvents(ev, up.objectId, 'SUBMITTED').length : 0;
        const delivered = r.outcomes?.filter(
          (o) => o.objectId === up.objectId && o.outcome === 'DELIVERED',
        ).length;
        return {
          pass: !down.ok && restarted && up.ok && n === 1 && delivered === 1,
          observed: { down, restarted, up, submitted: n, delivered },
        };
      },
    );

    // ---- T5 security monitoring ------------------------------------------------------------
    await check(
      'T5.1',
      'R6',
      `Security events reach the independent collector within ${TELEMETRY_LIMIT_MS / 1000} s, without plaintext`,
      async () => {
        const forbidden = await C('forbidden', { user: 'bob' });
        const wanted = ['AUTH_FAILURE', 'ACCESS_DENIED', 'RELEASE_DENIED', 'AUTHORITY_CHANGED'];
        const t0 = Date.now();
        let events = [];
        while (Date.now() - t0 < TELEMETRY_LIMIT_MS) {
          await A('epoch', { user: 'alice' }); // telemetry is exported after each control request
          events =
            (await B('collector', { identity: 'operator-client', port: PORTS.collector })).events ??
            [];
          if (wanted.every((k) => events.some((e) => e.event.eventType === k))) break;
          await sleep(200);
        }
        const kinds = Object.fromEntries(
          wanted.map((k) => [k, events.filter((e) => e.event.eventType === k).length]),
        );
        const contentFree = !JSON.stringify(events).includes(CANARY);
        return {
          pass:
            forbidden.status === 403 &&
            wanted.every((k) => kinds[k] > 0) &&
            contentFree &&
            Date.now() - t0 < TELEMETRY_LIMIT_MS,
          observed: { forbidden: forbidden.status, kinds, contentFree, elapsedMs: Date.now() - t0 },
        };
      },
    );
    await check(
      'T5.2',
      'R6',
      'Operator acknowledges an event; non-operator identity refused',
      async () => {
        const list = await B('collector', { identity: 'operator-client', port: PORTS.collector });
        const target =
          list.events.find((e) => e.event.eventType === 'ACCESS_DENIED') ?? list.events[0];
        const ack = await B('collector', {
          identity: 'operator-client',
          action: 'ack',
          eventId: target.event.eventId,
          port: PORTS.collector,
        });
        const outsider = await B('collector', {
          identity: 'control-client',
          port: PORTS.collector,
        });
        return {
          pass: ack.status === 200 && outsider.status === 403,
          observed: { ack: ack.status, nonOperator: outsider.status },
        };
      },
    );
    await check(
      'T5.3',
      'R2, R6',
      'Relay failure: submission refused with no partial object; accepted after restart',
      async () => {
        const before = await A('count', { user: 'alice' });
        await platform.stop('relay');
        const down = await A('send', { user: 'alice', to: 'bob', bytes: 4096, seed: 400 });
        const after = await A('count', { user: 'alice' });
        platform.start('relay');
        let up = { ok: false };
        for (let i = 0; i < 50 && !up.ok; i++) {
          await sleep(200);
          up = await A('send', { user: 'alice', to: 'bob', bytes: 4096, seed: 401 + i });
        }
        return {
          pass: !down.ok && before.objects === after.objects && up.ok,
          observed: {
            down,
            objectsBefore: before.objects,
            objectsAfter: after.objects,
            recovered: up.ok,
          },
        };
      },
    );
    await check(
      'T5.4',
      'R2',
      'Evidence verified on Host C by Node and Rust verifiers; tampered copy rejected',
      async () => {
        await exportEvidence('evidence-final.json');
        cpSync(join(states.b, 'evidence-final.json'), join(states.c, 'evidence-final.json')); // offline transfer
        const v = await C('verify', { file: 'evidence-final.json', rustBinary: RUST_VERIFIER });
        const rustOk =
          v.rust === 'NOT_BUILT' || (v.rust === 'ACCEPT' && v.rustTampered === 'REJECT');
        return {
          pass:
            v.node === 'ACCEPT' && v.nodeTampered === 'REJECT' && rustOk && v.rust !== 'NOT_BUILT',
          observed: v,
        };
      },
    );

    // ---- T6 recovery -----------------------------------------------------------------------
    const dbFiles = ['control.sqlite', 'control.sqlite-wal', 'control.sqlite-shm'];
    const snapshot = (to) => {
      mkdirSync(to, { recursive: true });
      for (const n of dbFiles) if (existsSync(join(f.dir, n))) cpSync(join(f.dir, n), join(to, n));
    };
    const restore = (from) => {
      for (const n of dbFiles) {
        rmSync(join(f.dir, n), { force: true });
        if (existsSync(join(from, n))) cpSync(join(from, n), join(f.dir, n));
      }
    };
    const restartControl = async (between) => {
      await platform.stop('control');
      between?.();
      platform.start('control');
      await B('ready');
    };
    await check('T6.1', 'R2, R10', 'Rolled-back authority database is quarantined', async () => {
      await restartControl(() => snapshot(join(work, 'backup-old')));
      const revoke = await B('admin', {
        user: 'admin',
        method: 'PATCH',
        path: `/api/admin/users/${P.rcp3.userId}`,
        body: { active: false },
      });
      await restartControl(() => {
        snapshot(join(work, 'backup-latest'));
        restore(join(work, 'backup-old'));
      });
      const send = await A('send', { user: 'alice', to: 'bob', bytes: 2048, seed: 500 });
      const claimR3 = await C('count', { user: 'rcp3' }).catch(() => ({ ok: false }));
      return {
        pass: revoke.ok && !send.ok && send.status === 503 && send.code === 'RECOVERY_QUARANTINED',
        observed: {
          revokeAfterBackup: revoke.status,
          sendWhileRolledBack: send,
          revokedUserRequest: claimR3,
        },
      };
    });
    await check(
      'T6.2',
      'R2',
      'Consistent database restored: service resumes and the revocation still holds',
      async () => {
        await restartControl(() => restore(join(work, 'backup-latest')));
        const send = await A('send', { user: 'alice', to: 'bob', bytes: 2048, seed: 501 });
        const revoked = await C('count', { user: 'rcp3' });
        return { pass: send.ok && !revoked.ok, observed: { send: send.ok, revokedUser: revoked } };
      },
    );

    // ---- T7 sovereign operation ------------------------------------------------------------
    await check('T7.1', 'R4', 'No host has a route out of the enclave', async () => {
      const out = {};
      for (const [h, run] of [
        ['a', A],
        ['b', B],
        ['c', C],
      ])
        out[h] = [
          await run('external', { host: '1.1.1.1', port: 443 }),
          await run('external', { host: '8.8.8.8', port: 53 }),
        ];
      return {
        pass: Object.values(out)
          .flat()
          .every((r) => !r.ok),
        observed: out,
      };
    });
    await check(
      'T7.2',
      'R12',
      'Signed offline bundle installs; tampered bundle refused',
      async () => {
        const tree = join(work, 'tree');
        execFileSync('git', ['worktree', 'add', '--detach', tree, 'HEAD'], { stdio: 'pipe' });
        try {
          const keys = pair();
          const bundle = join(work, 'bundle');
          const m = buildOfflineBundle({
            source: tree,
            destination: bundle,
            version: 1,
            revision: sourceRevision().commit,
            signingKey: keys.privateKey,
          });
          const installed = installOfflineBundle({
            bundle,
            destination: join(states.b, 'install'),
            ledger: join(work, 'ledger.json'),
            trustedKey: keys.publicKey,
            initialize: true,
          });
          cpSync(bundle, join(work, 'tampered'), { recursive: true });
          const file = join(work, 'tampered', 'files', 'app', 'services', 'control', 'core.mjs');
          writeFileSync(file, readFileSync(file, 'utf8') + '\n// altered\n');
          let tamper = 'ACCEPTED';
          try {
            installOfflineBundle({
              bundle: join(work, 'tampered'),
              destination: join(states.b, 'install2'),
              ledger: join(work, 'ledger2.json'),
              trustedKey: keys.publicKey,
              initialize: true,
            });
          } catch (error) {
            tamper = error.message;
          }
          return {
            pass: installed.status === 'INSTALLED' && tamper !== 'ACCEPTED',
            observed: { files: m.payload.files.length, installed: installed.status, tamper },
          };
        } finally {
          execFileSync('git', ['worktree', 'remove', '--force', tree], { stdio: 'pipe' });
        }
      },
    );
    await check(
      'T7.3',
      'R10',
      'Keys and evidence are local files on Host B; evidence verified offline on Host C',
      async () => {
        const keyFiles = readdirSync(f.dir, { recursive: true }).filter(
          (n) => /key/.test(String(n)) && !/\.(crt|csr)$/.test(String(n)),
        );
        const verified = results.find((r) => r.id === 'T5.4')?.outcome === 'PASS';
        return {
          pass: keyFiles.length > 0 && verified,
          observed: { keyFiles: keyFiles.map(String).sort(), offlineVerification: verified },
        };
      },
    );

    // ---- T8 performance --------------------------------------------------------------------
    await check(
      'T8.1',
      'R11',
      `Sustained load ${LOAD_SECONDS} s: zero digest mismatches and zero failures`,
      async () => {
        const pids = platform.pids();
        const dbBefore = databaseBytes(f.dir);
        const linkBefore = topology.linkCounters('b', 'sb1');
        const samples = [];
        let sampling = true;
        const sampler = (async () => {
          while (sampling) {
            samples.push({
              t: Date.now(),
              procs: Object.fromEntries(Object.entries(pids).map(([r, p]) => [r, procSample(p)])),
            });
            await sleep(1000);
          }
        })();
        const t0 = Date.now();
        const sent = await A(
          'loadSend',
          {
            users: ['snd1', 'snd2', 'snd3', 'snd4'],
            to: ['lrx1', 'lrx2', 'lrx3', 'lrx4'],
            seconds: LOAD_SECONDS,
            bytes: 4096,
            workers: 2,
          },
          (LOAD_SECONDS + 120) * 1000,
        );
        const sendSeconds = (Date.now() - t0) / 1000;
        cpSync(join(states.a, 'load-sent.json'), join(states.c, 'load-sent.json')); // manifest of digests
        const from = Object.fromEntries([1, 2, 3, 4].map((i) => [P[`snd${i}`].userId, `snd${i}`]));
        const t1 = Date.now();
        const received = await C(
          'loadReceive',
          {
            users: ['lrx1', 'lrx2', 'lrx3', 'lrx4'],
            from: { ...from, _: 'snd1' },
            manifest: 'load-sent.json',
          },
          600000,
        );
        const receiveSeconds = (Date.now() - t1) / 1000;
        sampling = false;
        await sampler;
        const linkAfter = topology.linkCounters('b', 'sb1');
        const dbAfter = databaseBytes(f.dir);
        const cpu = {};
        for (const role of Object.keys(pids)) {
          const series = samples.map((s) => s.procs[role]).filter(Boolean);
          if (series.length < 2) continue;
          const span = (samples.at(-1).t - samples[0].t) / 1000;
          cpu[role] = {
            avgCpuPercent:
              Math.round(((series.at(-1).cpuSeconds - series[0].cpuSeconds) / span) * 1000) / 10,
            peakRssMiB: Math.round(Math.max(...series.map((x) => x.rssBytes)) / 1048576),
          };
        }
        metrics.load = {
          senders: 4,
          workersPerSender: 2,
          payloadBytes: 4096,
          sendPhase: {
            seconds: sendSeconds,
            sent: sent.sent,
            refused: sent.refused,
            exchangesPerSecond: Math.round((sent.sent / sendSeconds) * 100) / 100,
            latencyMs: summary(sent.latencies ?? []),
          },
          receivePhase: {
            seconds: receiveSeconds,
            delivered: received.delivered,
            mismatched: received.mismatched,
            failed: received.failed,
            claimsPerSecond: Math.round((received.delivered / receiveSeconds) * 100) / 100,
            latencyMs: summary(received.latencies ?? []),
          },
          hostB: {
            processes: cpu,
            linkAB: {
              rxBytes: linkAfter.rxBytes - linkBefore.rxBytes,
              txBytes: linkAfter.txBytes - linkBefore.txBytes,
            },
            databaseGrowthBytes: dbAfter - dbBefore,
            databaseBytesPerExchange: sent.sent
              ? Math.round((dbAfter - dbBefore) / sent.sent)
              : null,
          },
        };
        return {
          pass:
            sent.ok &&
            sent.sent > 0 &&
            sent.refused === 0 &&
            received.mismatched === 0 &&
            received.failed === 0 &&
            received.delivered === sent.sent,
          observed: {
            sent: sent.sent,
            refused: sent.refused,
            delivered: received.delivered,
            mismatched: received.mismatched,
            failed: received.failed,
          },
          measurements: metrics.load,
        };
      },
    );
  } catch (error) {
    record('HARNESS', '-', 'Harness completed without an unexpected fault', false, {
      error: error.message,
      stack: error.stack?.split('\n').slice(0, 4),
    });
  } finally {
    await stopChild(adapter);
    await stopChild(relay);
    await platform.stopAll();
    try {
      topology.teardown();
    } catch {}
    rmSync(work, { recursive: true, force: true });
    rmSync(f.dir, { recursive: true, force: true });
  }
  return finish({ results, metrics, capability, startedAt, environment });
}

async function finish({ results, metrics, capability, startedAt, environment }) {
  const source = sourceRevision();
  const inventory = {
    schemaVersion: 1,
    source: { ...source, sourceDigest: await sourceDigest() },
    host: { cpu: cpus()[0]?.model ?? null, cpuCount: cpus().length, memoryBytes: totalmem() },
    runtime: runtimeVersions(),
    capability,
    environment,
  };
  const allPass = results.length > 0 && results.every((r) => r.outcome === 'PASS');
  const outcome = !allPass ? 'FAIL' : ONLY ? 'PARTIAL' : 'PASS';
  const testResults = {
    schemaVersion: 1,
    matrix: 'docs/trl5/ACCEPTANCE_MATRIX.md',
    startedAt,
    finishedAt: new Date().toISOString(),
    source: inventory.source,
    outcome,
    filter: ONLY,
    passed: results.filter((r) => r.outcome === 'PASS').length,
    total: results.length,
    results,
  };
  writeFileSync(join(OUT, 'test-results.json'), JSON.stringify(testResults, null, 2) + '\n');
  writeFileSync(join(OUT, 'metrics.json'), JSON.stringify(metrics, null, 2) + '\n');
  writeFileSync(join(OUT, 'environment-inventory.json'), JSON.stringify(inventory, null, 2) + '\n');
  const manifest = { schemaVersion: 1, source: inventory.source, files: {} };
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name !== 'evidence-manifest.json')
        manifest.files[relative(OUT, p)] = sha256(readFileSync(p));
    }
  };
  walk(OUT);
  writeFileSync(join(OUT, 'evidence-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return testResults;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve('scripts/trl5-validation.mjs')) {
  const r = await runTrl5Validation();
  console.log(
    `TRL 5 advancement validation ${r.outcome}: ${r.passed}/${r.total} (${join(OUT, 'test-results.json')})`,
  );
  if (r.outcome !== 'PASS') process.exitCode = 1;
}
