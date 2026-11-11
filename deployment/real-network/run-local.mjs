import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { platform, release, cpus, totalmem } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { provision, placement } from './provision.mjs';
import { startHost } from './host.mjs';
import { campaign, benchmarkProtocol } from './campaign.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import { packet } from '../../services/control/primitives.mjs';
import { verifyEvidence } from '../../apps/verifier/verify.mjs';
const exec = promisify(execFile),
  output = resolve(process.argv[2] ?? 'artifacts/p0-047/local');
mkdirSync(resolve(output, '..'), { recursive: true });
mkdirSync(output, { mode: 0o700 });
const privateDir = resolve(process.argv[3] ?? '.data/p0-047-local');
const deployment = await provision(privateDir, { mode: 'local-process' }),
  hosts = [];
const hash = (b) => createHash('sha256').update(b).digest('hex');
const report = {
  schemaVersion: 1,
  source: deployment.source,
  startedAt: new Date().toISOString(),
  evidenceClass: 'LOCAL_PROCESS',
  independentHosts: false,
  independentAdministration: false,
  managedCompanion: 'BLOCKED_TOKEN_AND_SANDBOX_UNAVAILABLE',
  endpoint: 'REAL_SOFTWARE_SDK_AND_MANAGED_OUTBOX',
  transport: 'TLS1.3 endpoint-to-web; pinned mTLS service-to-service',
  protocol: benchmarkProtocol,
  environment: {
    node: process.version,
    platform: platform(),
    kernel: release(),
    cpuModel: cpus()[0]?.model,
    cpus: cpus().length,
    memory: totalmem(),
  },
  rows: [],
  startupDiagnostics: [],
  startupDiagnosticsTruncated: false,
  limitations: [
    'One kernel and administrator',
    'No emulated link or external network',
    'Standby remains quarantined',
    'Short fixed-work experiment only',
  ],
};
const save = () =>
  writeFileSync(join(output, 'campaign.json'), JSON.stringify(report, null, 2) + '\n');
const roleDir = (role) =>
  join(privateDir, Object.entries(placement).find(([, roles]) => roles.includes(role))[0], role);
async function invoke(role, op, arg) {
  let stdout;
  try {
    ({ stdout } = await exec(
      process.execPath,
      [
        'deployment/real-network/endpoint.mjs',
        roleDir(role),
        op,
        ...(arg === undefined ? [] : [String(arg)]),
      ],
      { timeout: 30000, maxBuffer: 1024 * 1024 },
    ));
  } catch (e) {
    if (!e.stdout) throw new Error('ENDPOINT_PROCESS_FAILED');
    stdout = e.stdout;
  }
  return JSON.parse(stdout.trim().split('\n').at(-1));
}
const unit = async (...args) => {
  const r = await invoke(...args);
  assert.equal(r.ok, true, `${args[0]}/${args[1]} ${r.code ?? ''} ${r.status ?? ''}`);
  return r;
};
const failure = async (...args) => {
  const r = await invoke(...args);
  assert.equal(r.ok, false, 'UNEXPECTED_OPERATION_SUCCESS');
  return r;
};
const tls = { ca: readFileSync(join(roleDir('unit-a'), 'keys/ca.crt')) };
async function ready() {
  for (let i = 0; i < 120; i++) {
    try {
      const response = await requestBytes(deployment.urls.web + '/health/ready', {
        tls,
        timeoutMs: 500,
      });
      report.lastReadiness = {
        status: response.status,
        body: response.body.toString('utf8').slice(0, 500),
      };
      if (response.status === 200) return;
    } catch (error) {
      report.lastReadiness = {
        code: error.code ?? error.name,
        message: String(error.message).slice(0, 200),
      };
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('TESTBED_READINESS');
}
function disk(path) {
  return readdirSync(path, { withFileTypes: true }).reduce(
    (sum, f) =>
      sum +
      (f.isDirectory()
        ? disk(join(path, f.name))
        : f.isFile()
          ? statSync(join(path, f.name)).size
          : 0),
    0,
  );
}
function resources() {
  return hosts.flatMap((h) =>
    [...h.children.entries()].map(([role, c]) => {
      try {
        return {
          role,
          pid: c.pid,
          status: readFileSync(`/proc/${c.pid}/status`, 'utf8')
            .split('\n')
            .filter((s) => /^(VmRSS|VmHWM|Threads):/.test(s)),
          stat: readFileSync(`/proc/${c.pid}/stat`, 'utf8').trim(),
        };
      } catch {
        return { role, unavailable: true };
      }
    }),
  );
}
try {
  for (const node of ['D', 'C', 'B'])
    hosts.push(
      startHost(join(privateDir, node), {
        onLog(role, line) {
          if (report.startupDiagnostics.length < 40)
            report.startupDiagnostics.push({ role, line: line.slice(0, 1000) });
          else report.startupDiagnosticsTruncated = true;
        },
      }),
    );
  await ready();
  report.diskBefore = disk(privateDir);
  report.resourcesBefore = resources();
  save();
  const authority = hosts.at(-1);
  await campaign({
    unit,
    failure,
    record: async (row) => {
      report.rows.push(row);
      save();
    },
    hooks: {
      stopAuthority: () => authority.stopRole('control'),
      startAuthority: async () => {
        authority.startRole('control');
        await ready();
      },
      inspectRelay: async () => {
        const dir = roleDir('relay'),
          state = join(dir, 'state'),
          files = readdirSync(state).sort();
        assert.deepEqual(files, ['authority-public.json', 'relay', 'relay.secret']);
        const db = new DatabaseSync(join(state, 'relay/relay.sqlite'), { readOnly: true });
        try {
          const blobs = db.prepare('SELECT hash,ciphertext,size FROM blobs').all();
          assert.ok(blobs.length >= 2);
          for (const b of blobs) {
            assert.equal(hash(b.ciphertext), b.hash);
            assert.equal(Buffer.from(b.ciphertext).includes(Buffer.alloc(64, 83)), false);
          }
          return {
            files,
            blobCount: blobs.length,
            ciphertextHashes: blobs.map((b) => b.hash),
            protectedKeysInRoleBundle: false,
            scope:
              'Controlled synthetic role mount only; host administrator and timing/size metadata remain trusted or exposed',
          };
        } finally {
          db.close();
        }
      },
    },
  });
  report.diskAfter = disk(privateDir);
  report.resourcesAfter = resources();
} catch (error) {
  report.runnerFailure = String(error.message).slice(0, 300);
  report.serviceStatesAtFailure = hosts.flatMap((h) =>
    [...h.children.entries()].map(([role, c]) => ({
      role,
      exitCode: c.exitCode,
      signalCode: c.signalCode,
    })),
  );
} finally {
  for (const h of [...hosts].reverse()) await h.stop();
  for (let n = 1; n <= 12; n++) {
    const id = 'NET-' + String(n).padStart(2, '0');
    if (!report.rows.some((r) => r.id === id))
      report.rows.push({
        id,
        outcome: 'BLOCKED',
        reason: 'Runner prerequisite failed; experiment not executed',
      });
  }
  const evidenceFiles = [];
  try {
    const dir = join(roleDir('control'), 'state'),
      db = new DatabaseSync(join(dir, 'control.sqlite'), { readOnly: true });
    try {
      const records = db
        .prepare('SELECT record FROM evidence ORDER BY sequence')
        .all()
        .map((r) => JSON.parse(r.record));
      const head = db
        .prepare('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1')
        .get();
      const key = JSON.parse(readFileSync(join(dir, 'public-key.json')));
      const checkpoint = packet(JSON.parse(readFileSync(join(dir, 'server-key.json'))), {
        sequence: head?.sequence ?? 0,
        headHash: head?.hash ?? '0'.repeat(64),
        issuedAt: Date.now(),
      });
      const exported = { records, checkpoint };
      report.offlineVerification = await verifyEvidence(exported, key);
      report.offlineVerification.independentCheckpointRetention = 'NOT_ESTABLISHED';
      for (const [name, value] of [
        ['evidence.json', exported],
        ['authority-public.json', key],
        ['checkpoint.json', checkpoint],
      ]) {
        writeFileSync(join(output, name), JSON.stringify(value, null, 2) + '\n');
        evidenceFiles.push(name);
      }
    } finally {
      db.close();
    }
  } catch (error) {
    report.evidenceExportFailure = String(error.message).slice(0, 200);
  }
  report.finishedAt = new Date().toISOString();
  report.localOutcome =
    report.runnerFailure ||
    report.evidenceExportFailure ||
    report.rows.some((r) => r.outcome === 'FAIL')
      ? 'FAIL'
      : 'PASS_WITH_BLOCKERS';
  report.requestedIndependentHostValidation = 'BLOCKED';
  save();
  const manifest = {
    format: 'P0_047_CONTENT_MANIFEST_V1',
    source: deployment.source,
    files: ['campaign.json', ...evidenceFiles].map((path) => ({
      path,
      sha256: hash(readFileSync(join(output, path))),
    })),
  };
  writeFileSync(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  console.log(
    JSON.stringify({
      outcome: report.localOutcome,
      rows: report.rows.map(({ id, outcome }) => ({ id, outcome })),
      report: join(output, 'campaign.json'),
    }),
  );
  if (report.localOutcome === 'FAIL') process.exitCode = 1;
}
