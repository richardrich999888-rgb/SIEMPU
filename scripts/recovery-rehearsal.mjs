// Frozen-source synthetic rehearsal; no production-input arguments.
import { existsSync, lstatSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, relative, join, dirname } from 'node:path';
import { snapshot } from '../assurance/sag/package.mjs';
import { encode, sha256, fingerprint, safePath, insist } from '../assurance/sag/format.mjs';
import {
  recoveryFixture,
  runRecoveryFixture,
  getJson,
} from '../tests/helpers/recovery-rehearsal.mjs';
const root = process.cwd(),
  out = resolve(process.argv[2] || 'artifacts/guarded-recovery'),
  rel = relative(root, out).replaceAll('\\', '/');
insist(
  process.argv.length <= 3 && safePath(rel) && rel.startsWith('artifacts/') && !existsSync(out),
  'NEW_ARTIFACT_DIRECTORY_REQUIRED',
);
let current = root;
for (const part of rel.split('/').slice(0, -1)) {
  current = join(current, part);
  if (existsSync(current))
    insist(
      lstatSync(current).isDirectory() && !lstatSync(current).isSymbolicLink(),
      'UNSAFE_OUTPUT_DIRECTORY',
    );
  else mkdirSync(current, { mode: 0o700 });
}
const source = snapshot(root);
mkdirSync(out, { mode: 0o700 });
const files = [],
  save = (path, value) => {
    const bytes = encode(value);
    writeFileSync(join(out, path), bytes, { flag: 'wx', mode: 0o600 });
    files.push({ path, bytes: bytes.length, sha256: sha256(bytes) });
  };
const report = {
  schemaVersion: 1,
  kind: 'SYNTHETIC_GUARDED_RECOVERY_REHEARSAL',
  gitCommit: source.commit,
  gitTree: source.tree,
  sourceFingerprint: fingerprint(source.index),
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  startedAt: new Date().toISOString(),
  outcome: 'FAIL',
  cases: [],
  failures: [],
  qualification: 'NOT_ESTABLISHED',
  trl: 'PROVISIONAL_TRL4_UNCHANGED',
  measurement:
    'One fixture per profile. recoveryMs includes input validation/staging through fresh lease and listening control server. totalMs includes encrypted exchange, identity denial and stale-writer checks. Setup and human decision time excluded; no percentile, capacity or RTO/RPO SLA.',
  limitations: [
    'Synthetic data, one host/administrator; separate keys/stores do not demonstrate independent administrative custody.',
    'Real loopback HTTP control and relay; custodian and monitoring calls in-process. Not multi-host mTLS recovery.',
    'One acknowledged pre-snapshot object per profile; zero measured object loss is not fleet RPO.',
    'Quiescent snapshots only, at most 1000 evidence records and 1000 alerts. Full signed telemetry replay, not exporter cursor recovery.',
    'Custody preserved, never restored/reset. Missing historical witnesses and unverifiable legacy states remain refused.',
    'Resume only before protected state advances; later restart requires new consistent snapshots/evidence/review.',
    'No endpoint keys/queues, connector state, full-site DR, HA, physical power-loss qualification or production activation.',
    'Fixture signatures do not establish real human approval or current policy truth.',
  ],
};
for (const migrated of [false, true]) {
  const cleanups = [],
    profile = migrated ? 'migrated' : 'sealed';
  try {
    const f = await recoveryFixture({ after: (fn) => cleanups.push(fn) }, { migrated });
    const { evidence, publicKey, ...result } = await runRecoveryFixture(f.config);
    save(`${profile}-evidence.json`, evidence);
    save(`${profile}-authority-public-key.json`, publicKey);
    save(`${profile}-trust.json`, f.trust);
    save(`${profile}-plan.json`, f.plan);
    save(`${profile}-approval.json`, f.approval);
    save(
      `${profile}-handover.json`,
      getJson(join(dirname(f.request.trust), 'retained-handover.json')),
    );
    report.cases.push(result);
  } catch (error) {
    report.failures.push({ profile, error: error.message });
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup();
  }
}
const after = snapshot(root);
insist(
  after.commit === source.commit && after.tree === source.tree,
  'SOURCE_CHANGED_DURING_REHEARSAL',
);
report.finishedAt = new Date().toISOString();
report.outcome = report.failures.length || report.cases.length !== 2 ? 'FAIL' : 'PASS';
save('report.json', report);
const manifest = encode({
  kind: 'GUARDED_RECOVERY_EVIDENCE_MANIFEST',
  gitCommit: source.commit,
  gitTree: source.tree,
  files,
});
writeFileSync(join(out, 'manifest.json'), manifest, { flag: 'wx', mode: 0o600 });
console.log(
  JSON.stringify(
    {
      outcome: report.outcome,
      gitCommit: source.commit,
      gitTree: source.tree,
      manifestSha256: sha256(manifest),
      cases: report.cases,
      failures: report.failures,
    },
    null,
    2,
  ),
);
if (report.outcome !== 'PASS') process.exitCode = 1;
