// Frozen-source five-demonstration campaign. Synthetic data and local fixtures only.
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, relative, join } from 'node:path';
import { snapshot } from '../sag/package.mjs';
import { encode, sha256, fingerprint, safePath, insist } from '../sag/format.mjs';
import { executeFamily } from '../iaf/run.mjs';
import { comparePolicyRelease } from '../../scripts/policy-release-comparison.mjs';

const root = process.cwd(),
  out = resolve(process.argv[2] || 'artifacts/p0-041');
const rel = relative(root, out).replaceAll('\\', '/');
insist(
  safePath(rel) && rel.startsWith('artifacts/') && !existsSync(out),
  'NEW_ARTIFACT_DIRECTORY_REQUIRED',
);
const source = snapshot(root);
mkdirSync(out, { recursive: true, mode: 0o700 });
const demos = [
  {
    id: 'DEMO-1',
    title: 'Ciphertext relay and sealed connector cannot decrypt endpoint content',
    tests: ['tests/crypto.test.mjs', 'tests/sealed-integration.test.mjs'],
    expected:
      'Endpoint round trip succeeds; wrong recipient key, tampered wraps and connector plaintext/key canaries are rejected or absent.',
  },
  {
    id: 'DEMO-2',
    title: 'Revocation prevents new release',
    tests: ['tests/authority.test.mjs', 'scripts/policy-release-comparison.test.mjs'],
    expected:
      'A revocation committed before release produces zero new authorized issuances. Previously returned keys remain usable.',
  },
  {
    id: 'DEMO-3',
    title: 'Unsafe recovery and conflicting writer authority are quarantined',
    tests: [
      'tests/recovery.test.mjs',
      'tests/authority-state-custody.test.mjs',
      'tests/writer-fencing.test.mjs',
    ],
    expected:
      'Wrong ancestry, partial authorization rollback, unanchored-suffix rollback, missing seals, stale writers, lower floors and interrupted writes fail closed.',
  },
  {
    id: 'DEMO-4',
    title: 'Network interruption preserves integrity and fresh policy checks',
    tests: ['tests/network-failure/recovery.test.mjs', 'tests/transport/secure-stack.test.mjs'],
    expected:
      'Lost responses/reconnect preserve exact bytes; disconnected revocation blocks release; actual mTLS custody outage quarantines then recovers.',
  },
  {
    id: 'DEMO-5',
    title: 'Offline verification detects inconsistent evidence',
    tests: [
      'tests/crypto.test.mjs',
      'tests/verifier-replay.test.mjs',
      'tests/incremental-custody.test.mjs',
    ],
    expected:
      'Tamper, deletion, replay, wrong receipt bindings and divergent history fail. A valid old prefix requires an independently retained checkpoint to detect rollback.',
  },
];
const report = {
  schemaVersion: 1,
  kind: 'P0_041_QUALIFICATION_LAB',
  gitCommit: source.commit,
  gitTree: source.tree,
  sourceFingerprint: fingerprint(source.index),
  startedAt: new Date().toISOString(),
  outcome: 'FAIL',
  demonstrations: [],
  comparisons: [],
  qualification: 'NOT_ESTABLISHED',
  trl: 'PROVISIONAL_TRL4_UNCHANGED',
  limitations: [
    'All local fixtures share one host and administrator. Distinct keys and processes do not establish independent custody.',
    'Counts overlap native and adversarial suites; do not sum.',
    'Network namespace, kernel loss and sustained-load evidence belong to the separate relevant-environment CI artifact.',
    'These applicant-defined criteria do not substitute for IAF or SAG acceptance.',
  ],
  failures: [],
};
const files = [];
const save = (path, value) => {
  const bytes = typeof value === 'string' ? Buffer.from(value) : encode(value);
  writeFileSync(join(out, path), bytes, { flag: 'wx', mode: 0o600 });
  files.push({ path, bytes: bytes.length, sha256: sha256(bytes) });
};
for (const demo of demos) {
  const { log, ...result } = await executeFamily(root, demo.tests);
  save(`${demo.id}.tap`, log);
  report.demonstrations.push({ ...demo, ...result });
  if (result.outcome !== 'PASS') report.failures.push(demo.id);
}
// Same source, runtime, payload size, count and serial scheduling. No concurrent campaign work.
for (const custody of ['none', 'fenced']) {
  try {
    const result = await comparePolicyRelease({ iterations: 20, custody });
    save(`comparison-${custody}.json`, result.report);
    save(`comparison-${custody}-evidence.json`, result.evidence);
    save(`comparison-${custody}-public-key.json`, result.publicKey);
    report.comparisons.push({ custody, ...result.report });
  } catch (error) {
    report.failures.push(`comparison-${custody}: ${error.message}`);
  }
}
const after = snapshot(root);
insist(
  after.commit === source.commit && after.tree === source.tree,
  'SOURCE_CHANGED_DURING_CAMPAIGN',
);
report.finishedAt = new Date().toISOString();
report.outcome = report.failures.length ? 'FAIL' : 'PASS';
save('report.json', report);
const manifest = encode({
  kind: 'P0_041_EVIDENCE_MANIFEST',
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
      manifestSha256: sha256(manifest),
      demonstrations: report.demonstrations.map(({ id, counts, outcome }) => ({
        id,
        counts,
        outcome,
      })),
      failures: report.failures,
    },
    null,
    2,
  ),
);
if (report.outcome !== 'PASS') process.exitCode = 1;
