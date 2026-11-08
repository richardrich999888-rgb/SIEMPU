// Source-bound, synthetic observer package. No external API access or qualification decision.
import { existsSync, mkdirSync, lstatSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { snapshot } from '../assurance/sag/package.mjs';
import { encode, sha256, fingerprint, safePath, insist } from '../assurance/sag/format.mjs';
import { executeFamily, redact } from '../assurance/iaf/run.mjs';
import { comparePolicyRelease } from './policy-release-comparison.mjs';
import { IUDX_CONTRACT } from '../integrations/india-dpi/iudx-resource-reader.mjs';

const root = process.cwd();
const destination = resolve(process.argv[2] || 'artifacts/interop-assurance');
const rel = relative(root, destination).replaceAll('\\', '/');
insist(
  safePath(rel) && rel.startsWith('artifacts/') && !existsSync(destination),
  'NEW_ARTIFACT_DIRECTORY_REQUIRED',
);
let parent = root;
for (const part of rel.split('/').slice(0, -1)) {
  parent = join(parent, part);
  if (existsSync(parent))
    insist(
      lstatSync(parent).isDirectory() && !lstatSync(parent).isSymbolicLink(),
      'UNSAFE_ARTIFACT_DIRECTORY',
    );
  else mkdirSync(parent, { mode: 0o700 });
}
const source = snapshot(root);
mkdirSync(destination, { mode: 0o700 });
const report = {
  schemaVersion: 1,
  kind: 'SIEPMU_GOVERNMENT_INTEROP_ASSURANCE_LAB',
  startedAt: new Date().toISOString(),
  gitCommit: source.commit,
  gitTree: source.tree,
  sourceFingerprint: fingerprint(source.index),
  scope: 'Synthetic local contract and TLS tests; no live government API or personnel data.',
  qualification: 'NOT_ESTABLISHED',
  trl: 'PROVISIONAL_TRL4_UNCHANGED',
  outcome: 'FAIL',
  contract: IUDX_CONTRACT,
  tests: null,
  benchmark: null,
  failures: [],
};
const files = [];
function save(name, bytes) {
  writeFileSync(join(destination, name), bytes, { flag: 'wx', mode: 0o600 });
  files.push({ path: name, bytes: bytes.length, sha256: sha256(bytes) });
}
try {
  const { log, ...result } = await executeFamily(root, [
    'tests/india-dpi-iudx.test.mjs',
    'scripts/policy-release-comparison.test.mjs',
  ]);
  save('contracts.tap', Buffer.from(log));
  report.tests = result;
  if (result.outcome !== 'PASS') report.failures.push('CONTRACT_OR_COMPARISON_TEST_FAILED');
  try {
    const comparison = await comparePolicyRelease();
    report.benchmark = comparison.report;
    save('evidence.json', encode(comparison.evidence));
    save('public-key.json', encode(comparison.publicKey));
  } catch (error) {
    report.failures.push('BENCHMARK_FAILED: ' + redact(error.message).slice(0, 1000));
  }
  const after = snapshot(root);
  insist(
    after.commit === source.commit &&
      after.tree === source.tree &&
      fingerprint(after.index) === report.sourceFingerprint,
    'SOURCE_CHANGED',
  );
  report.outcome = report.failures.length ? 'FAIL' : 'PASS';
} catch (error) {
  report.failures.push(redact(error.message).slice(0, 1000));
}
report.finishedAt = new Date().toISOString();
save('report.json', encode(report));
save('source-index.json', encode(source.index));
save(
  'research-and-readiness.md',
  readFileSync(join(root, 'docs/interop/GOVERNMENT_INTEROPERABILITY_AND_DEFENCE_ASSURANCE.md')),
);
const bench = report.benchmark;
const summary = [
  '# AIRON–SIEPMU Government Interoperability and Defence Assurance Report',
  '',
  `Source: \`${report.gitCommit}\`; tree: \`${report.gitTree}\`.`,
  `Execution: **${report.outcome}**; ${report.tests?.counts?.pass ?? 0}/${report.tests?.counts?.tests ?? 0} contract/comparison tests.`,
  'Scope: synthetic local tests only. No live government compatibility, SAG grading, operational authorization or TRL advancement is established.',
  '',
  '## Measurements',
  '',
  '| Operation | Samples | Median ms | p95 ms |',
  '|---|---:|---:|---:|',
  ...Object.entries(bench?.measurements || {}).map(
    ([k, v]) => `| ${k} | ${v.count} | ${v.p50Ms.toFixed(3)} | ${v.p95Ms.toFixed(3)} |`,
  ),
  '',
  `Sequential workload: ${bench?.sequentialObjectsPerSecond?.toFixed(2) ?? 'unavailable'} objects/second; in-process, one sender, 4 KiB synthetic data. This is not maximum capacity.`,
  `Post-revocation new issuances: ${bench?.policyExperiment?.newIssuancesAfterRevocation ?? 'unavailable'}. Already disclosed content remains readable.`,
  '',
  'Raw samples, CPU/memory, audit size, environment and limitations: report.json. Research, nine requested report sections and external blockers: research-and-readiness.md.',
  'Independent reproduction: follow docs/interop/INDIA_DPI_TESTBED.md at the source hash above. The manifest detects changed files only relative to its independently retained digest; it is not a signed attestation.',
  '',
  ...(report.failures.length
    ? ['## Failures', '', ...report.failures.map((x) => '- ' + x), '']
    : []),
].join('\n');
save('REPORT.md', Buffer.from(summary));
const manifest = encode({
  kind: 'SIEPMU_INTEROP_LAB_EVIDENCE_V1',
  gitCommit: source.commit,
  gitTree: source.tree,
  files,
});
writeFileSync(join(destination, 'manifest.json'), manifest, { flag: 'wx', mode: 0o600 });
console.log(
  JSON.stringify(
    {
      outcome: report.outcome,
      gitCommit: source.commit,
      destination: rel,
      manifestSha256: sha256(manifest),
      tests: report.tests?.counts,
      measurements: bench?.measurements,
      failures: report.failures,
    },
    null,
    2,
  ),
);
if (report.outcome !== 'PASS') process.exitCode = 1;
