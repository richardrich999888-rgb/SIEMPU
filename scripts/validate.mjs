import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn, execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { sourceDigest, auditClaims } from './audit-claims.mjs';

const root = process.cwd();
const destination = resolve(root, 'artifacts/validation');
await mkdir(destination, { recursive: true });
const report = {
  schemaVersion: 1,
  kind: 'native-validation',
  startedAt: new Date().toISOString(),
  gitCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  workingTreeStatus: execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }),
  sourceDigest: await sourceDigest(root),
  runtime: { node: process.version, platform: process.platform, architecture: process.arch },
  externalObservations: {
    container: 'NOT_OBSERVED',
    hostedSast: 'NOT_OBSERVED',
    browser: 'NOT_OBSERVED',
  },
  gates: [],
};
const sanitize = (value) =>
  value
    .replace(/otpauth:\/\/\S+/gi, '[REDACTED_OTP_URI]')
    .replace(/(authorization\s*[:=]\s*|bearer\s+)\S+/gi, '$1[REDACTED]')
    .replace(
      /((?:password|totpSecret|privateKey|token|secret)\s*["']?\s*[:=]\s*["']?)[^\s,"'}]+/gi,
      '$1[REDACTED]',
    );
const gates = [
  ['check', ['run', 'check']],
  ['lint', ['run', 'lint']],
  ['typecheck', ['run', 'typecheck']],
  ['format:check', ['run', 'format:check']],
  ['test:coverage', ['run', 'test:coverage']],
  ['security', ['run', 'security']],
  ['dependency-audit', ['audit', '--audit-level=high']],
  ['build', ['run', 'build']],
  ['sbom', ['run', 'sbom']],
  ['demo', ['run', 'demo']],
];
if (process.argv.includes('--benchmark')) gates.push(['benchmark', ['run', 'benchmark']]);
for (const [name, args] of gates) {
  const startedAt = new Date().toISOString();
  let output = '';
  const exitCode = await new Promise((resolveExit) => {
    const child = spawn('npm', args, {
      cwd: root,
      env: { ...process.env, SIEPMU_EVIDENCE_DIR: resolve(root, 'artifacts/validation/demo') },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    for (const stream of [child.stdout, child.stderr])
      stream.on('data', (b) => {
        if (output.length < 32 * 1024 * 1024) output += b.toString();
      });
    child.on('error', (error) => {
      output += error.message;
      resolveExit(127);
    });
    child.on('close', (code) => resolveExit(code ?? 128));
  });
  const log = `artifacts/validation/${name.replaceAll(':', '-')}.log`;
  await writeFile(resolve(root, log), sanitize(output), { mode: 0o600 });
  report.gates.push({
    name,
    command: ['npm', ...args],
    exitCode,
    outcome: exitCode === 0 ? 'PASS' : 'FAIL',
    startedAt,
    finishedAt: new Date().toISOString(),
    log,
  });
  if (name === 'test:coverage') {
    const count = (label) => {
      const match = output.match(new RegExp('(?:#|ℹ)\\s+' + label + '\\s+(\\d+)'));
      return match ? Number(match[1]) : null;
    };
    report.tests = {
      total: count('tests'),
      failed: count('fail'),
      cancelled: count('cancelled'),
      skipped: count('skipped'),
    };
  }
  console.log(`${name}: ${exitCode === 0 ? 'PASS' : 'FAIL'} (exit ${exitCode}; ${log})`);
}
try {
  const demo = JSON.parse(
    await readFile(resolve(root, 'artifacts/validation/demo/results.json'), 'utf8'),
  );
  const fresh = Date.parse(demo.timestamp) >= Date.parse(report.startedAt);
  const passed = demo.results.filter((r) => r.outcome === 'PASS').length;
  report.demo = {
    total: demo.results.length,
    passed: fresh ? passed : 0,
    failed: fresh ? demo.results.length - passed : demo.results.length,
    synthetic: demo.synthetic === true,
  };
} catch {
  report.demo = { total: 0, passed: 0, failed: 1, synthetic: false };
}
report.sourceDigestAfter = await sourceDigest(root);
report.finishedAt = new Date().toISOString();
report.outcome =
  report.gates.every((g) => g.exitCode === 0) &&
  report.sourceDigest === report.sourceDigestAfter &&
  report.tests?.total > 0 &&
  report.tests.failed === 0 &&
  report.tests.cancelled === 0 &&
  report.tests.skipped === 0 &&
  report.demo.total >= 9 &&
  report.demo.failed === 0 &&
  report.demo.synthetic
    ? 'PASS'
    : 'FAIL';
const reportPath = resolve(destination, 'report.json');
await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
const claims = await auditClaims({ root, requireEvidence: true });
report.claimsAudit = claims;
if (!claims.valid) report.outcome = 'FAIL';
await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
console.log(
  `Validation ${report.outcome}: artifacts/validation/report.json. Native execution does not prove container, browser, hosted SAST or external approval.`,
);
if (report.outcome !== 'PASS') process.exitCode = 1;
