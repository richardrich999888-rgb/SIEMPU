import { readFile, stat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const requiredGates = [
  'check',
  'lint',
  'typecheck',
  'format:check',
  'test:coverage',
  'security',
  'dependency-audit',
  'build',
  'sbom',
  'demo',
];
const statuses = new Set([
  'TESTED',
  'MEASURED',
  'IMPLEMENTED_UNVERIFIED',
  'SIMULATED',
  'PLANNED',
  'EXTERNALLY_APPROVED',
  'NOT_SUPPORTED',
]);
const requiredFields = [
  'CLAIM_ID',
  'CLAIM_TEXT',
  'STATUS',
  'SOURCE',
  'IMPLEMENTATION',
  'COMMIT',
  'TEST',
  'RESULT',
  'EVIDENCE',
  'DATE',
  'LIMITATION',
];
const unsupported =
  /\b(?:IAF approved|SAG (?:graded|certified)|defen[cs]e certified|unhackable|zero vulnerabilities|guaranteed delivery|instant revocation|patent(?:able| granted)|first in the world|100% Indian IP|production.ready)\b/i;

/** Bind evidence to executable sources, tests, policy manifest, build/deployment and lockfile. */
export async function sourceDigest(root = process.cwd()) {
  const files = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { cwd: root, encoding: 'utf8' },
  )
    .split('\0')
    .filter(Boolean)
    .filter(
      (p) =>
        /^(?:apps|services|packages|scripts|tests|tools|database|deployment|deploy|infrastructure|security|\.github)\//.test(
          p,
        ) ||
        p === 'docs/api.openapi.json' ||
        /^(?:package(?:-lock)?\.json|CLAIMS_REGISTER\.yaml|Dockerfile|compose\.yaml|Makefile|eslint\.config\.mjs|tsconfig\.json|\.prettier(?:rc\.json|ignore)|\.env\.example|\.gitignore)$/.test(
          p,
        ),
    );
  const hash = createHash('sha256');
  for (const file of [...new Set(files)].sort()) {
    hash.update(file + '\0');
    try {
      hash.update(await readFile(resolve(root, file)));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      hash.update('DELETED');
    }
    hash.update('\0');
  }
  return hash.digest('hex');
}

export async function auditClaims({
  root = process.cwd(),
  requireEvidence = false,
  evidencePath = 'artifacts/validation/report.json',
  manifest,
} = {}) {
  const errors = [];
  const register =
    manifest || JSON.parse(await readFile(resolve(root, 'CLAIMS_REGISTER.yaml'), 'utf8'));
  if (register.schemaVersion !== 1 || !Array.isArray(register.claims) || !register.claims.length)
    errors.push('Invalid claims schema');
  const seen = new Set();
  for (const claim of register.claims || []) {
    const id = claim.CLAIM_ID || '(missing id)';
    for (const field of requiredFields)
      if (claim[field] === undefined || claim[field] === '') errors.push(`${id}: missing ${field}`);
    if (seen.has(id)) errors.push(`${id}: duplicate ID`);
    seen.add(id);
    if (!statuses.has(claim.STATUS)) errors.push(`${id}: invalid status`);
    if (!Array.isArray(claim.IMPLEMENTATION) || !Array.isArray(claim.TEST))
      errors.push(`${id}: implementation and test must be arrays`);
    if (unsupported.test(claim.CLAIM_TEXT || '') && claim.STATUS !== 'NOT_SUPPORTED')
      errors.push(`${id}: unsupported assurance or novelty claim`);
    // This prototype has no independently provisioned approval trust source. A self-authored field is not approval.
    if (claim.STATUS === 'EXTERNALLY_APPROVED')
      errors.push(`${id}: external approval cannot be established by the native validator`);
    for (const file of [
      ...(Array.isArray(claim.IMPLEMENTATION) ? claim.IMPLEMENTATION : []),
      ...(Array.isArray(claim.TEST) ? claim.TEST : []),
    ]) {
      if (typeof file !== 'string' || file.startsWith('/') || file.split(/[\\/]/).includes('..')) {
        errors.push(`${id}: unsafe evidence path`);
        continue;
      }
      try {
        if (!(await stat(resolve(root, file))).isFile())
          errors.push(`${id}: evidence is not a file: ${file}`);
      } catch {
        errors.push(`${id}: missing file ${file}`);
      }
    }
    if (['TESTED', 'MEASURED'].includes(claim.STATUS) && !(claim.TEST || []).length)
      errors.push(`${id}: tested claim has no test mapping`);
  }
  let report;
  if (requireEvidence) {
    try {
      report = JSON.parse(await readFile(resolve(root, evidencePath), 'utf8'));
    } catch {
      errors.push('Fresh validator evidence missing or unreadable');
    }
    if (report) {
      if (
        report.schemaVersion !== 1 ||
        report.kind !== 'native-validation' ||
        report.outcome !== 'PASS'
      )
        errors.push('Validator did not pass');
      const digest = await sourceDigest(root);
      if (report.sourceDigest !== digest || report.sourceDigestAfter !== digest)
        errors.push('Evidence is stale: source digest mismatch');
      if (
        !/^[0-9a-f]{40,64}$/.test(report.gitCommit || '') ||
        typeof report.workingTreeStatus !== 'string'
      )
        errors.push('Missing execution revision metadata');
      if (
        !Number.isFinite(Date.parse(report.startedAt)) ||
        !Number.isFinite(Date.parse(report.finishedAt))
      )
        errors.push('Missing execution timestamps');
      for (const name of requiredGates) {
        const matching = (report.gates || []).filter((g) => g.name === name);
        if (matching.length !== 1 || matching[0].exitCode !== 0 || matching[0].outcome !== 'PASS')
          errors.push(`Required gate did not pass: ${name}`);
      }
      if (
        !(report.tests?.total > 0) ||
        report.tests.failed !== 0 ||
        report.tests.cancelled !== 0 ||
        report.tests.skipped !== 0
      )
        errors.push('Test execution counts missing or failures/skips present');
      if (
        !(report.demo?.total >= 9) ||
        report.demo.failed !== 0 ||
        report.demo.passed !== report.demo.total
      )
        errors.push('Demonstration stages did not all pass');
      for (const key of ['container', 'hostedSast', 'browser'])
        if (report.externalObservations?.[key] !== 'NOT_OBSERVED')
          errors.push(`Native validation cannot assert ${key} observation`);
      if (
        (register.claims || []).some((c) => c.STATUS === 'MEASURED') &&
        !(report.gates || []).some(
          (g) => g.name === 'benchmark' && g.exitCode === 0 && g.outcome === 'PASS',
        )
      )
        errors.push('Measured claim requires a fresh benchmark gate');
    }
  }
  return {
    valid: errors.length === 0,
    mode: requireEvidence ? 'EXECUTION_EVIDENCE_CHECKED' : 'MANIFEST_ONLY_NOT_TEST_PROOF',
    claims: (register.claims || []).length,
    errors,
    trustBoundary:
      'Local records are not independent attestation; reviewer must trust the runner and inspect logs.',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = await auditClaims({
      requireEvidence: process.argv.includes('--require-evidence'),
    });
    console.log(JSON.stringify(result, null, 2));
    if (!result.valid) process.exitCode = 1;
  } catch (error) {
    console.error('Claims audit failed: ' + error.message);
    process.exitCode = 1;
  }
}
