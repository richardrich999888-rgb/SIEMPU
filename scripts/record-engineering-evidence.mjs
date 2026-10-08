import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { sourceDigest } from './audit-claims.mjs';

const verified = process.argv.includes('--verified');
if (!verified) throw new Error('Evidence recording requires an explicit successful-gate marker');
const revision = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
const sourceBoundDigest = await sourceDigest();
const tests = [
  ['T5-01', 'node --test tests/acceptance/vertical-slice/*.test.mjs', 'PASS'],
  ['T5-02', 'node deployment/testbed/run.mjs', 'CI_REQUIRED'],
  ['T5-03', 'node --test tests/recovery.test.mjs tests/filed-mission-authority.test.mjs', 'PASS'],
  ['T5-04', 'node --test tests/monitoring.test.mjs tests/independent-services.test.mjs', 'PASS'],
  ['T5-05', 'node --test tests/recovery.test.mjs apps/unit-client/*.test.mjs', 'PASS'],
  ['T5-06', 'node --test tests/independent-services.test.mjs', 'PASS'],
  ['T5-07', 'node --test tests/checkpoint-custody.test.mjs tests/recovery.test.mjs', 'PASS'],
  [
    'TLS-01',
    'node --test tests/transport/tls.test.mjs tests/transport/secure-stack.test.mjs',
    'PASS',
  ],
  ['T5-09/T5-11', 'node deployment/testbed/run.mjs', 'CI_REQUIRED'],
  ['T5-12', 'node --test tests/crypto-provider.test.mjs tests/crypto.test.mjs', 'PASS'],
  [
    'T5-13',
    'node --test tests/flash-approval.test.mjs tests/filed-mission-policy.test.mjs',
    'PASS',
  ],
  [
    'SAG-01',
    'Authorised cryptographic authority decision for exact deployed configuration',
    'EXTERNAL_BLOCKED',
  ],
  ['T5-08', 'Independent assessor review and sponsor acceptance', 'EXTERNAL_BLOCKED'],
];
const evidence = {
  format: 'SIEPMU_ENGINEERING_EVIDENCE_V1',
  revision,
  generatedAt: new Date().toISOString(),
  node: process.version,
  packageVersion: packageJson.version,
  sourceDigest: sourceBoundDigest,
  evidencePolicy:
    'Only commands already passed in this candidate are marked PASS; hosted impairment and external decisions remain separate.',
  tests: tests.map(([id, command, status]) => ({
    id,
    command,
    status,
    environment:
      status === 'CI_REQUIRED'
        ? 'Hosted Linux runner with Docker, sudo, nsenter and tc'
        : status === 'EXTERNAL_BLOCKED'
          ? 'External authority or independent assessor'
          : 'Node native laboratory runner',
    result: status === 'PASS' ? 'Executed by the candidate gate' : undefined,
  })),
  limitations: [
    'No hardware-backed key test was available in this workspace.',
    'WebCrypto and Node providers are software demonstrations and do not establish SAG grading.',
    'No external IAF, SAG, STQC, CERT-In or independent assessor decision is represented.',
  ],
};
await mkdir(resolve('artifacts/validation'), { recursive: true });
await writeFile(
  'artifacts/validation/engineering-evidence.json',
  JSON.stringify(evidence, null, 2) + '\n',
);
console.log(JSON.stringify({ status: 'EVIDENCE_RECORDED', revision, tests: tests.length }));
