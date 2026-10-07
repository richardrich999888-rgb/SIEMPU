import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { auditClaims, sourceDigest, requiredGates } from '../scripts/audit-claims.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'siepmu-claims-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  execFileSync('git', ['init', '-q'], { cwd: root });
  await mkdir(join(root, 'services'));
  await writeFile(join(root, 'services/example.mjs'), 'export const value = 1;\n');
  const manifest = {
    schemaVersion: 1,
    claims: [
      {
        CLAIM_ID: 'T01',
        CLAIM_TEXT: 'Synthetic test behavior.',
        STATUS: 'TESTED',
        SOURCE: 'Synthetic fixture',
        IMPLEMENTATION: ['services/example.mjs'],
        COMMIT: 'Runtime report',
        TEST: ['services/example.mjs'],
        RESULT: 'Conditional on execution',
        EVIDENCE: 'report.json',
        DATE: 'Runtime report',
        LIMITATION: 'No certification',
      },
    ],
  };
  await writeFile(join(root, 'CLAIMS_REGISTER.yaml'), JSON.stringify(manifest));
  const digest = await sourceDigest(root);
  const report = {
    schemaVersion: 1,
    kind: 'native-validation',
    outcome: 'PASS',
    gitCommit: 'a'.repeat(40),
    workingTreeStatus: '?? services/',
    sourceDigest: digest,
    sourceDigestAfter: digest,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    gates: requiredGates.map((name) => ({ name, outcome: 'PASS', exitCode: 0 })),
    tests: { total: 1, failed: 0, skipped: 0, cancelled: 0 },
    demo: { total: 9, passed: 9, failed: 0 },
    externalObservations: {
      browser: 'NOT_OBSERVED',
      container: 'NOT_OBSERVED',
      hostedSast: 'NOT_OBSERVED',
    },
  };
  const save = () => writeFile(join(root, 'report.json'), JSON.stringify(report));
  await save();
  return {
    root,
    manifest,
    report,
    save,
    audit: () => auditClaims({ root, requireEvidence: true, evidencePath: 'report.json' }),
  };
}

test('claims schema audit is explicitly not execution evidence; strict gate accepts complete matching synthetic metadata', async (t) => {
  const f = await fixture(t);
  const ordinary = await auditClaims({ root: f.root });
  assert.equal(ordinary.valid, true);
  assert.equal(ordinary.mode, 'MANIFEST_ONLY_NOT_TEST_PROOF');
  assert.equal((await f.audit()).valid, true);
});

test('claims gate rejects stale source including new untracked source and lockfile changes', async (t) => {
  const f = await fixture(t);
  await writeFile(join(f.root, 'services/new.mjs'), 'export const altered = true;');
  assert.ok((await f.audit()).errors.some((e) => e.includes('stale')));
  await rm(join(f.root, 'services/new.mjs'));
  await writeFile(join(f.root, 'package-lock.json'), '{}');
  assert.ok((await f.audit()).errors.some((e) => e.includes('stale')));
});

test('claims gate rejects missing, failed, skipped or incomplete execution and fabricated external observations', async (t) => {
  const f = await fixture(t);
  for (const mutate of [
    (r) => {
      r.gates[0].exitCode = 1;
    },
    (r) => {
      r.tests.failed = 1;
    },
    (r) => {
      r.tests.skipped = 1;
    },
    (r) => {
      r.demo.passed = 8;
    },
    (r) => {
      r.externalObservations.hostedSast = 'PASS';
    },
  ]) {
    const original = structuredClone(f.report);
    mutate(f.report);
    await f.save();
    assert.equal((await f.audit()).valid, false);
    Object.assign(f.report, original);
  }
  await rm(join(f.root, 'report.json'));
  assert.equal((await f.audit()).valid, false);
});

test('claims gate rejects invented certification, self-certified external approval and unsafe file paths', async (t) => {
  const f = await fixture(t);
  f.manifest.claims[0].CLAIM_TEXT = 'SAG certified';
  assert.equal((await auditClaims({ root: f.root, manifest: f.manifest })).valid, false);
  f.manifest.claims[0].CLAIM_TEXT = 'Approved by an external body';
  f.manifest.claims[0].STATUS = 'EXTERNALLY_APPROVED';
  assert.equal((await auditClaims({ root: f.root, manifest: f.manifest })).valid, false);
  f.manifest.claims[0].STATUS = 'TESTED';
  f.manifest.claims[0].IMPLEMENTATION = ['../outside.mjs'];
  assert.equal((await auditClaims({ root: f.root, manifest: f.manifest })).valid, false);
});
