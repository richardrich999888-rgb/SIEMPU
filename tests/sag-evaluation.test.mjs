import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
  symlinkSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { buildEvaluationPackage, snapshot } from '../assurance/sag/package.mjs';
import { verifyEvaluationPackage } from '../assurance/sag/verify.mjs';
import {
  encode,
  sha256,
  GATES,
  assessment,
  validateCatalogue,
  sourcePathAllowed,
} from '../assurance/sag/format.mjs';
import { sourceDigest } from '../scripts/audit-claims.mjs';

const repo = resolve('.');
const requests = JSON.parse(readFileSync(join(repo, 'assurance/sag/requests.json')));
const git = (root, ...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
function put(root, path, bytes) {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), bytes, { mode: 0o600 });
}
async function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-evaluation-fixture-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  put(root, '.gitignore', 'artifacts/\ndist/\n.data/\n');
  put(root, 'apps/fixture.mjs', '// Synthetic package-format fixture, not a tested application.\n');
  put(root, 'tests/fixture.test.mjs', '// Synthetic validation-report fixture.\n');
  put(root, 'package.json', encode({ name: 'synthetic-evaluation-fixture', private: true }));
  put(root, 'assurance/sag/requests.json', encode(requests));
  const sources = ['apps/fixture.mjs'],
    tests = ['tests/fixture.test.mjs'];
  const catalogue = {
    schemaVersion: 1,
    kind: 'APPLICANT_CRYPTO_INVENTORY',
    reviewDate: '2026-11-07',
    coverage: 'Test fixture only.',
    components: [
      {
        id: 'FIXTURE',
        purpose: 'Fixture',
        mechanisms: ['fixture'],
        boundary: 'Fixture',
        deploymentScope: 'APPLICATION',
        custody: 'None',
        limitations: 'Not real evidence.',
        sources,
        tests,
      },
    ],
    sourceBindings: Object.fromEntries(
      [...sources, ...tests].map((p) => [p, { sha256: sha256(readFileSync(join(root, p))) }]),
    ),
  };
  put(root, 'assurance/sag/catalogue.json', encode(catalogue));
  git(root, 'init', '--quiet');
  git(root, 'config', 'user.email', 'fixture@example.invalid');
  git(root, 'config', 'user.name', 'Synthetic test fixture');
  git(root, 'add', '.');
  git(
    root,
    '-c',
    'commit.gpgsign=false',
    '-c',
    'core.hooksPath=/dev/null',
    'commit',
    '--quiet',
    '-m',
    'Synthetic fixture',
  );
  const startedAt = new Date(Date.now() - 1000).toISOString(),
    finishedAt = new Date().toISOString();
  const digest = await sourceDigest(root);
  const report = {
    schemaVersion: 1,
    kind: 'native-validation',
    outcome: 'PASS',
    gitCommit: git(root, 'rev-parse', 'HEAD'),
    workingTreeStatus: '',
    sourceDigest: digest,
    sourceDigestAfter: digest,
    startedAt,
    finishedAt,
    runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    tests: { total: 1, failed: 0, skipped: 0, cancelled: 0 },
    claimsAudit: { valid: true },
    gates: GATES.map((name) => ({
      name,
      outcome: 'PASS',
      exitCode: 0,
      log: `artifacts/validation/${name.replaceAll(':', '-')}.log`,
    })),
  };
  put(root, 'artifacts/validation/report.json', encode(report));
  for (const g of report.gates) put(root, g.log, 'Synthetic report fixture; no execution claim.\n');
  put(
    root,
    'artifacts/application.cdx.json',
    encode({
      bomFormat: 'CycloneDX',
      metadata: { timestamp: finishedAt, component: { name: 'synthetic-evaluation-fixture' } },
    }),
  );
  const app = readFileSync(join(root, 'apps/fixture.mjs'));
  put(root, 'dist/apps/fixture.mjs', app);
  put(
    root,
    'dist/manifest.json',
    encode({
      schemaVersion: 1,
      files: [{ file: 'apps/fixture.mjs', bytes: app.length, sha256: sha256(app) }],
    }),
  );
  return { root, report, catalogue };
}

test('test discovery covers tracked tests and never executes copied package tests', (t) => {
  const scripts = JSON.parse(readFileSync(join(repo, 'package.json'))).scripts;
  const patterns = [...scripts.test.matchAll(/'([^']+)'/g)].map((m) => m[1]);
  const roots = patterns.map((p) => p.replace('/**/*.test.mjs', ''));
  assert.ok(patterns.every((p, i) => p === `${roots[i]}/**/*.test.mjs`));
  assert.ok(roots.length > 0 && roots.every((r) => /^[a-z]+$/.test(r)));
  assert.ok(scripts['test:coverage'].endsWith(' ' + patterns.map((p) => `'${p}'`).join(' ')));
  const tracked = git(repo, 'ls-files', '*.test.mjs').split('\n');
  assert.ok(tracked.length > 0);
  for (const path of tracked)
    assert.ok(
      roots.some((r) => path.startsWith(`${r}/`)),
      `Undiscovered test: ${path}`,
    );
  const root = mkdtempSync(join(tmpdir(), 'siepmu-test-discovery-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const r of roots) mkdirSync(join(root, r));
  for (const r of roots)
    put(
      root,
      `${r}/nested/real.test.mjs`,
      "import test from 'node:test'; test('real source test', () => {});\n",
    );
  const copied = "throw new Error('COPIED_PACKAGE_TEST_EXECUTED');\n";
  put(root, 'artifacts/sag-evaluation/source/tests/copied.test.mjs', copied);
  put(root, 'dist/apps/copied.test.mjs', copied);
  const run = (args) =>
    spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...args], {
      cwd: root,
      encoding: 'utf8',
      timeout: 10000,
      env: Object.fromEntries(
        Object.entries(process.env).filter(([k]) => !k.startsWith('NODE_TEST_')),
      ),
    });
  // Positive control: the old automatic discovery really executes the bad copies.
  const broad = run([]);
  assert.equal(broad.status, 1, broad.stderr);
  assert.match(broad.stdout, /COPIED_PACKAGE_TEST_EXECUTED/);
  const scoped = run(patterns);
  assert.equal(scoped.status, 0, scoped.stdout + scoped.stderr);
  assert.match(scoped.stdout, /real source test/);
  assert.doesNotMatch(scoped.stdout, /COPIED_PACKAGE_TEST_EXECUTED/);
});

test('reviewed crypto inventory includes application, laboratory and optional tools and matches source bytes', () => {
  const c = JSON.parse(readFileSync('assurance/sag/catalogue.json'));
  const source = new Map(Object.keys(c.sourceBindings).map((p) => [p, readFileSync(p)]));
  assert.equal(validateCatalogue(c, source), c);
  assert.equal(c.components.length, 17);
  assert.ok(c.components.some((v) => v.mechanisms.some((m) => m.includes('TOTP HMAC-SHA1'))));
  assert.deepEqual(
    new Set(c.components.map((v) => v.deploymentScope)),
    new Set(['APPLICATION', 'LAB_ONLY', 'OPTIONAL_OFFLINE_TOOL']),
  );
  const malformed = structuredClone(c);
  const first = Object.keys(malformed.sourceBindings)[0];
  malformed.sourceBindings[first] = malformed.sourceBindings[first].sha256;
  assert.throws(() => validateCatalogue(malformed, source), /INVALID_SCHEMA/);
  source.set('packages/crypto/crypto.mjs', Buffer.from('unreviewed change'));
  assert.throws(() => validateCatalogue(c, source), /CRYPTO_REVIEW_DRIFT/);
  assert.throws(() => validateCatalogue({ ...c, sagGraded: true }, source), /INVALID_MEMBERS/);
});

test('scope references never confer grading, including when all reference fields are populated', () => {
  assert.equal(assessment(requests).missingInputs.length, 12);
  const supplied = structuredClone(requests);
  for (const r of supplied.requests) r.publicReference = 'UNVERIFIED-SYNTHETIC-REFERENCE';
  const result = assessment(supplied);
  assert.equal(result.missingInputs.length, 0);
  assert.equal(result.sagGrading, 'NOT_ESTABLISHED');
  assert.equal(result.operationalAuthorization, 'NOT_ESTABLISHED');
  assert.ok(result.requests.every((r) => r.status === 'REFERENCE_SUPPLIED_UNVERIFIED'));
  supplied.requests[0].approved = true;
  assert.throws(() => assessment(supplied), /INVALID_MEMBERS/);
  supplied.requests[0] = supplied.requests[1];
  assert.throws(() => assessment(supplied), /REQUEST_SET/);
});

test('candidate package is repeatable, independently verifiable and excludes ignored runtime secrets', async (t) => {
  const f = await fixture(t);
  put(f.root, '.data/master.key', 'SYNTHETIC_SECRET_CANARY');
  const first = await buildEvaluationPackage(f.root, 'artifacts/first');
  const second = await buildEvaluationPackage(f.root, 'artifacts/second');
  assert.equal(first.manifestSha256, second.manifestSha256);
  assert.equal(first.sagGrading, 'NOT_ESTABLISHED');
  assert.equal(statSync(join(f.root, 'artifacts/first/manifest.json')).mode & 0o777, 0o600);
  const m = JSON.parse(readFileSync(join(f.root, 'artifacts/first/manifest.json')));
  assert.ok(!m.files.some((x) => x.path.includes('.data') || x.path.endsWith('.key')));
  const child = spawnSync(
    process.execPath,
    [join(repo, 'assurance/sag/verify.mjs'), join(f.root, 'artifacts/first'), first.manifestSha256],
    { encoding: 'utf8', timeout: 10000, cwd: tmpdir() },
  );
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(child.stdout).integrity, 'MATCHES_EXPECTED_DIGEST');
  await assert.rejects(
    buildEvaluationPackage(f.root, 'artifacts/first'),
    /NEW_ARTIFACT_DESTINATION_REQUIRED/,
  );
});

test('tampering, manifest replacement, unlisted files and self-awarded grades are rejected', async (t) => {
  const f = await fixture(t),
    built = await buildEvaluationPackage(f.root, 'artifacts/package');
  const dir = join(f.root, 'artifacts/package'),
    file = join(dir, 'application/apps/fixture.mjs');
  const original = readFileSync(file);
  writeFileSync(file, 'tampered');
  assert.throws(() => verifyEvaluationPackage(dir, built.manifestSha256), /FILE_DIGEST_MISMATCH/);
  writeFileSync(file, original);
  put(dir, 'extra.txt', 'unlisted');
  assert.throws(
    () => verifyEvaluationPackage(dir, built.manifestSha256),
    /UNLISTED_OR_MISSING_FILE/,
  );
  rmSync(join(dir, 'extra.txt'));
  const m = JSON.parse(readFileSync(join(dir, 'manifest.json')));
  m.sagGrading = 'SELF_AWARDED';
  writeFileSync(join(dir, 'manifest.json'), encode(m));
  assert.throws(
    () => verifyEvaluationPackage(dir, built.manifestSha256),
    /MANIFEST_DIGEST_MISMATCH/,
  );
  assert.throws(() => verifyEvaluationPackage(dir, sha256(encode(m))), /SELF_APPROVAL_FORBIDDEN/);
  assert.throws(() => verifyEvaluationPackage(dir), /INDEPENDENT_MANIFEST_DIGEST_REQUIRED/);
});

test('verifier rejects traversal, duplicate entries, symlinks and forged internal inventories', async (t) => {
  const f = await fixture(t),
    built = await buildEvaluationPackage(f.root, 'artifacts/package');
  const dir = join(f.root, 'artifacts/package'),
    original = JSON.parse(readFileSync(join(dir, 'manifest.json')));
  for (const mutate of [
    (m) => {
      m.files[0].path = '../escape';
    },
    (m) => {
      m.files.push(m.files[0]);
    },
  ]) {
    const m = structuredClone(original);
    mutate(m);
    writeFileSync(join(dir, 'manifest.json'), encode(m));
    assert.throws(() => verifyEvaluationPackage(dir, sha256(encode(m))), /MANIFEST_PATH/);
  }
  writeFileSync(join(dir, 'manifest.json'), encode(original));
  symlinkSync(join(f.root, '.git'), join(dir, 'link'));
  assert.throws(() => verifyEvaluationPackage(dir, built.manifestSha256), /SYMLINK_FORBIDDEN/);
  rmSync(join(dir, 'link'));
  const bad = JSON.parse(readFileSync(join(dir, 'crypto-inventory.json')));
  bad.components[0].purpose = 'invented';
  const bytes = encode(bad),
    m = structuredClone(original);
  const entry = m.files.find((e) => e.path === 'crypto-inventory.json');
  entry.sha256 = sha256(bytes);
  entry.size = bytes.length;
  writeFileSync(join(dir, 'crypto-inventory.json'), bytes);
  writeFileSync(join(dir, 'manifest.json'), encode(m));
  assert.throws(() => verifyEvaluationPackage(dir, sha256(encode(m))), /INVENTORY_SOURCE_MISMATCH/);
});

test('packager requires a clean commit, including edits hidden from git status', async (t) => {
  const f = await fixture(t);
  put(f.root, 'unexpected.txt', 'untracked');
  await assert.rejects(
    buildEvaluationPackage(f.root, 'artifacts/one'),
    /CLEAN_COMMITTED_TREE_REQUIRED/,
  );
  rmSync(join(f.root, 'unexpected.txt'));
  git(f.root, 'update-index', '--assume-unchanged', 'apps/fixture.mjs');
  put(f.root, 'apps/fixture.mjs', 'hidden change');
  assert.throws(() => snapshot(f.root), /WORKTREE_DIFFERS_FROM_COMMIT/);
});

test('offline verification reconstructs Git source identity rather than trusting declared revision text', async (t) => {
  const f = await fixture(t),
    built = await buildEvaluationPackage(f.root, 'artifacts/package');
  const dir = join(f.root, 'artifacts/package');
  const original = JSON.parse(readFileSync(join(dir, 'manifest.json')));
  assert.equal(
    verifyEvaluationPackage(dir, built.manifestSha256).gitCommit,
    git(f.root, 'rev-parse', 'HEAD'),
  );
  for (const [field, error] of [
    ['gitCommit', /GIT_COMMIT_MISMATCH/],
    ['gitTree', /GIT_TREE_MISMATCH/],
  ]) {
    const manifest = structuredClone(original);
    manifest[field] = '0'.repeat(40);
    writeFileSync(join(dir, 'manifest.json'), encode(manifest));
    assert.throws(() => verifyEvaluationPackage(dir, sha256(encode(manifest))), error);
  }
});

test('failed, stale, skipped and malformed validation evidence cannot be packaged', async (t) => {
  const f = await fixture(t);
  const mutations = [
    (r) => {
      r.outcome = 'FAIL';
    },
    (r) => {
      r.gitCommit = '0'.repeat(40);
    },
    (r) => {
      r.workingTreeStatus = 'modified';
    },
    (r) => {
      r.sourceDigestAfter = '0'.repeat(64);
    },
    (r) => {
      r.runtime.node = 'wrong';
    },
    (r) => {
      r.tests.skipped = 1;
    },
    (r) => {
      r.gates[0].outcome = 'FAIL';
    },
    (r) => {
      r.gates[0].log = '.data/master.key';
    },
    (r) => {
      r.gates[0] = r.gates[1];
    },
    (r) => {
      r.claimsAudit.valid = false;
    },
  ];
  for (const mutate of mutations) {
    const report = structuredClone(f.report);
    mutate(report);
    put(f.root, 'artifacts/validation/report.json', encode(report));
    await assert.rejects(buildEvaluationPackage(f.root, 'artifacts/rejected'), /VALIDATION_/);
  }
});

test('stale SBOM, changed application, extra build files and unsafe destinations fail closed', async (t) => {
  const f = await fixture(t);
  const bom = JSON.parse(readFileSync(join(f.root, 'artifacts/application.cdx.json')));
  const stale = structuredClone(bom);
  stale.metadata.timestamp = '2000-01-01T00:00:00Z';
  put(f.root, 'artifacts/application.cdx.json', encode(stale));
  await assert.rejects(buildEvaluationPackage(f.root, 'artifacts/a'), /STALE_SBOM/);
  put(f.root, 'artifacts/application.cdx.json', encode(bom));
  put(f.root, 'dist/apps/fixture.mjs', 'changed build');
  await assert.rejects(buildEvaluationPackage(f.root, 'artifacts/a'), /BUILD_SOURCE_MISMATCH/);
  put(f.root, 'dist/apps/fixture.mjs', readFileSync(join(f.root, 'apps/fixture.mjs')));
  put(f.root, 'dist/secret.txt', 'SYNTHETIC');
  await assert.rejects(buildEvaluationPackage(f.root, 'artifacts/a'), /UNLISTED_BUILD_FILE/);
  await assert.rejects(
    buildEvaluationPackage(f.root, '../outside'),
    /NEW_ARTIFACT_DESTINATION_REQUIRED/,
  );
  symlinkSync(tmpdir(), join(f.root, 'artifacts/link'));
  await assert.rejects(
    buildEvaluationPackage(f.root, 'artifacts/link/out'),
    /UNSAFE_OUTPUT_DIRECTORY/,
  );
  for (const p of [
    '.data/file',
    'server-key.json',
    'a.key',
    '../secret',
    '.env',
    'native/target/file',
  ])
    assert.equal(sourcePathAllowed(p), false);
  assert.equal(sourcePathAllowed('.env.example'), true);
});
