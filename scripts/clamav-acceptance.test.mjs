// Evidence-gate regressions only. These do not run or emulate successful native detection.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, chmod, rm, statfs, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  databaseInventory,
  fileHash,
  requirePrivateTmpfs,
  runAcceptance,
  requireReviewedVersion,
  testOutcome,
} from './clamav-acceptance.mjs';

const summary = '# tests 3\n# pass 3\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';

test('acceptance evidence requires the complete three-case summary and successful exit', () => {
  assert.equal(testOutcome(summary, 0).outcome, 'PASS');
  assert.deepEqual(testOutcome('FILE_INSPECTION_INCOMPLETE\n' + summary, 1).failureCodes, [
    'FILE_INSPECTION_INCOMPLETE',
  ]);
  for (const output of [
    '',
    summary.replace('# pass 3', '# pass 2'),
    summary.replace('# skipped 0', '# skipped 1'),
    summary + '# tests 3\n',
    summary.replace('# todo 0\n', ''),
  ])
    assert.equal(testOutcome(output, 0).outcome, 'FAIL');
  for (const exit of [1, null, 137]) assert.equal(testOutcome(summary, exit).outcome, 'FAIL');
});

test('acceptance rejects old, unknown and ambiguous engine versions', () => {
  assert.equal(requireReviewedVersion('ClamAV 1.5.4\n'), '1.5.4');
  assert.equal(requireReviewedVersion('ClamAV 1.5.4/12345/Sun Nov 8 00:00:00 2026\n'), '1.5.4');
  for (const output of [
    'ClamAV 1.5.3\n',
    'ClamAV 1.5.40\n',
    'ClamAV 2.0.0\n',
    'ClamAV 1.5.4\nwarning\n',
    '',
  ])
    assert.throws(() => requireReviewedVersion(output), { code: 'ACCEPTANCE_ENGINE_VERSION' });
});

test('acceptance refuses missing, empty, ambiguous and symlink database files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'clamav-inventory-'));
  try {
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_MISSING' });
    await writeFile(join(dir, 'main.cvd'), '');
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_FILE' });
    await writeFile(join(dir, 'main.cvd'), 'inventory-only-not-a-signature');
    await writeFile(join(dir, 'daily.cvd'), 'inventory-only-not-a-signature');
    const inventory = await databaseInventory(dir);
    assert.equal(inventory.length, 2);
    assert.equal(inventory[0].sha256, await fileHash(join(dir, 'main.cvd')));
    await writeFile(join(dir, 'main.cld'), 'ambiguous');
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_AMBIGUOUS' });
    await rm(join(dir, 'main.cld'));
    await writeFile(join(dir, 'other.cvd'), 'unexpected');
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_UNEXPECTED_FILE' });
    await rm(join(dir, 'other.cvd'));
    await writeFile(join(dir, 'main.cvd'), 'ClamAV-VDB:synthetic:63:not-an-authentic-database');
    await writeFile(join(dir, 'main-63.cvd.sign'), 'inventory-only-not-a-signature');
    assert.equal((await databaseInventory(dir)).length, 3);
    await writeFile(join(dir, 'bytecode-339.cvd.sign'), 'orphan');
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_FILE' });
    await rm(join(dir, 'bytecode-339.cvd.sign'));
    await rm(join(dir, 'daily.cvd'));
    await symlink(join(dir, 'main.cvd'), join(dir, 'daily.cvd'));
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_FILE' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('versioned signature sidecars must match the database header; unsupported names remain refused', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'clamav-sidecar-'));
  try {
    await writeFile(join(dir, 'main.cvd'), 'ClamAV-VDB:synthetic:63:not-an-authentic-database');
    await writeFile(join(dir, 'daily.cvd'), 'ClamAV-VDB:synthetic:28177:not-an-authentic-database');
    await writeFile(join(dir, 'main-64.cvd.sign'), 'inventory-only-not-a-signature');
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_SIDECAR_VERSION' });
    await rm(join(dir, 'main-64.cvd.sign'));
    await writeFile(join(dir, 'main.cvd.sign'), 'unsupported-name');
    await assert.rejects(databaseInventory(dir), { code: 'ACCEPTANCE_DATABASE_UNEXPECTED_FILE' });
    await rm(join(dir, 'main.cvd.sign'));
    await writeFile(join(dir, 'main-63.cvd.sign'), 'inventory-only-not-a-signature');
    assert.equal((await databaseInventory(dir)).length, 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('acceptance refuses shared or linked temporary roots before scanning', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'clamav-permissions-'));
  try {
    await chmod(dir, 0o755);
    await assert.rejects(requirePrivateTmpfs(dir), {
      code: process.platform === 'linux' ? 'ACCEPTANCE_TEMP_PERMISSIONS' : 'ACCEPTANCE_PLATFORM',
    });
    await symlink(dir, join(dir, 'linked'));
    await assert.rejects(requirePrivateTmpfs(join(dir, 'linked')), {
      code: process.platform === 'linux' ? 'ACCEPTANCE_TEMP_PERMISSIONS' : 'ACCEPTANCE_PLATFORM',
    });
    await chmod(dir, 0o700);
    if (process.platform === 'linux') {
      if ((await statfs(dir)).type === 0x01021994) await requirePrivateTmpfs(dir);
      else await assert.rejects(requirePrivateTmpfs(dir), { code: 'ACCEPTANCE_TEMP_NOT_TMPFS' });
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('unavailable acceptance configuration writes a blocked report without paths or native pass', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'clamav-report-'));
  try {
    const destination = join(dir, 'run');
    const report = await runAcceptance(join(dir, 'missing.json'), destination);
    assert.equal(report.outcome, 'BLOCKED');
    assert.equal(report.nativeTests.outcome, 'NOT_EXECUTED');
    assert.equal(report.reason, 'ACCEPTANCE_PREREQUISITE_ERROR');
    const saved = await readFile(join(destination, 'report.json'), 'utf8');
    assert.equal(saved.includes(dir), false);
    assert.deepEqual(JSON.parse(saved), report);
    await assert.rejects(runAcceptance(join(dir, 'missing.json'), destination), { code: 'EEXIST' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
