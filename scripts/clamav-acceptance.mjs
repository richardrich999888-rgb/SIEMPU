// Explicit Linux laboratory gate. Does not install software or qualify a deployment.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, readdir, statfs, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ClamAvInspector } from '../packages/file-inspection/clamav.mjs';
import { sourceDigest } from './audit-claims.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const failure = (code) => Object.assign(new Error(code), { code });
const cleanEnvironment = { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' };

export async function fileHash(path) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(path)) hash.update(bytes);
  return hash.digest('hex');
}

export function requireReviewedVersion(output) {
  // Exact laboratory selection, not a promise that this version has no vulnerabilities.
  // New versions require advisory review and a new native acceptance record.
  if (!/^ClamAV 1\.5\.4(?:\/[^\r\n]+)?\n?$/.test(output))
    throw failure('ACCEPTANCE_ENGINE_VERSION');
  return '1.5.4';
}

export async function requirePrivateTmpfs(path) {
  if (process.platform !== 'linux') throw failure('ACCEPTANCE_PLATFORM');
  const info = await lstat(path);
  if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o7777) !== 0o700)
    throw failure('ACCEPTANCE_TEMP_PERMISSIONS');
  if ((await statfs(path)).type !== 0x01021994) throw failure('ACCEPTANCE_TEMP_NOT_TMPFS');
}

export async function databaseInventory(database) {
  const records = [];
  // Use a dedicated snapshot directory, not an updater's live working directory.
  const names = await readdir(database);
  if (names.some((name) => !/^(main|daily|bytecode)\.(cvd|cld)(\.sign)?$/.test(name)))
    throw failure('ACCEPTANCE_DATABASE_UNEXPECTED_FILE');
  for (const name of ['main', 'daily', 'bytecode']) {
    const found = [];
    for (const extension of ['cvd', 'cld']) {
      const filename = `${name}.${extension}`;
      const path = resolve(database, filename);
      let info;
      try {
        info = await lstat(path);
      } catch (error) {
        if (error.code === 'ENOENT') continue;
        throw error;
      }
      if (!info.isFile() || info.size === 0) throw failure('ACCEPTANCE_DATABASE_FILE');
      found.push({ filename, bytes: info.size, sha256: await fileHash(path) });
    }
    if (found.length > 1) throw failure('ACCEPTANCE_DATABASE_AMBIGUOUS');
    if (!found.length && name !== 'bytecode') throw failure('ACCEPTANCE_DATABASE_MISSING');
    records.push(...found);
  }
  for (const filename of names.filter((name) => name.endsWith('.sign')).sort()) {
    if (!names.includes(filename.slice(0, -5))) throw failure('ACCEPTANCE_DATABASE_FILE');
    const path = resolve(database, filename);
    const info = await lstat(path);
    if (!info.isFile() || info.size === 0) throw failure('ACCEPTANCE_DATABASE_FILE');
    records.push({ filename, bytes: info.size, sha256: await fileHash(path) });
  }
  // Inventory is not signature validation. The native scanner must enforce official/fresh DBs.
  return records;
}

export function testOutcome(output, exitCode) {
  const counts = {};
  for (const label of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const matches = [...output.matchAll(new RegExp(`^# ${label} (\\d+)$`, 'gm'))];
    counts[label] = matches.length === 1 ? Number(matches[0][1]) : null;
  }
  const passed =
    exitCode === 0 &&
    counts.tests === 3 &&
    counts.pass === 3 &&
    ['fail', 'cancelled', 'skipped', 'todo'].every((key) => counts[key] === 0);
  return {
    outcome: passed ? 'PASS' : 'FAIL',
    exitCode,
    counts,
    failureCodes: [...new Set(output.match(/FILE_INSPECTION_[A-Z_]+/g) ?? [])].sort(),
  };
}

export async function runAcceptance(configuration, destination) {
  // Refuse to replace an earlier run. Reports contain synthetic tests and hashes only.
  await mkdir(destination, { mode: 0o700 });
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  const before = await sourceDigest(root);
  const report = {
    schemaVersion: 1,
    kind: 'clamav-native-acceptance',
    startedAt: new Date().toISOString(),
    gitCommit: git('rev-parse', 'HEAD'),
    sourceDigest: before,
    workingTreeClean: git('status', '--porcelain') === '',
    runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    outcome: 'BLOCKED',
    nativeTests: { outcome: 'NOT_EXECUTED' },
    limits: [
      'Synthetic three-case smoke test only; no representative corpus qualification',
      'Launcher hash does not attest its interpreter, engine libraries or host',
      'tmpfs check does not prevent swap, dumps, parser compromise or mount changes',
      'No readiness, grading or operational authorization is assigned',
    ],
  };
  try {
    const settings = JSON.parse(await readFile(configuration, 'utf8'));
    new ClamAvInspector(settings); // Reuse the runtime configuration constraints.
    report.configurationSha256 = await fileHash(configuration);
    report.executableSha256 = await fileHash(settings.executable);
    if (report.executableSha256 !== settings.executableSha256)
      throw failure('ACCEPTANCE_ENGINE_HASH');
    await requirePrivateTmpfs(settings.tempRoot);
    report.temporaryStorage = 'PRIVATE_OWNER_0700_TMPFS_OBSERVED';
    report.engineVersion = requireReviewedVersion(
      execFileSync(settings.executable, ['--version'], {
        env: cleanEnvironment,
        encoding: 'utf8',
        timeout: 10000,
        maxBuffer: 4096,
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    );
    report.databases = await databaseInventory(settings.database);
    if (!report.workingTreeClean) throw failure('ACCEPTANCE_DIRTY_SOURCE');
    let output = '',
      exitCode;
    try {
      output = execFileSync(
        process.execPath,
        [
          '--test',
          '--test-concurrency=1',
          '--test-reporter=tap',
          'tests/file-inspection/clamav.check.mjs',
        ],
        {
          cwd: root,
          env: { ...cleanEnvironment, SIEPMU_CLAMAV_CONFIG: resolve(configuration) },
          encoding: 'utf8',
          timeout: 400000,
          maxBuffer: 1024 * 1024,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      exitCode = 0;
    } catch (error) {
      output = String(error.stdout ?? '');
      exitCode = Number.isInteger(error.status) ? error.status : null;
    }
    report.nativeTests = testOutcome(output, exitCode);
    // No raw scanner output, file content, native diagnostics or operator paths in reports.
    report.nativeTests.tapSha256 = createHash('sha256').update(output).digest('hex');
    report.outcome = report.nativeTests.outcome;
    const unchanged =
      report.configurationSha256 === (await fileHash(configuration)) &&
      report.executableSha256 === (await fileHash(settings.executable)) &&
      JSON.stringify(report.databases) ===
        JSON.stringify(await databaseInventory(settings.database));
    if (!unchanged) throw failure('ACCEPTANCE_INPUT_CHANGED');
    await requirePrivateTmpfs(settings.tempRoot);
  } catch (error) {
    report.reason = /^(ACCEPTANCE|FILE_INSPECTION)_[A-Z_]+$/.test(error?.code ?? '')
      ? error.code
      : 'ACCEPTANCE_PREREQUISITE_ERROR';
    report.outcome = report.nativeTests.outcome === 'NOT_EXECUTED' ? 'BLOCKED' : 'FAIL';
  }
  report.sourceUnchanged =
    before === (await sourceDigest(root)) &&
    report.gitCommit === git('rev-parse', 'HEAD') &&
    report.workingTreeClean === (git('status', '--porcelain') === '');
  if (!report.sourceUnchanged) report.outcome = 'INVALIDATED';
  report.finishedAt = new Date().toISOString();
  await writeFile(resolve(destination, 'report.json'), JSON.stringify(report, null, 2) + '\n', {
    flag: 'wx',
    mode: 0o600,
  });
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 4) {
    console.error(
      'Usage: node scripts/clamav-acceptance.mjs <configuration.json> <new-output-directory>',
    );
    process.exitCode = 2;
  } else {
    const report = await runAcceptance(resolve(process.argv[2]), resolve(process.argv[3]));
    console.log(
      JSON.stringify({
        outcome: report.outcome,
        reason: report.reason,
        gitCommit: report.gitCommit,
        nativeTests: report.nativeTests,
      }),
    );
    process.exitCode = report.outcome === 'PASS' ? 0 : 1;
  }
}
