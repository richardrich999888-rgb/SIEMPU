// Freeze an inspectable, ungraded candidate. No generated keys, live configuration or data.
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync, lstatSync, existsSync, realpathSync } from 'node:fs';
import { resolve, join, dirname, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { getFips } from 'node:crypto';
import { sourceDigest } from '../../scripts/audit-claims.mjs';
import {
  FORMAT,
  MAX_FILE,
  MAX_TOTAL,
  encode,
  sha256,
  insist,
  sourcePathAllowed,
  safePath,
  readBounded,
  regularFiles,
  fingerprint,
  validateCatalogue,
  assessment,
  validateReport,
} from './format.mjs';
import { verifyEvaluationPackage } from './verify.mjs';

const git = (root, args, options = {}) =>
  execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: MAX_TOTAL,
    ...options,
  });
export function snapshot(root) {
  insist(
    git(root, ['status', '--porcelain', '--untracked-files=all']).trim() === '',
    'CLEAN_COMMITTED_TREE_REQUIRED',
  );
  const commit = git(root, ['rev-parse', 'HEAD']).trim();
  const tree = git(root, ['rev-parse', 'HEAD^{tree}']).trim();
  const items = git(root, ['ls-tree', '-r', '-z', '--full-tree', 'HEAD'])
    .split('\0')
    .filter(Boolean)
    .map((line) => {
      const match = /^(100644|100755) blob ([a-f0-9]{40})\t(.+)$/.exec(line);
      insist(match && sourcePathAllowed(match[3]), 'UNSAFE_TRACKED_SOURCE');
      return { mode: match[1], oid: match[2], path: match[3] };
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  insist(items.length > 0 && items.length <= 2000, 'SOURCE_FILE_COUNT');
  const batch = git(root, ['cat-file', '--batch'], {
    encoding: null,
    input: items.map((x) => x.oid).join('\n') + '\n',
  });
  const source = new Map(),
    index = [];
  let offset = 0;
  for (const item of items) {
    const end = batch.indexOf(10, offset);
    insist(end >= offset, 'GIT_BATCH_HEADER');
    const header = /^([a-f0-9]{40}) blob (\d+)$/.exec(batch.subarray(offset, end).toString());
    insist(header && header[1] === item.oid, 'GIT_BATCH_OBJECT');
    const size = Number(header[2]);
    insist(Number.isSafeInteger(size) && size <= MAX_FILE, 'SOURCE_SIZE_LIMIT');
    offset = end + 1;
    insist(offset + size < batch.length && batch[offset + size] === 10, 'GIT_BATCH_SIZE');
    const bytes = Buffer.from(batch.subarray(offset, offset + size));
    offset += size + 1;
    // Detect assume-unchanged/skip-worktree and edits hidden by Git status flags.
    insist(readBounded(join(root, item.path)).equals(bytes), 'WORKTREE_DIFFERS_FROM_COMMIT');
    source.set(item.path, bytes);
    index.push({ path: item.path, mode: item.mode, size, sha256: sha256(bytes) });
  }
  insist(offset === batch.length, 'GIT_BATCH_TRAILING_DATA');
  return { commit, tree, source, index };
}

export async function buildEvaluationPackage(root, destination) {
  root = realpathSync(root);
  destination = resolve(root, destination);
  const outputPath = relative(root, destination).replaceAll('\\', '/');
  insist(
    safePath(outputPath) && outputPath.startsWith('artifacts/') && !existsSync(destination),
    'NEW_ARTIFACT_DESTINATION_REQUIRED',
  );
  // Refuse symlink ancestors before creating any output.
  let current = root;
  for (const part of outputPath.split('/').slice(0, -1)) {
    current = join(current, part);
    if (existsSync(current))
      insist(
        lstatSync(current).isDirectory() && !lstatSync(current).isSymbolicLink(),
        'UNSAFE_OUTPUT_DIRECTORY',
      );
    else mkdirSync(current, { mode: 0o700 });
  }
  const frozen = snapshot(root);
  const catalogue = validateCatalogue(
    JSON.parse(frozen.source.get('assurance/sag/catalogue.json')),
    frozen.source,
  );
  const status = assessment(JSON.parse(frozen.source.get('assurance/sag/requests.json')));
  const reportBytes = readBounded(join(root, 'artifacts/validation/report.json'));
  const report = JSON.parse(reportBytes);
  const digest = await sourceDigest(root);
  validateReport(report, { commit: frozen.commit, digest });
  const payload = new Map();
  const add = (path, bytes) => {
    insist(safePath(path) && !payload.has(path) && bytes.length <= MAX_FILE, 'PACKAGE_ENTRY');
    payload.set(path, bytes);
  };
  for (const [path, bytes] of frozen.source) add(`source/${path}`, bytes);
  add('source-index.json', encode(frozen.index));
  add('git-commit.txt', git(root, ['cat-file', 'commit', frozen.commit], { encoding: null }));
  add('crypto-inventory.json', encode(catalogue));
  add('assessment.json', encode(status));
  add('evidence/validation.json', reportBytes);
  for (const gate of report.gates)
    add(`evidence/${gate.name.replaceAll(':', '-')}.log`, readBounded(join(root, gate.log)));
  const sbom = readBounded(join(root, 'artifacts/application.cdx.json'));
  const bom = JSON.parse(sbom);
  insist(
    bom.bomFormat === 'CycloneDX' &&
      bom.metadata?.component?.name === JSON.parse(frozen.source.get('package.json')).name,
    'SBOM_SCOPE',
  );
  insist(
    Date.parse(bom.metadata.timestamp) >= Date.parse(report.startedAt) &&
      Date.parse(bom.metadata.timestamp) <= Date.parse(report.finishedAt),
    'STALE_SBOM',
  );
  add('evidence/application.cdx.json', sbom);
  const manifestBytes = readBounded(join(root, 'dist/manifest.json'));
  const built = JSON.parse(manifestBytes);
  insist(
    built.schemaVersion === 1 && Array.isArray(built.files) && built.files.length > 0,
    'BUILD_MANIFEST',
  );
  const names = new Set();
  for (const file of built.files) {
    insist(
      safePath(file.file) && !names.has(file.file) && frozen.source.has(file.file),
      'BUILD_SOURCE_PATH',
    );
    insist(
      !/^(?:packages\/pqc-lab|integrations|native|assurance)\//.test(file.file),
      'LAB_CODE_IN_APPLICATION',
    );
    names.add(file.file);
    const bytes = readBounded(join(root, 'dist', file.file));
    insist(
      bytes.length === file.bytes &&
        sha256(bytes) === file.sha256 &&
        bytes.equals(frozen.source.get(file.file)),
      'BUILD_SOURCE_MISMATCH',
    );
    add(`application/${file.file}`, bytes);
  }
  insist(
    regularFiles(join(root, 'dist')).join('\0') === [...names, 'manifest.json'].sort().join('\0'),
    'UNLISTED_BUILD_FILE',
  );
  add('application/manifest.json', manifestBytes);
  const entries = [...payload]
    .map(([path, bytes]) => ({ path, size: bytes.length, sha256: sha256(bytes) }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  insist(entries.reduce((n, f) => n + f.size, 0) <= MAX_TOTAL, 'PACKAGE_SIZE_LIMIT');
  const manifest = {
    format: FORMAT,
    gitCommit: frozen.commit,
    gitTree: frozen.tree,
    sourceFingerprint: fingerprint(frozen.index),
    validationSourceDigest: digest,
    runtime: {
      node: process.version,
      openssl: process.versions.openssl,
      platform: process.platform,
      architecture: process.arch,
      fipsModeReported: getFips(),
    },
    sagGrading: 'NOT_ESTABLISHED',
    operationalAuthorization: 'NOT_ESTABLISHED',
    files: entries,
    limitations: [
      'Applicant-created, unsigned evidence. An independently delivered manifest digest establishes package integrity, not independent testing, identity or approval.',
      'Full committed source includes clearly separated laboratory PQC and optional NEXORA code for inspection. The application tree excludes them.',
      'The application is packaged JavaScript, not a complete deployment image. Node/OS binaries, production PKI, credentials, live data and controlled agency documents are not included.',
      'Crypto inventory is a reviewed declaration with source-change detection, not exhaustive automated discovery or proof of cryptographic implementation security.',
      'Browser, container, native Rust, NEXORA, PQC, formal and network-job evidence must be obtained separately for this exact candidate. This package captures only native-validation evidence.',
      'No approved algorithms, required grade, hardware target, laboratory acceptance profile or evaluation outcome is inferred.',
    ],
  };
  const manifestData = encode(manifest),
    manifestSha256 = sha256(manifestData);
  // Repeat the source identity and working-tree check after gathering evidence.
  insist(
    git(root, ['rev-parse', 'HEAD']).trim() === frozen.commit &&
      git(root, ['status', '--porcelain', '--untracked-files=all']).trim() === '',
    'SOURCE_CHANGED_DURING_PACKAGING',
  );
  mkdirSync(destination, { mode: 0o700 });
  try {
    for (const [path, bytes] of payload) {
      const target = join(destination, path);
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      writeFileSync(target, bytes, { flag: 'wx', mode: 0o600 });
    }
    writeFileSync(join(destination, 'manifest.json'), manifestData, { flag: 'wx', mode: 0o600 });
    const verified = verifyEvaluationPackage(destination, manifestSha256);
    return { package: outputPath, manifestSha256, ...verified };
  } catch (error) {
    rmSync(destination, { recursive: true, force: true });
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    insist(args.length === 1, 'Usage: package.mjs artifacts/NEW_PACKAGE_DIRECTORY');
    console.log(JSON.stringify(await buildEvaluationPackage(process.cwd(), args[0]), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
