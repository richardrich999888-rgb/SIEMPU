// Run from an independently trusted checkout. This verifies bytes, not SAG approval.
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  FORMAT,
  MAX_TOTAL,
  encode,
  sha256,
  insist,
  members,
  safePath,
  hashString,
  readBounded,
  regularFiles,
  fingerprint,
  assessment,
  validateCatalogue,
  sourcePathAllowed,
  sourceTreeId,
  gitObjectId,
  validateReport,
} from './format.mjs';

export function verifyEvaluationPackage(directory, expectedDigest) {
  insist(hashString(expectedDigest), 'INDEPENDENT_MANIFEST_DIGEST_REQUIRED');
  directory = resolve(directory);
  const paths = regularFiles(directory);
  const bytes = readBounded(join(directory, 'manifest.json'));
  insist(sha256(bytes) === expectedDigest, 'MANIFEST_DIGEST_MISMATCH');
  const m = JSON.parse(bytes);
  insist(encode(m).equals(bytes), 'NONCANONICAL_MANIFEST');
  members(m, [
    'format',
    'gitCommit',
    'gitTree',
    'sourceFingerprint',
    'validationSourceDigest',
    'runtime',
    'sagGrading',
    'operationalAuthorization',
    'files',
    'limitations',
  ]);
  insist(
    m.format === FORMAT && /^[a-f0-9]{40}$/.test(m.gitCommit) && /^[a-f0-9]{40}$/.test(m.gitTree),
    'MANIFEST_FORMAT',
  );
  insist(
    m.sagGrading === 'NOT_ESTABLISHED' && m.operationalAuthorization === 'NOT_ESTABLISHED',
    'SELF_APPROVAL_FORBIDDEN',
  );
  members(m.runtime, ['node', 'openssl', 'platform', 'architecture', 'fipsModeReported']);
  insist(
    ['node', 'openssl', 'platform', 'architecture'].every(
      (k) => typeof m.runtime[k] === 'string',
    ) && [0, 1].includes(m.runtime.fipsModeReported),
    'MANIFEST_RUNTIME',
  );
  insist(
    hashString(m.sourceFingerprint) && hashString(m.validationSourceDigest),
    'MANIFEST_SOURCE',
  );
  insist(Array.isArray(m.files) && m.files.length > 0 && m.files.length <= 5000, 'MANIFEST_FILES');
  const expected = [],
    content = new Map();
  let total = 0;
  for (const file of m.files) {
    members(file, ['path', 'size', 'sha256']);
    insist(
      safePath(file.path) && file.path !== 'manifest.json' && !content.has(file.path),
      'MANIFEST_PATH',
    );
    insist(
      Number.isSafeInteger(file.size) && file.size >= 0 && hashString(file.sha256),
      'MANIFEST_FILE',
    );
    total += file.size;
    insist(total <= MAX_TOTAL, 'PACKAGE_SIZE_LIMIT');
    const data = readBounded(join(directory, file.path));
    insist(data.length === file.size && sha256(data) === file.sha256, 'FILE_DIGEST_MISMATCH');
    content.set(file.path, data);
    expected.push(file.path);
  }
  insist(
    paths.join('\0') === [...expected, 'manifest.json'].sort().join('\0'),
    'UNLISTED_OR_MISSING_FILE',
  );
  const index = JSON.parse(content.get('source-index.json'));
  insist(
    Array.isArray(index) && index.length > 0 && fingerprint(index) === m.sourceFingerprint,
    'SOURCE_INDEX',
  );
  const source = new Map();
  for (const entry of index) {
    members(entry, ['path', 'mode', 'size', 'sha256']);
    insist(
      sourcePathAllowed(entry.path) &&
        !source.has(entry.path) &&
        ['100644', '100755'].includes(entry.mode),
      'SOURCE_INDEX_PATH',
    );
    const data = content.get(`source/${entry.path}`);
    insist(
      data && data.length === entry.size && sha256(data) === entry.sha256,
      'SOURCE_INDEX_DIGEST',
    );
    source.set(entry.path, data);
  }
  insist(
    [...content.keys()].filter((p) => p.startsWith('source/')).length === source.size,
    'SOURCE_INDEX_COVERAGE',
  );
  insist(sourceTreeId(index, source) === m.gitTree, 'GIT_TREE_MISMATCH');
  const commit = content.get('git-commit.txt');
  insist(
    commit &&
      gitObjectId('commit', commit) === m.gitCommit &&
      /^tree ([a-f0-9]{40})\n/.exec(commit.toString())?.[1] === m.gitTree,
    'GIT_COMMIT_MISMATCH',
  );
  const report = JSON.parse(content.get('evidence/validation.json'));
  validateReport(report, {
    commit: m.gitCommit,
    digest: m.validationSourceDigest,
    runtime: m.runtime,
  });
  for (const gate of report.gates)
    insist(content.has(`evidence/${gate.name.replaceAll(':', '-')}.log`), 'MISSING_VALIDATION_LOG');
  const catalogue = JSON.parse(content.get('crypto-inventory.json'));
  validateCatalogue(catalogue, source);
  insist(
    encode(catalogue).equals(encode(JSON.parse(source.get('assurance/sag/catalogue.json')))),
    'INVENTORY_SOURCE_MISMATCH',
  );
  const status = assessment(JSON.parse(source.get('assurance/sag/requests.json')));
  insist(encode(status).equals(content.get('assessment.json')), 'ASSESSMENT_MISMATCH');
  const build = JSON.parse(content.get('application/manifest.json'));
  const built = new Set();
  insist(build.schemaVersion === 1 && Array.isArray(build.files), 'BUILD_MANIFEST');
  for (const file of build.files) {
    insist(safePath(file.file) && !built.has(file.file), 'BUILD_PATH');
    insist(
      !/^(?:packages\/pqc-lab|integrations|native|assurance)\//.test(file.file),
      'LAB_CODE_IN_APPLICATION',
    );
    built.add(file.file);
    const data = content.get(`application/${file.file}`);
    insist(
      data &&
        source.has(file.file) &&
        data.equals(source.get(file.file)) &&
        data.length === file.bytes &&
        sha256(data) === file.sha256,
      'BUILD_SOURCE_MISMATCH',
    );
  }
  insist(
    [...content.keys()].filter((p) => p.startsWith('application/')).length === built.size + 1,
    'BUILD_COVERAGE',
  );
  return {
    integrity: 'MATCHES_EXPECTED_DIGEST',
    gitCommit: m.gitCommit,
    files: m.files.length,
    ...status,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    insist(args.length === 2, 'Usage: verify.mjs PACKAGE EXPECTED_MANIFEST_SHA256');
    console.log(JSON.stringify(verifyEvaluationPackage(...args), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
