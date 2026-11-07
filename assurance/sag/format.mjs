// Applicant evaluation-package format. No value in this format confers external approval.
import {
  constants,
  openSync,
  closeSync,
  fstatSync,
  readSync,
  lstatSync,
  readdirSync,
} from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export const FORMAT = 'SIEPMU_SAG_EVALUATION_CANDIDATE_V1';
export const MAX_FILE = 16 * 1024 * 1024;
export const MAX_TOTAL = 128 * 1024 * 1024;
export const GATES = [
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
export const REQUEST_IDS = [
  'SAG-01', // Pending external scope input, never an approval.
  'SAG-02', // Pending external scope input, never an approval.
  'SAG-03', // Pending external scope input, never an approval.
  'SAG-04', // Pending external scope input, never an approval.
  'SAG-05', // Pending external scope input, never an approval.
  'SAG-06', // Pending external scope input, never an approval.
  'IAF-01',
  'IAF-02',
  'IAF-07',
  'IAF-08',
  'IAF-10',
  'IAF-12',
];
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const encode = (value) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
export const insist = (ok, code) => {
  if (!ok) throw new Error(code);
};
export const hashString = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function members(value, names) {
  insist(value && typeof value === 'object' && !Array.isArray(value), 'INVALID_SCHEMA');
  insist(Object.keys(value).sort().join('\0') === [...names].sort().join('\0'), 'INVALID_MEMBERS');
}
export function safePath(path) {
  return (
    typeof path === 'string' &&
    path.length < 300 &&
    /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(path) &&
    path.split('/').every((s) => s !== '.' && s !== '..')
  );
}
export function sourcePathAllowed(path) {
  return (
    safePath(path) &&
    !path
      .split('/')
      .some((s) =>
        ['.git', '.data', 'node_modules', 'target', 'artifacts', 'dist', 'coverage'].includes(s),
      ) &&
    !/(?:^|\/)\.env(?:$|\.(?!example$))/.test(path) &&
    !/\.(?:key|pem|p12|pfx|sqlite|sqlite3|db)$/i.test(path) &&
    !/(?:^|\/)(?:server-key|master|demo-profiles|adapter-profile|signer-private)\.json$/.test(path)
  );
}
export function readBounded(path, limit = MAX_FILE) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    insist(st.isFile() && st.size <= limit, 'UNSAFE_OR_OVERSIZE_FILE');
    const chunks = [];
    let total = 0;
    while (total <= limit) {
      const chunk = Buffer.alloc(Math.min(65536, limit + 1 - total));
      const n = readSync(fd, chunk, 0, chunk.length, null);
      if (!n) break;
      total += n;
      chunks.push(chunk.subarray(0, n));
    }
    insist(total <= limit, 'OVERSIZE_FILE');
    return Buffer.concat(chunks, total);
  } finally {
    closeSync(fd);
  }
}
export function regularFiles(root, prefix = '', budget = { count: 0 }) {
  insist(lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink(), 'UNSAFE_DIRECTORY');
  const result = [];
  for (const name of readdirSync(root).sort()) {
    insist(++budget.count <= 10000, 'TOO_MANY_FILES');
    const path = prefix ? `${prefix}/${name}` : name;
    insist(safePath(path), 'UNSAFE_PATH');
    const st = lstatSync(join(root, name));
    insist(!st.isSymbolicLink(), 'SYMLINK_FORBIDDEN');
    if (st.isDirectory()) result.push(...regularFiles(join(root, name), path, budget));
    else {
      insist(st.isFile(), 'SPECIAL_FILE_FORBIDDEN');
      result.push(path);
    }
  }
  return result.sort();
}
export function fingerprint(entries) {
  return sha256(encode(entries));
}
// Git identity is checked independently of the SHA-256 transfer manifest.
export function gitObjectId(type, bytes) {
  return createHash('sha1').update(`${type} ${bytes.length}\0`).update(bytes).digest('hex');
}
export function sourceTreeId(index, source) {
  const root = new Map();
  for (const entry of index) {
    const parts = entry.path.split('/');
    let directory = root;
    for (const part of parts.slice(0, -1)) {
      if (!directory.has(part)) directory.set(part, new Map());
      directory = directory.get(part);
      insist(directory instanceof Map, 'SOURCE_TREE_COLLISION');
    }
    const name = parts.at(-1);
    insist(!directory.has(name), 'SOURCE_TREE_COLLISION');
    directory.set(name, { mode: entry.mode, oid: gitObjectId('blob', source.get(entry.path)) });
  }
  function tree(directory) {
    const entries = [...directory].map(([name, value]) =>
      value instanceof Map
        ? { name, sort: name + '/', mode: '40000', oid: tree(value) }
        : { name, sort: name, ...value },
    );
    entries.sort((a, b) => Buffer.compare(Buffer.from(a.sort), Buffer.from(b.sort)));
    return gitObjectId(
      'tree',
      Buffer.concat(
        entries.flatMap((e) => [Buffer.from(`${e.mode} ${e.name}\0`), Buffer.from(e.oid, 'hex')]),
      ),
    );
  }
  return tree(root);
}
function text(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 3000;
}
export function validateCatalogue(catalogue, source) {
  members(catalogue, [
    'schemaVersion',
    'kind',
    'reviewDate',
    'coverage',
    'components',
    'sourceBindings',
  ]);
  insist(
    catalogue.schemaVersion === 1 && catalogue.kind === 'APPLICANT_CRYPTO_INVENTORY',
    'CATALOGUE_FORMAT',
  );
  insist(text(catalogue.reviewDate) && text(catalogue.coverage), 'CATALOGUE_DESCRIPTION');
  insist(Array.isArray(catalogue.components) && catalogue.components.length > 0, 'CATALOGUE_EMPTY');
  const ids = new Set(),
    paths = new Set();
  for (const c of catalogue.components) {
    members(c, [
      'id',
      'purpose',
      'mechanisms',
      'boundary',
      'deploymentScope',
      'custody',
      'limitations',
      'sources',
      'tests',
    ]);
    insist(text(c.id) && !ids.has(c.id), 'CATALOGUE_DUPLICATE');
    ids.add(c.id);
    for (const name of ['purpose', 'boundary', 'custody', 'limitations'])
      insist(text(c[name]), 'CATALOGUE_DESCRIPTION');
    insist(
      ['APPLICATION', 'LAB_ONLY', 'OPTIONAL_OFFLINE_TOOL'].includes(c.deploymentScope),
      'CATALOGUE_SCOPE',
    );
    insist(
      Array.isArray(c.mechanisms) && c.mechanisms.length && c.mechanisms.every(text),
      'CATALOGUE_MECHANISMS',
    );
    for (const name of ['sources', 'tests']) {
      insist(Array.isArray(c[name]) && c[name].length > 0, 'CATALOGUE_PATHS');
      for (const path of c[name]) {
        insist(sourcePathAllowed(path) && source.has(path), 'CATALOGUE_MISSING_SOURCE');
        paths.add(path);
      }
    }
  }
  members(catalogue.sourceBindings, [...paths]);
  for (const path of paths) {
    const binding = catalogue.sourceBindings[path];
    members(binding, ['sha256']);
    insist(
      hashString(binding.sha256) && sha256(source.get(path)) === binding.sha256,
      'CRYPTO_REVIEW_DRIFT',
    );
  }
  return catalogue;
}
export function assessment(requests) {
  members(requests, ['schemaVersion', 'kind', 'requests']);
  insist(
    requests.schemaVersion === 1 && requests.kind === 'EXTERNAL_SCOPE_REQUESTS',
    'REQUEST_FORMAT',
  );
  insist(
    Array.isArray(requests.requests) && requests.requests.length === REQUEST_IDS.length,
    'REQUEST_SET',
  );
  const ids = new Set();
  const items = requests.requests.map((r) => {
    members(r, ['id', 'owner', 'question', 'publicReference']);
    insist(REQUEST_IDS.includes(r.id) && !ids.has(r.id), 'REQUEST_SET');
    ids.add(r.id);
    insist(text(r.owner) && text(r.question), 'REQUEST_DESCRIPTION');
    insist(r.publicReference === null || text(r.publicReference), 'REQUEST_REFERENCE');
    return {
      ...r,
      status:
        r.publicReference === null ? 'EXTERNAL_INPUT_REQUIRED' : 'REFERENCE_SUPPLIED_UNVERIFIED',
    };
  });
  return {
    status: 'EXTERNAL_ASSESSMENT_REQUIRED',
    sagGrading: 'NOT_ESTABLISHED',
    operationalAuthorization: 'NOT_ESTABLISHED',
    missingInputs: items.filter((r) => r.publicReference === null).map((r) => r.id),
    requests: items,
    limitation:
      'Applicant references and passing software tests do not authenticate an external decision. Scope, authenticity and applicability require the authorised evaluator.',
  };
}
export function validateReport(
  report,
  {
    commit,
    digest,
    runtime = { node: process.version, platform: process.platform, architecture: process.arch },
  },
) {
  insist(
    report.schemaVersion === 1 && report.kind === 'native-validation' && report.outcome === 'PASS',
    'VALIDATION_FAILED',
  );
  insist(
    report.gitCommit === commit && report.workingTreeStatus === '',
    'VALIDATION_REVISION_MISMATCH',
  );
  insist(
    hashString(digest) && report.sourceDigest === digest && report.sourceDigestAfter === digest,
    'VALIDATION_SOURCE_MISMATCH',
  );
  insist(
    report.runtime?.node === runtime.node &&
      report.runtime?.platform === runtime.platform &&
      report.runtime?.architecture === runtime.architecture,
    'VALIDATION_RUNTIME_MISMATCH',
  );
  insist(
    Number.isFinite(Date.parse(report.startedAt)) &&
      Date.parse(report.finishedAt) >= Date.parse(report.startedAt),
    'VALIDATION_TIME',
  );
  insist(
    report.tests?.total > 0 &&
      ['failed', 'skipped', 'cancelled'].every((k) => report.tests[k] === 0),
    'VALIDATION_TESTS',
  );
  insist(report.claimsAudit?.valid === true, 'VALIDATION_CLAIMS');
  insist(Array.isArray(report.gates) && report.gates.length === GATES.length, 'VALIDATION_GATES');
  const seen = new Set();
  for (const gate of report.gates) {
    insist(GATES.includes(gate.name) && !seen.has(gate.name), 'VALIDATION_GATES');
    seen.add(gate.name);
    insist(gate.outcome === 'PASS' && gate.exitCode === 0, 'VALIDATION_GATE_FAILED');
    insist(
      gate.log === `artifacts/validation/${gate.name.replaceAll(':', '-')}.log`,
      'VALIDATION_LOG_PATH',
    );
  }
}
