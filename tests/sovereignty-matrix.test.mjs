// Keeps docs/research/sovereign/sovereignty-matrix.csv truthful: closed vocabulary, existing
// evidence, and complete coverage of every pinned third-party package. A dependency added to a
// lockfile without a matrix row, or a row that claims qualification without evidence, fails here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { root } from './helpers/fixture.mjs';

const MATRIX = join(root, 'docs/research/sovereign/sovereignty-matrix.csv');
const HEADER = [
  'id',
  'component',
  'version',
  'layer',
  'origin',
  'developed_by',
  'operated_by',
  'licence',
  'runtime_role',
  'ships_in_release',
  'qualification',
  'evidence',
];
const VOCABULARY = {
  origin: [
    'SYNTRIASS_SOURCE',
    'FOREIGN_OPEN_SOURCE',
    'FOREIGN_STANDARD',
    'FOREIGN_SERVICE',
    'IMPORTED_HARDWARE',
  ],
  operated_by: ['OPERATOR', 'THIRD_PARTY', 'NONE'],
  runtime_role: [
    'RUNTIME',
    'ENDPOINT',
    'ALGORITHM',
    'LAB_ONLY',
    'DEV_ONLY',
    'CI_ONLY',
    'VERIFICATION_ONLY',
  ],
  ships_in_release: ['YES', 'NO'],
  qualification: ['NOT_QUALIFIED', 'PROJECT_TESTED', 'INDEPENDENTLY_QUALIFIED'],
};
/** Independent qualification must cite a report in this directory; none exists today. */
const QUALIFICATION_EVIDENCE_DIR = 'docs/assurance/qualification/';

/** Minimal RFC 4180 parser for quoted fields (no embedded newlines are used). */
function parseCsv(text) {
  return text
    .trimEnd()
    .split('\n')
    .map((line) => {
      const cells = [];
      let cell = '';
      let quoted = false;
      for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (quoted && c === '"' && line[i + 1] === '"') {
          cell += '"';
          i++;
        } else if (c === '"') quoted = !quoted;
        else if (c === ',' && !quoted) {
          cells.push(cell);
          cell = '';
        } else cell += c;
      }
      cells.push(cell);
      return cells;
    });
}
function matrix() {
  const [header, ...lines] = parseCsv(readFileSync(MATRIX, 'utf8'));
  return {
    header,
    rows: lines.map((cells) => Object.fromEntries(header.map((h, i) => [h, cells[i]]))),
  };
}
const json = (path) => JSON.parse(readFileSync(join(root, path), 'utf8'));

test('matrix has the fixed header, unique ids and a closed vocabulary', () => {
  const { header, rows } = matrix();
  assert.deepEqual(header, HEADER);
  assert.equal(new Set(rows.map((r) => r.id)).size, rows.length, 'duplicate id');
  for (const r of rows) {
    for (const h of HEADER) assert.ok(r[h] && r[h].length > 0, `${r.id}: empty ${h}`);
    for (const [field, allowed] of Object.entries(VOCABULARY))
      assert.ok(allowed.includes(r[field]), `${r.id}: ${field}=${r[field]}`);
  }
});

test('every evidence path exists and qualification claims need qualification evidence', () => {
  for (const r of matrix().rows) {
    assert.ok(existsSync(join(root, r.evidence)), `${r.id}: missing evidence ${r.evidence}`);
    if (r.qualification === 'INDEPENDENTLY_QUALIFIED')
      assert.ok(r.evidence.startsWith(QUALIFICATION_EVIDENCE_DIR), `${r.id}: unsupported claim`);
    if (r.qualification === 'PROJECT_TESTED')
      assert.equal(r.origin, 'SYNTRIASS_SOURCE', `${r.id}: only project code is project-tested`);
  }
});

test('origin is never upgraded: third-party and standards rows are not SYNTRIASS source', () => {
  for (const r of matrix().rows) {
    const thirdParty = /^(npm-|rust-crate:|rt-|alg-|ci-|hw-)/.test(r.id);
    assert.equal(thirdParty, r.origin !== 'SYNTRIASS_SOURCE', `${r.id}: origin ${r.origin}`);
    if (r.origin === 'SYNTRIASS_SOURCE') assert.equal(r.developed_by, 'SYNTRIASS', r.id);
  }
});

test('every pinned npm package (dev and lab) and every Rust crate is listed at its locked version', () => {
  const rows = new Map(matrix().rows.map((r) => [r.id, r]));
  const pkg = json('package.json');
  const lock = json('package-lock.json');
  for (const [name, version] of Object.entries(pkg.devDependencies))
    assert.equal(rows.get('npm-dev:' + name)?.version, version, `npm-dev:${name}`);
  const transitive =
    Object.keys(lock.packages).filter(Boolean).length - Object.keys(pkg.devDependencies).length;
  assert.equal(rows.get('npm-dev-transitive')?.version, String(transitive));
  const lab = json('packages/pqc-lab/package-lock.json');
  for (const [path, meta] of Object.entries(lab.packages)) {
    if (!path) continue;
    const name = path.replace('node_modules/', '');
    assert.equal(rows.get('npm-lab:' + name)?.version, meta.version, `npm-lab:${name}`);
  }
  const cargo = readFileSync(join(root, 'native/Cargo.lock'), 'utf8');
  const crates = [...cargo.matchAll(/^name = "([^"]+)"\nversion = "([^"]+)"/gm)].filter(
    ([, name]) => name !== 'siepmu-evidence-verify',
  );
  assert.ok(crates.length > 0);
  for (const [, name, version] of crates)
    assert.equal(rows.get('rust-crate:' + name)?.version, version, `rust-crate:${name}`);
});

test('runtime image ships no third-party package outside the runtime and algorithms', () => {
  for (const r of matrix().rows.filter((x) => x.ships_in_release === 'YES'))
    assert.ok(
      ['RUNTIME', 'ALGORITHM'].includes(r.runtime_role),
      `${r.id}: ships but is ${r.runtime_role}`,
    );
});
