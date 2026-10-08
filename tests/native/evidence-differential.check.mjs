/**
 * Differential acceptance of the Rust evidence verifier against the Node reference CLI.
 *
 * 1. Real evidence: runs the actual synthetic HTTP demonstration (scripts/demo.mjs), takes the
 *    authority's exported chain, checkpoint, release receipt and public key, and requires
 *    byte-identical stdout from both verifiers.
 * 2. Seeded mutation campaign over that real export: every mutation must produce the same exit
 *    status and byte-identical stdout/stderr from both verifiers.
 * 3. The committed language-neutral vectors are executed through the Rust *binary* (the cargo
 *    conformance test covers the library entry point).
 *
 * Requires the release binary (npm run build:native). A missing binary is a failure, not a skip.
 * Run with: npm run test:native
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { root } from '../helpers/fixture.mjs';

const rustBinary = resolve(
  process.env.SIEPMU_RUST_VERIFIER ?? join(root, 'native/target/release/siepmu-evidence-verify'),
);
const nodeCli = join(root, 'apps/verifier/verify.mjs');
/** Fixed seed: the campaign is reproducible; change it only together with MUTATIONS. */
const SEED = 0x51e9;
const MUTATIONS = 400;

function runBoth(argv, cwd) {
  const options = { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 };
  const node = spawnSync(process.execPath, [nodeCli, ...argv], options);
  const rust = spawnSync(rustBinary, argv, options);
  assert.equal(rust.error, undefined, `cannot execute ${rustBinary}`);
  return { node, rust };
}
function assertParity({ node, rust }, label) {
  assert.equal(rust.status, node.status, `${label}: exit status (node: ${node.stderr})`);
  assert.equal(rust.stdout, node.stdout, `${label}: stdout`);
  assert.equal(rust.stderr, node.stderr, `${label}: stderr`);
}

/** mulberry32: small deterministic PRNG for reproducible mutation selection (not security). */
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function scalarPaths(value, path = []) {
  if (value === null || typeof value !== 'object') return [path];
  return Object.entries(value).flatMap(([k, v]) =>
    scalarPaths(v, [...path, Array.isArray(value) ? Number(k) : k]),
  );
}
function setAt(target, path, update) {
  const parent = path.slice(0, -1).reduce((o, k) => o[k], target);
  const key = path.at(-1);
  parent[key] = update(parent[key]);
}
const tweak = (v) =>
  typeof v === 'number'
    ? v + 1
    : typeof v === 'string'
      ? v.length
        ? v.slice(0, -1) + (v.at(-1) === 'a' ? 'b' : 'a')
        : 'x'
      : typeof v === 'boolean'
        ? !v
        : 0;

/** Each operator returns [description, mutated export text]. */
function mutations(base, random) {
  const pick = (n) => Math.floor(random() * n);
  const n = base.records.length;
  const copy = () => structuredClone(base);
  return [
    () => {
      const m = copy();
      const i = pick(n);
      const paths = scalarPaths(m.records[i].payload);
      const p = paths[pick(paths.length)];
      setAt(m.records[i].payload, p, tweak);
      return [`payload ${i}:${p.join('.')}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const i = pick(n);
      m.records.splice(i, 1);
      return [`delete ${i}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const i = pick(n),
        j = pick(n);
      [m.records[i], m.records[j]] = [m.records[j], m.records[i]];
      return [`swap ${i},${j}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const i = pick(n);
      m.records.splice(i, 0, structuredClone(m.records[i]));
      return [`duplicate ${i}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const i = pick(n);
      const s = m.records[i].signature;
      const k = pick(s.length);
      m.records[i].signature = s.slice(0, k) + (s[k] === 'A' ? 'B' : 'A') + s.slice(k + 1);
      return [`signature ${i}@${k}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      m.records[pick(n)].keyId = 'f'.repeat(64);
      return ['keyId', JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const i = pick(n);
      const names = Object.keys(m.records[i].payload);
      delete m.records[i].payload[names[pick(names.length)]];
      return [`drop member ${i}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      m.records[pick(n)].extra = 1;
      return ['extra packet member', JSON.stringify(m)];
    },
    () => {
      const m = copy();
      m.records = m.records.slice(0, pick(n));
      return [`truncate to ${m.records.length}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const field = ['sequence', 'headHash', 'issuedAt'][pick(3)];
      setAt(m.checkpoint.payload, [field], tweak);
      return [`checkpoint ${field}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const i = pick(n);
      m.records[i].payload.epoch = 0.5;
      return [`float epoch ${i}`, JSON.stringify(m)];
    },
    () => {
      const m = copy();
      const i = pick(n);
      m.records[i].payload = [null, 'array', 1][pick(3)];
      return [`payload type ${i}`, JSON.stringify(m)];
    },
    () => {
      // Whitespace and member reordering must not change the verdict (canonical preimage).
      const m = copy();
      const i = pick(n);
      m.records[i] = Object.fromEntries(Object.entries(m.records[i]).reverse());
      return [`reorder members ${i}`, JSON.stringify(m, null, 1 + pick(3))];
    },
  ];
}

let demo;
test.before(() => {
  assert.ok(
    existsSync(rustBinary),
    `Rust verifier missing at ${rustBinary}; run npm run build:native`,
  );
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-differential-'));
  const run = spawnSync(process.execPath, ['scripts/demo.mjs'], {
    cwd: root,
    env: { ...process.env, SIEPMU_EVIDENCE_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(run.status, 0, `demo failed: ${run.stderr}`);
  demo = {
    dir,
    evidence: JSON.parse(readFileSync(join(dir, 'evidence.json'), 'utf8')),
    receipt: JSON.parse(readFileSync(join(dir, 'receipt.json'), 'utf8')),
  };
});
test.after(() => demo && rmSync(demo.dir, { recursive: true, force: true }));

test('real authority evidence: identical results for chain, saved checkpoint and receipt bindings', () => {
  assert.ok(demo.evidence.records.length >= 10, 'demo should produce a substantive chain');
  const chain = runBoth(['evidence.json', 'public-key.json'], demo.dir);
  assertParity(chain, 'chain');
  assert.equal(chain.node.status, 0);
  assert.equal(JSON.parse(chain.rust.stdout).records, demo.evidence.records.length);

  assertParity(
    runBoth(['evidence.json', 'public-key.json', '--checkpoint', 'checkpoint.json'], demo.dir),
    'saved checkpoint',
  );
  const { details, epoch, objectId } = demo.receipt.payload;
  const bound = runBoth(
    [
      'receipt.json',
      'public-key.json',
      '--object-digest',
      details.objectDigest,
      '--epoch',
      String(epoch),
      '--object-id',
      objectId,
    ],
    demo.dir,
  );
  assertParity(bound, 'receipt bindings');
  assert.equal(JSON.parse(bound.rust.stdout).bindingVerified, true);
});

test(`seeded mutation campaign (${MUTATIONS} cases, seed ${SEED}) yields identical verdicts`, () => {
  const random = prng(SEED);
  const operators = mutations(demo.evidence, random);
  const tally = { accepted: 0, rejected: 0 };
  for (let index = 0; index < MUTATIONS; index++) {
    const [label, text] = operators[Math.floor(random() * operators.length)]();
    writeFileSync(join(demo.dir, 'mutated.json'), text);
    const result = runBoth(['mutated.json', 'public-key.json'], demo.dir);
    assertParity(result, `mutation ${index} (${label})`);
    tally[result.node.status === 0 ? 'accepted' : 'rejected']++;
  }
  // Reordering/whitespace mutations must be accepted; nearly everything else rejected.
  assert.ok(tally.rejected > MUTATIONS / 2 && tally.accepted > 0, JSON.stringify(tally));
});

test('committed language-neutral vectors pass through the Rust binary', () => {
  const vectors = JSON.parse(readFileSync(join(root, 'spec/vectors/evidence-v1.json'), 'utf8'));
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-binary-vectors-'));
  try {
    const paths = {
      '@input': join(dir, 'input.json'),
      '@key': join(dir, 'key.json'),
      '@checkpoint': join(dir, 'checkpoint.json'),
    };
    for (const c of vectors.cases) {
      rmSync(paths['@checkpoint'], { force: true });
      writeFileSync(
        paths['@input'],
        c.inputBase64 ? Buffer.from(c.inputBase64, 'base64') : c.input,
      );
      writeFileSync(paths['@key'], c.key);
      if (c.checkpoint !== null) writeFileSync(paths['@checkpoint'], c.checkpoint);
      const run = spawnSync(
        rustBinary,
        c.argv.map((a) => paths[a] ?? a),
        { encoding: 'utf8' },
      );
      assert.equal(run.status, c.expect.status, `${c.id}: status`);
      if (c.expect.stdout !== undefined) assert.equal(run.stdout, c.expect.stdout, `${c.id}`);
      if (typeof c.expect.error === 'string')
        assert.equal(JSON.parse(run.stderr).error, c.expect.error, `${c.id}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
