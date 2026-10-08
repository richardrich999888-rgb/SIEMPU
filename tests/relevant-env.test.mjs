// Unit tests for the pure parts of the three-host TRL 5 advancement harness. The harness itself
// needs root and network namespaces and runs through `npm run trl5:validate`; these tests need
// neither and run everywhere.

import test from 'node:test';
import assert from 'node:assert/strict';
import { HOSTS, LINKS, topologyPlan, hostsFiles } from '../deployment/relevant-env/topology.mjs';
import {
  MAX_DELAY_MS,
  MAX_JITTER_MS,
  mulberry32,
  validateProfile,
  nextDue,
  createDelayQueue,
} from '../deployment/relevant-env/wan-relay.mjs';
import {
  syntheticBytes,
  plaintextRepresentations,
  blockIndex,
  containsIndexedBlock,
} from '../deployment/relevant-env/payload.mjs';
import { createHash } from 'node:crypto';
import { percentile, summary, PROFILES, LOSS_PROFILES } from '../scripts/trl5-validation.mjs';

test('topology: three namespaces, two links, A and C only reach B', () => {
  const plan = topologyPlan();
  assert.deepEqual(
    plan.filter((argv) => argv[1] === 'netns' && argv[2] === 'add').map((argv) => argv[3]),
    ['siepmu-a', 'siepmu-b', 'siepmu-c'],
  );
  assert.equal(plan.filter((argv) => argv.includes('veth')).length, 2);
  // Every link has Host B on one end; there is no A↔C link.
  for (const link of LINKS) assert.ok(link.left[0] === 'b' || link.right[0] === 'b');
  assert.ok(!LINKS.some((l) => [l.left[0], l.right[0]].sort().join('') === 'ac'));
  // Pure: the same plan every call.
  assert.deepEqual(topologyPlan(), plan);
});

test('topology: hosts files resolve the gateway name per host', () => {
  const files = hostsFiles();
  assert.match(
    files[HOSTS.c.ns],
    new RegExp(`^${HOSTS.c.gatewayAddress.replaceAll('.', '\\.')} web$`, 'm'),
  );
  // Host A resolves web to its own loopback, where the WAN emulator listens.
  assert.match(files[HOSTS.a.ns], /^127\.0\.0\.1 web$/m);
  assert.match(files[HOSTS.b.ns], /^127\.0\.0\.1 web$/m);
});

test('mulberry32: deterministic for a seed, uniform range, distinct seeds diverge', () => {
  const a = mulberry32(42);
  const b = mulberry32(42);
  const c = mulberry32(43);
  const xs = Array.from({ length: 1000 }, () => a());
  assert.deepEqual(
    xs,
    Array.from({ length: 1000 }, () => b()),
  );
  assert.ok(xs.every((x) => x >= 0 && x < 1));
  assert.notEqual(xs[0], c());
});

test('validateProfile: accepts bounded profiles, rejects everything else (fail closed)', () => {
  assert.deepEqual(validateProfile({ delayMs: 100, jitterMs: 20, seed: 1 }), {
    delayMs: 100,
    jitterMs: 20,
    seed: 1,
  });
  assert.deepEqual(validateProfile({ delayMs: 0, jitterMs: 0, seed: 0 }).delayMs, 0);
  for (const bad of [
    null,
    {},
    { delayMs: -1, jitterMs: 0, seed: 1 },
    { delayMs: MAX_DELAY_MS + 1, jitterMs: 0, seed: 1 },
    { delayMs: 2000, jitterMs: MAX_JITTER_MS + 1, seed: 1 },
    { delayMs: 10, jitterMs: 20, seed: 1 }, // jitter larger than delay
    { delayMs: 1.5, jitterMs: 0, seed: 1 },
    { delayMs: 10, jitterMs: 0, seed: '1' },
  ])
    assert.throws(() => validateProfile(bad), TypeError);
});

test('nextDue: delay within jitter bounds and never earlier than the previous chunk', () => {
  const profile = { delayMs: 100, jitterMs: 20 };
  const random = mulberry32(7);
  let due = 0;
  for (let now = 0; now < 500; now += 3) {
    const next = nextDue(due, now, profile, random);
    assert.ok(next >= due, 'in order');
    assert.ok(next >= now + 80, 'not before delay - jitter');
    assert.ok(next <= Math.max(due, now + 120), 'not after delay + jitter unless queued');
    due = next;
  }
  assert.equal(
    nextDue(0, 10, { delayMs: 50, jitterMs: 0 }, () => 0.9),
    60,
  );
});

test('createDelayQueue: delivers strictly in push order even with equal due times (regression)', async () => {
  // Regression: one setTimeout per chunk reordered chunks with equal expiry and broke TLS
  // (ERR_SSL_DECRYPTION_FAILED_OR_BAD_RECORD_MAC) under the P1/P2 profiles.
  const delivered = [];
  const queue = createDelayQueue((chunk) => delivered.push(chunk));
  const base = Date.now() + 20;
  for (let i = 0; i < 200; i++) queue.push(i, base + Math.floor(i / 10));
  queue.push(null, base + 25);
  await new Promise((r) => setTimeout(r, 120));
  assert.deepEqual(delivered, [...Array.from({ length: 200 }, (_, i) => i), null]);
  assert.equal(queue.length, 0);
});

test('createDelayQueue: rejects a decreasing due time and clear() drops pending chunks', async () => {
  const delivered = [];
  const queue = createDelayQueue((chunk) => delivered.push(chunk));
  const t = Date.now() + 30;
  queue.push('a', t);
  assert.throws(() => queue.push('b', t - 1), RangeError);
  queue.clear();
  await new Promise((r) => setTimeout(r, 60));
  assert.deepEqual(delivered, []);
});

test('syntheticBytes: deterministic, seed-dependent, exact length', () => {
  assert.deepEqual(syntheticBytes(4096, 3), syntheticBytes(4096, 3));
  assert.notDeepEqual(syntheticBytes(4096, 3), syntheticBytes(4096, 4));
  assert.equal(syntheticBytes(0, 1).length, 0);
  assert.equal(syntheticBytes(65536, 1).length, 65536);
});

test('percentile and summary: nearest-rank statistics with explicit empty case', () => {
  const values = Array.from({ length: 100 }, (_, i) => i + 1);
  assert.equal(percentile(values, 50), 50);
  assert.equal(percentile(values, 95), 95);
  assert.equal(percentile(values, 99), 99);
  assert.equal(percentile([7], 99), 7);
  assert.equal(percentile([], 50), null);
  const s = summary([3, 1, 2]);
  assert.deepEqual(s, { n: 3, p50: 2, p95: 3, p99: null, max: 3 });
  // p99 is reported only when the sample can support it (n >= 100).
  assert.equal(summary(values).p99, 99);
  assert.deepEqual(summary([]), { n: 0, p50: null, p95: null, p99: null, max: null });
});

test('impairment profiles are those declared in the acceptance matrix', () => {
  assert.deepEqual(
    PROFILES.map((p) => p.id),
    ['P0', 'P1', 'P2', 'P3', 'P4'],
  );
  assert.deepEqual(
    LOSS_PROFILES.map((p) => p.id),
    ['L1', 'L2'],
  );
  for (const p of PROFILES.filter((x) => x.delayMs))
    assert.doesNotThrow(() =>
      validateProfile({ delayMs: p.delayMs, jitterMs: p.jitterMs, seed: 1 }),
    );
});

test('plaintext scan: detects any 64-byte window raw, hex or base64 at every offset (positive control)', () => {
  const plaintext = syntheticBytes(8192, 11);
  const index = blockIndex(plaintextRepresentations(plaintext));
  // Deterministic filler that is not synthetic payload.
  const filler = Buffer.alloc(997, 0x41);
  for (const offset of [0, 1, 2, 31, 32, 33, 4000, 8192 - 64]) {
    const window = Buffer.from(plaintext.subarray(offset, offset + 64));
    for (const encoded of [
      window,
      Buffer.from(window.toString('hex')),
      // base64 of the window embedded in a longer base64 run, as a JSON field would hold it
      Buffer.from(
        Buffer.from(plaintext.subarray(offset - (offset % 3), offset + 64)).toString('base64'),
      ),
    ]) {
      const content = Buffer.concat([filler, encoded, filler]);
      assert.equal(containsIndexedBlock(content, index), true, `offset ${offset}`);
    }
  }
});

test('plaintext scan: no false positive on ciphertext-like or unrelated content (negative control)', () => {
  const index = blockIndex(plaintextRepresentations(syntheticBytes(65536, 11)));
  const seeded = Buffer.from(syntheticBytes(65536, 99)).reverse(); // unrelated synthetic content
  assert.equal(containsIndexedBlock(seeded, index), false);
  assert.equal(containsIndexedBlock(Buffer.alloc(0), index), false);
  assert.equal(containsIndexedBlock(Buffer.alloc(31, 1), index), false);
  // Ciphertext-like bytes (a SHA-256 counter stream; deterministic) and their base64.
  const stream = Buffer.concat(
    Array.from({ length: 2048 }, (_, k) => createHash('sha256').update(String(k)).digest()),
  );
  assert.equal(
    containsIndexedBlock(Buffer.concat([stream, Buffer.from(stream.toString('base64'))]), index),
    false,
  );
});
