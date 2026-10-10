#!/usr/bin/env node
/**
 * Generates spec/vectors/evidence-range-v1.json (SIEPMU-EVIDENCE-RANGE-v1) from the Node
 * reference `verifyEvidenceRange` in apps/verifier/verify.mjs.
 *
 * Every expected outcome is captured by executing the reference; none is written by hand.
 * Keys and ECDSA signatures change on each regeneration (random nonce, per-run key), the case
 * semantics do not. No private key is written anywhere.
 *
 * Usage: node scripts/evidence-range-vectors.mjs [--check]
 *   --check  regenerate in memory and require every committed case to keep its outcome class.
 */
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../packages/protocol/canonical.mjs';
import { verifyEvidenceRange } from '../apps/verifier/verify.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(root, 'spec/vectors/evidence-range-v1.json');
const GENESIS = '0'.repeat(64);
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const sha256 = (text) => createHash('sha256').update(text).digest('hex');

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  return { privateKey, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}
function packet(signer, payload) {
  return {
    payload,
    signature: nodeSign('sha256', Buffer.from(canonical(payload)), {
      key: signer.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url'),
    keyId: sha256(canonical(signer.jwk)),
  };
}
/** Records `from.sequence + 1 .. from.sequence + count`, linked from `from.headHash`. */
function records(signer, from, count, tag = 'a') {
  const out = [];
  let previousHash = from.headHash;
  for (let i = 1; i <= count; i++) {
    const sequence = from.sequence + i;
    const record = packet(signer, {
      sequence,
      previousHash,
      eventId: `${tag}-${sequence}`,
      eventType: 'SYNTHETIC_TEST',
      timestamp: 1700000000000 + i,
      epoch: 4,
      actorId: 'synthetic',
    });
    out.push(record);
    previousHash = sha256(canonical(record));
  }
  return out;
}
const head = (from, list) =>
  list.length
    ? { sequence: list.at(-1).payload.sequence, headHash: sha256(canonical(list.at(-1))) }
    : from;
const checkpoint = (signer, position) => packet(signer, { ...position, issuedAt: 1700000009999 });
const clone = (value) => structuredClone(value);

function buildCases() {
  const signer = keyPair();
  const other = keyPair();
  const key = JSON.stringify(signer.jwk);
  const genesis = { sequence: 0, headHash: GENESIS };
  const prefix = records(signer, genesis, 3);
  const base = head(genesis, prefix);
  const tail = records(signer, base, 3);
  const cp = checkpoint(signer, head(base, tail));
  const ok = { base, records: tail, checkpoint: cp };
  const cases = [];
  const add = (id, input, extra = {}) =>
    cases.push({
      id,
      input: typeof input === 'string' ? input : JSON.stringify(input),
      key,
      ...extra,
    });

  add('accept-extension', ok);
  add('accept-genesis-base', {
    base: genesis,
    records: prefix,
    checkpoint: checkpoint(signer, base),
  });
  add('accept-empty-range', { base, records: [], checkpoint: checkpoint(signer, base) });
  const highBase = { sequence: MAX_SAFE - 2, headHash: 'e'.repeat(64) };
  const high = records(signer, highBase, 2);
  add('accept-near-max-safe', {
    base: highBase,
    records: high,
    checkpoint: checkpoint(signer, head(highBase, high)),
  });
  // Base + 2 records would end at 2^53, which no signer can encode: the bound is checked
  // before any record, so two copies of the one signable record suffice.
  const lastSafe = records(signer, { sequence: MAX_SAFE - 1, headHash: 'e'.repeat(64) }, 1);
  add('reject-end-beyond-max-safe', {
    base: { sequence: MAX_SAFE - 1, headHash: 'e'.repeat(64) },
    records: [lastSafe[0], lastSafe[0]],
    checkpoint: cp,
  });
  add('reject-gap', { ...ok, records: [tail[0], tail[2]] });
  add('reject-reorder', { ...ok, records: [tail[1], tail[0], tail[2]] });
  const fork = records(signer, { sequence: 3, headHash: 'c'.repeat(64) }, 3, 'f');
  add('reject-fork', { base, records: fork, checkpoint: checkpoint(signer, head(base, fork)) });
  const tampered = clone(tail);
  tampered[1].payload.eventType = 'ALTERED';
  add('reject-tampered-record', { ...ok, records: tampered });
  add('reject-foreign-key-record', { ...ok, records: records(other, base, 3) });
  add('reject-truncated-range', { ...ok, records: tail.slice(0, 2) });
  add('reject-checkpoint-hash', {
    ...ok,
    checkpoint: checkpoint(signer, { sequence: 6, headHash: 'd'.repeat(64) }),
  });
  add('reject-checkpoint-foreign-key', { ...ok, checkpoint: checkpoint(other, head(base, tail)) });
  add('reject-extra-member', { ...ok, extra: true });
  add('reject-base-extra-member', { ...ok, base: { ...base, extra: 1 } });
  add('reject-base-negative', { ...ok, base: { sequence: -1, headHash: base.headHash } });
  add('reject-base-fraction', { ...ok, base: { sequence: 1.5, headHash: base.headHash } });
  add('reject-base-uppercase-hash', {
    ...ok,
    base: { ...base, headHash: base.headHash.toUpperCase() },
  });
  add('reject-base-genesis-mismatch', { ...ok, base: { sequence: 0, headHash: base.headHash } });
  add('reject-base-zero-hash-nonzero-sequence', {
    ...ok,
    base: { sequence: 3, headHash: GENESIS },
  });
  add('reject-records-not-array', { ...ok, records: {} });
  add('reject-over-limit', ok, { maxRecords: 2 });
  add('reject-not-object', '[]');
  add('reject-invalid-record-payload', {
    ...ok,
    records: [packet(signer, [1]), ...tail.slice(1)],
  });
  add('reject-record-event-type', {
    ...ok,
    records: records(signer, base, 1).map((r) => packet(signer, { ...r.payload, eventType: '' })),
    checkpoint: cp,
  });
  return cases;
}

/** Executes the reference on each case and records its outcome. */
function evaluate(cases) {
  return cases.map((c) => {
    try {
      const result = verifyEvidenceRange(JSON.parse(c.input), JSON.parse(c.key), {
        ...(c.maxRecords === undefined ? {} : { maxRecords: c.maxRecords }),
      });
      return { ...c, expect: { valid: true, stdout: JSON.stringify(result, null, 2) + '\n' } };
    } catch (error) {
      return { ...c, expect: { valid: false, error: error.message } };
    }
  });
}

/** Printable-ASCII JSON (same convention as scripts/evidence-vectors.mjs). */
function asciiJson(value) {
  return (
    JSON.stringify(value, null, 2).replace(
      /[^ -~\n]/g,
      (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
    ) + '\n'
  );
}

const file = {
  format: 'SIEPMU-EVIDENCE-RANGE-v1 test vectors',
  specification: 'spec/SIEPMU-EVIDENCE-RANGE-v1.md',
  reference: 'apps/verifier/verify.mjs verifyEvidenceRange',
  notes: [
    'Synthetic data. Keys are generated per regeneration; no private key is stored.',
    'maxRecords, when present, is passed as the record limit; otherwise the default (4096) applies.',
    'expect.stdout is JSON.stringify(result, null, 2) plus a newline; expect.error is the normative message.',
  ],
  cases: evaluate(buildCases()),
};

if (process.argv.includes('--check')) {
  const committed = JSON.parse(readFileSync(output, 'utf8'));
  const shape = (c) => `${c.id}:${c.expect.valid}:${c.expect.error ?? ''}`;
  const same = committed.cases.map(shape).join('\n') === file.cases.map(shape).join('\n');
  if (!same) console.error('evidence-range-v1.json: committed outcomes differ from the reference');
  process.exitCode = same ? 0 : 1;
} else {
  writeFileSync(output, asciiJson(file));
  console.log(`Wrote ${file.cases.length} cases to ${output}`);
}
