#!/usr/bin/env node
/**
 * Generates the language-neutral SIEPMU-CJSON-v1 and SIEPMU-EVIDENCE-v1 test vectors in
 * spec/vectors/ from the Node reference implementation.
 *
 * Every expected outcome is captured by executing the reference (canonical() and the
 * apps/verifier CLI); none is written by hand. A case may additionally declare a documented
 * divergence (spec/SIEPMU-EVIDENCE-v1.md §8): the reference outcome is then recorded under
 * `reference`, and `expect` holds the normative outcome for conforming implementations.
 *
 * Determinism: node:crypto ECDSA signing uses a random nonce and the signing key is generated
 * per run, so regeneration changes keys and signatures but not the case semantics. The
 * committed files are the frozen artefact; checking them is fully deterministic. No private
 * key is written anywhere.
 *
 * Usage: node scripts/evidence-vectors.mjs [--check]
 *   --check  regenerate in memory and require that every committed case still has the
 *            reference outcome recorded for it (semantic check; signatures may differ).
 */
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../packages/protocol/canonical.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const verifierCli = join(root, 'apps/verifier/verify.mjs');
const outputDir = join(root, 'spec/vectors');
const GENESIS = '0'.repeat(64);
/** P-256 group order n (SEC 2), used to construct the high-S signature variant. */
const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  return { privateKey, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}
const signText = (privateKey, text) =>
  nodeSign('sha256', Buffer.from(text), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString(
    'base64url',
  );
function packet(signer, payload, keyJwk = signer.jwk) {
  return {
    payload,
    signature: signText(signer.privateKey, canonical(payload)),
    keyId: sha256(canonical(keyJwk)),
  };
}
function chain(signer, count, epoch = 4) {
  const records = [];
  let previousHash = GENESIS;
  for (let sequence = 1; sequence <= count; sequence++) {
    const record = packet(signer, {
      sequence,
      previousHash,
      eventId: `00000000-0000-4000-8000-00000000000${sequence}`,
      eventType: 'SYNTHETIC_TEST',
      timestamp: 1700000000000 + sequence,
      epoch,
      actorId: 'synthetic',
      details: { index: sequence, note: 'synthetic vector' },
    });
    records.push(record);
    previousHash = sha256(canonical(record));
  }
  return { records, checkpoint: checkpoint(signer, count, previousHash) };
}
const checkpoint = (signer, sequence, headHash) =>
  packet(signer, { sequence, headHash, issuedAt: 1700000009999 });
const headAfter = (records, n) => (n === 0 ? GENESIS : sha256(canonical(records[n - 1])));
const clone = (value) => structuredClone(value);
const json = (value) => JSON.stringify(value);

function releasePayload(overrides = {}) {
  return {
    eventId: '11111111-1111-4111-8111-111111111111',
    eventType: 'RELEASE_ISSUED',
    decision: 'RELEASED',
    sequence: 9,
    previousHash: sha256('synthetic previous'),
    timestamp: 1700000000500,
    epoch: 7,
    objectId: '22222222-2222-4222-8222-222222222222',
    details: { objectDigest: sha256('synthetic ciphertext'), authorityEpoch: 7 },
    ...overrides,
  };
}

/** Flips the low-S form of a P1363 signature to its high-S twin: (r, s) -> (r, n - s). */
function highS(signature) {
  const raw = Buffer.from(signature, 'base64url');
  const s = BigInt('0x' + raw.subarray(32).toString('hex'));
  const flipped = (P256_ORDER - s).toString(16).padStart(64, '0');
  return Buffer.concat([raw.subarray(0, 32), Buffer.from(flipped, 'hex')]).toString('base64url');
}

function buildCases() {
  const trusted = keyPair();
  const other = keyPair();
  const key = json(trusted.jwk);
  const base = chain(trusted, 3);
  const receipt = packet(trusted, releasePayload());
  const digest = receipt.payload.details.objectDigest;
  const std = ['@input', '@key'];
  const withCheckpoint = [...std, '--checkpoint', '@checkpoint'];
  const cases = [];
  const add = (id, description, input, extra = {}) =>
    cases.push({ id, description, input, key, checkpoint: null, argv: std, ...extra });

  // ---- Accepted inputs -------------------------------------------------------------------
  add('accept-chain', 'Three-record chain with matching signed checkpoint', json(base));
  add(
    'accept-empty-chain',
    'Empty chain with sequence-0 genesis checkpoint',
    json({
      records: [],
      checkpoint: checkpoint(trusted, 0, GENESIS),
    }),
  );
  add('accept-external-prefix', 'External checkpoint saved after record 2', json(base), {
    checkpoint: json(checkpoint(trusted, 2, headAfter(base.records, 2))),
    argv: withCheckpoint,
  });
  add('accept-external-genesis', 'External checkpoint at sequence 0', json(base), {
    checkpoint: json(checkpoint(trusted, 0, GENESIS)),
    argv: withCheckpoint,
  });
  add(
    'accept-single-packet',
    'Single signed non-release packet',
    json(packet(trusted, { grant: 'synthetic', n: 1 })),
  );
  add(
    'accept-receipt-all-bindings',
    'Release receipt with digest, epoch and object ID bindings',
    json(receipt),
    {
      argv: [
        ...std,
        '--object-digest',
        digest,
        '--epoch',
        '7',
        '--object-id',
        receipt.payload.objectId,
      ],
    },
  );
  add('accept-receipt-epoch-binding', 'Release receipt with epoch binding only', json(receipt), {
    argv: [...std, '--epoch', '7'],
  });
  add(
    'accept-falsy-external-checkpoint',
    'External checkpoint file containing null counts as absent',
    json(receipt),
    {
      checkpoint: 'null',
      argv: withCheckpoint,
    },
  );
  {
    const extended = { ...trusted.jwk, alg: 'ES256', use: 'sig', kid: 'synthetic' };
    add(
      'accept-jwk-extra-members',
      'Key ID covers every JWK member, including optional ones',
      json(packet(trusted, { a: 1 }, extended)),
      {
        key: json(extended),
      },
    );
  }
  {
    // Integral number lexemes normalise before canonical encoding, so they verify.
    const c = chain(trusted, 1, 1);
    const text = json(c).replace('"epoch":1,', '"epoch":1.0e0,');
    add('accept-integral-number-lexeme', 'Signed epoch 1 transported as 1.0e0', text);
  }
  {
    const payload = { '\uff61': 'half-width', '\u{1f600}': 'emoji', ctl: '\u0000\u001f\u007f "\\' };
    add(
      'accept-utf16-member-order',
      'Canonical preimage uses UTF-16 member order and JSON.stringify escaping',
      json(packet(trusted, payload)),
    );
  }
  {
    const p = packet(trusted, { a: 'high-s' });
    add(
      'high-s-signature',
      'High-S twin of a valid signature (outcome recorded from the reference)',
      json({ ...p, signature: highS(p.signature) }),
    );
  }

  // ---- Chain integrity ---------------------------------------------------------------------
  {
    const t = clone(base);
    t.records[1].payload.details.index = 900;
    add('reject-tampered-payload', 'Payload altered after signing', json(t));
  }
  {
    const t = clone(base);
    [t.records[0], t.records[1]] = [t.records[1], t.records[0]];
    add('reject-reordered', 'Records 1 and 2 swapped', json(t));
  }
  {
    const t = clone(base);
    t.records.splice(1, 1);
    add('reject-deleted-record', 'Middle record removed', json(t));
  }
  {
    const t = clone(base);
    t.records.pop();
    add(
      'reject-truncated-suffix',
      'Last record removed; embedded checkpoint no longer matches',
      json(t),
    );
  }
  {
    const t = clone(base);
    t.records[1] = packet(trusted, { ...t.records[1].payload, previousHash: sha256('wrong') });
    add('reject-previous-hash', 'Re-signed record with wrong previous hash', json(t));
  }
  {
    const t = clone(base);
    t.records[0] = packet(trusted, { ...t.records[0].payload, sequence: '1' });
    add('reject-string-sequence', 'Sequence encoded as a string', json(t));
  }
  {
    const t = clone(base);
    t.records[0] = packet(trusted, { ...t.records[0].payload, eventId: '' });
    add('reject-empty-event-id', 'Empty event ID', json(t));
  }
  {
    const t = clone(base);
    t.records[0] = packet(trusted, { ...t.records[0].payload, timestamp: -1 });
    add('reject-negative-timestamp', 'Negative timestamp', json(t));
  }
  {
    const t = clone(base);
    t.records[0] = packet(trusted, 'not an object');
    add('reject-non-object-payload', 'Signed record payload is a string', json(t));
  }
  {
    const t = clone(base);
    delete t.checkpoint;
    add('reject-missing-checkpoint', 'Export without checkpoint member', json(t));
  }
  {
    const t = clone(base);
    t.checkpoint = packet(trusted, {
      ...t.checkpoint.payload,
      headHash: t.checkpoint.payload.headHash.toUpperCase(),
    });
    add('reject-uppercase-checkpoint-hash', 'Checkpoint head hash in uppercase hex', json(t));
  }
  {
    const alternate = chain(trusted, 3, 5);
    add(
      'reject-external-conflict',
      'External checkpoint from an alternate chain at the same sequence',
      json(base),
      {
        checkpoint: json(alternate.checkpoint),
        argv: withCheckpoint,
      },
    );
    add(
      'reject-external-beyond-chain',
      'External checkpoint later than the supplied chain',
      json({
        records: base.records.slice(0, 2),
        checkpoint: checkpoint(trusted, 2, headAfter(base.records, 2)),
      }),
      { checkpoint: json(base.checkpoint), argv: withCheckpoint },
    );
  }
  add(
    'reject-external-with-single-packet',
    'External checkpoint supplied with a single packet',
    json(receipt),
    {
      checkpoint: json(base.checkpoint),
      argv: withCheckpoint,
    },
  );

  // ---- Packet and signature encoding --------------------------------------------------------
  add('reject-wrong-key', 'Chain signed by a different key', json(chain(other, 2)));
  add(
    'reject-key-id-mismatch',
    'Packet key ID does not match the trusted key',
    json({ ...receipt, keyId: sha256('other') }),
  );
  add(
    'reject-extra-packet-member',
    'Packet with an extra member',
    json({ ...receipt, extra: true }),
  );
  add(
    'reject-separator-collision',
    'Member named "keyId|payload" must not satisfy the member check',
    json({ 'keyId|payload': 'x', signature: receipt.signature }),
  );
  add(
    'reject-signature-alphabet',
    'Signature with standard-alphabet characters',
    json({ ...receipt, signature: receipt.signature.slice(0, -2) + '+/' }),
  );
  add(
    'reject-signature-padding',
    'Signature with base64 padding',
    json({ ...receipt, signature: receipt.signature + '=' }),
  );
  add(
    'reject-signature-short',
    'Signature of 63 bytes',
    json({ ...receipt, signature: Buffer.alloc(63, 1).toString('base64url') }),
  );
  add(
    'reject-signature-zero',
    'All-zero signature (r = s = 0)',
    json({ ...receipt, signature: Buffer.alloc(64).toString('base64url') }),
  );
  add(
    'reject-signature-out-of-range',
    'Signature with r, s >= n',
    json({ ...receipt, signature: Buffer.alloc(64, 0xff).toString('base64url') }),
  );
  {
    // 64 bytes encode to 86 characters; the last character carries 4 unused (zero) bits.
    // Setting the lowest one keeps the decoded bytes but makes the text non-canonical.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(receipt.signature.at(-1));
    const signature = receipt.signature.slice(0, -1) + alphabet[last | 1];
    add(
      'reject-non-canonical-trailing-bits',
      'Signature text whose unused trailing bits are set',
      json({ ...receipt, signature }),
    );
  }

  // ---- Canonical encoding of signed values ---------------------------------------------------
  add(
    'reject-float-in-payload',
    'Non-integer number in signed payload',
    json({ ...receipt, payload: { ...receipt.payload, ratio: 0.5 } }),
  );
  add(
    'reject-negative-zero',
    'Negative zero in signed payload',
    json({ ...receipt, payload: { a: 0 } }).replace('{"a":0}', '{"a":-0}'),
  );
  add(
    'reject-unsafe-integer',
    '2^53 in signed payload',
    json({ ...receipt, payload: { a: 0 } }).replace('{"a":0}', '{"a":9007199254740992}'),
  );
  {
    let deep = 1;
    for (let i = 0; i < 65; i++) deep = [deep];
    add(
      'reject-depth-65',
      'Signed payload nested beyond depth 64',
      json({ ...receipt, payload: deep }),
    );
  }

  // ---- Release bindings ---------------------------------------------------------------------
  add('reject-binding-with-chain', 'Expected bindings supplied with a chain', json(base), {
    argv: [...std, '--epoch', '4'],
  });
  add('reject-binding-digest-mismatch', 'Expected digest differs', json(receipt), {
    argv: [...std, '--object-digest', sha256('other')],
  });
  add('reject-binding-epoch-mismatch', 'Expected epoch differs', json(receipt), {
    argv: [...std, '--epoch', '8'],
  });
  add('reject-binding-object-mismatch', 'Expected object ID differs', json(receipt), {
    argv: [...std, '--object-id', 'other'],
  });
  add('reject-binding-uppercase-digest', 'Expected digest not lowercase hex', json(receipt), {
    argv: [...std, '--object-digest', digest.toUpperCase()],
  });
  add(
    'reject-binding-long-object-id',
    'Expected object ID longer than 128 UTF-16 units',
    json(receipt),
    { argv: [...std, '--object-id', 'x'.repeat(129)] },
  );
  add(
    'reject-binding-non-release',
    'Bindings against a non-release packet',
    json(packet(trusted, { eventType: 'GRANT' })),
    { argv: [...std, '--epoch', '7'] },
  );
  add(
    'reject-binding-inconsistent-epoch',
    'Receipt epoch and details.authorityEpoch disagree',
    json(packet(trusted, releasePayload({ details: { objectDigest: digest, authorityEpoch: 6 } }))),
    { argv: [...std, '--epoch', '7'] },
  );

  // ---- Trusted key ---------------------------------------------------------------------------
  add('reject-private-jwk', 'Trusted key carrying a private scalar', json(receipt), {
    key: json({ ...trusted.jwk, d: 'AA' }),
  });
  add('reject-wrong-curve', 'Trusted key on P-384', json(receipt), {
    key: json({ ...trusted.jwk, crv: 'P-384' }),
  });
  add('reject-short-coordinate', 'Trusted key coordinate of 31 bytes', json(receipt), {
    key: json({ ...trusted.jwk, x: Buffer.alloc(31, 1).toString('base64url') }),
  });
  add(
    'reject-off-curve-key',
    'Trusted key point not on P-256 (implementation-specific message)',
    json(receipt),
    {
      key: json({ ...trusted.jwk, y: Buffer.alloc(32, 1).toString('base64url') }),
    },
  );

  // ---- Input and command line ----------------------------------------------------------------
  add(
    'reject-malformed-json',
    'Truncated JSON input (implementation-specific message)',
    json(receipt).slice(0, -1),
  );
  add('reject-usage-odd-arguments', 'Option without value', json(receipt), {
    argv: [...std, '--epoch'],
  });
  add('reject-usage-unknown-option', 'Unknown option', json(receipt), {
    argv: [...std, '--fast', 'yes'],
  });
  add('reject-usage-duplicate-option', 'Repeated option', json(receipt), {
    argv: [...std, '--epoch', '7', '--epoch', '7'],
  });
  add('reject-epoch-zero', 'Expected epoch 0', json(receipt), { argv: [...std, '--epoch', '0'] });
  add('reject-replay-store-without-release', 'Replay store outside release mode', json(receipt), {
    argv: [...std, '--replay-store', 'x.sqlite'],
  });
  add('reject-release-with-checkpoint', 'Release mode combined with a checkpoint', json(receipt), {
    checkpoint: json(base.checkpoint),
    argv: [...std, '--mode', 'release', '--checkpoint', '@checkpoint'],
  });

  // ---- Documented divergences (spec §8) -------------------------------------------------------
  {
    const p = packet(trusted, { s: '\ud800' });
    add(
      'divergence-lone-surrogate',
      'D1: signed string containing a lone surrogate escape',
      json(p),
      {
        divergence: 'D1',
        normative: { status: 1, error: null },
      },
    );
  }
  {
    const p = packet(trusted, { a: 2 });
    add(
      'divergence-duplicate-member',
      'D3: duplicate member name; the reference keeps the last value',
      json(p).replace('{"a":2}', '{"a":1,"a":2}'),
      {
        divergence: 'D3',
        normative: { status: 1, error: null },
      },
    );
  }
  {
    // The reference decodes invalid UTF-8 with U+FFFD substitution; sign the substituted text
    // and transport a raw 0xFF byte in its place.
    const p = packet(trusted, { s: 'x\ufffdy' });
    const bytes = Buffer.from(json(p).replace('x\ufffdy', 'x\u0001y'), 'utf8');
    bytes[bytes.indexOf(1)] = 0xff;
    add('divergence-invalid-utf8', 'D2: invalid UTF-8 byte inside a string', null, {
      inputBase64: bytes.toString('base64'),
      divergence: 'D2',
      normative: { status: 1, error: null },
    });
  }
  return cases;
}

/** Runs the reference CLI for one case and returns {status, stdout} or {status, error}. */
function referenceOutcome(testCase, dir) {
  const paths = {
    '@input': join(dir, 'input.json'),
    '@key': join(dir, 'key.json'),
    '@checkpoint': join(dir, 'checkpoint.json'),
  };
  writeFileSync(
    paths['@input'],
    testCase.inputBase64 ? Buffer.from(testCase.inputBase64, 'base64') : testCase.input,
  );
  writeFileSync(paths['@key'], testCase.key);
  if (testCase.checkpoint !== null) writeFileSync(paths['@checkpoint'], testCase.checkpoint);
  const argv = testCase.argv.map((a) => paths[a] ?? a);
  const run = spawnSync(process.execPath, [verifierCli, ...argv], { cwd: dir, encoding: 'utf8' });
  if (run.status === 0) return { status: 0, stdout: run.stdout };
  return { status: run.status, error: JSON.parse(run.stderr).error };
}

/** Messages that come from JSON.parse or createPublicKey rather than the specification. */
const IMPLEMENTATION_SPECIFIC = new Set(['reject-off-curve-key', 'reject-malformed-json']);

function evidenceVectors() {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-vectors-'));
  try {
    const cases = buildCases().map((c) => {
      const reference = referenceOutcome(c, dir);
      const { divergence, normative, ...rest } = c;
      let expect = reference;
      if (IMPLEMENTATION_SPECIFIC.has(c.id)) expect = { status: reference.status, error: null };
      return divergence
        ? { ...rest, divergence, expect: normative, reference }
        : { ...rest, expect };
    });
    return {
      format: 'SIEPMU-EVIDENCE-v1 test vectors',
      specification: 'spec/SIEPMU-EVIDENCE-v1.md',
      reference: 'apps/verifier/verify.mjs (general mode)',
      notes: [
        'Synthetic data. Keys are generated per regeneration; no private key is stored.',
        'argv placeholders @input, @key and @checkpoint denote file paths holding input (or inputBase64 bytes), key and checkpoint.',
        'expect.error null means rejection is required but the message is implementation-specific.',
        'divergence cases: expect is normative; reference is the Node outcome (spec section 8).',
      ],
      cases,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function canonicalVectors() {
  const inputs = [
    ['object-order', '{"b":1,"a":2,"c":{"z":null,"y":[3,2,1]}}'],
    ['utf16-order', '{"\uff61":1,"\u{1f600}":2,"a":3}'],
    ['escapes', '"\\u0000\\u0008\\t\\n\\u000b\\f\\r\\u001f \\" \\\\ \\/ \\u007f \\u2028 \\u00e9"'],
    ['non-ascii-literal', '"\u0939\u093f\u0928\u094d\u0926\u0940 \u{1f600}"'],
    ['integral-lexemes', '[1.0,1e2,-5E0,0.0,10e-1]'],
    ['safe-bounds', '[9007199254740991,-9007199254740991]'],
    ['empty-containers', '{"a":[],"b":{}}'],
    ['scalars', '[true,false,null,""]'],
    ['depth-64', '['.repeat(64) + '1' + ']'.repeat(64)],
    ['reject-fraction', '0.5'],
    ['reject-unsafe', '9007199254740992'],
    ['reject-negative-zero', '-0'],
    ['reject-overflow', '1e400'],
    ['reject-depth-65', '['.repeat(65) + '1' + ']'.repeat(65)],
  ];
  const cases = inputs.map(([id, input]) => {
    try {
      return { id, input, canonical: canonical(JSON.parse(input)) };
    } catch (error) {
      return { id, input, error: error.message };
    }
  });
  cases.push(
    {
      id: 'divergence-lone-surrogate',
      input: '"\\ud800"',
      error: null,
      divergence: 'D1',
      reference: { canonical: canonical(JSON.parse('"\\ud800"')) },
    },
    {
      id: 'divergence-duplicate-member',
      input: '{"a":1,"a":2}',
      error: null,
      divergence: 'D3',
      reference: { canonical: canonical(JSON.parse('{"a":1,"a":2}')) },
    },
  );
  return {
    format: 'SIEPMU-CJSON-v1 test vectors',
    specification: 'spec/SIEPMU-CJSON-v1.md',
    reference: 'packages/protocol/canonical.mjs applied to JSON.parse(input)',
    notes: ['error null means rejection is required but the message is implementation-specific.'],
    cases,
  };
}

/**
 * JSON text restricted to printable ASCII: every code unit outside U+0020..U+007E is written as a
 * \\uXXXX escape. The parsed value is identical, and the committed files pass the repository's
 * text-integrity gate (no raw controls, DEL or U+FFFD) and survive any transport re-encoding.
 */
function asciiJson(value) {
  return (
    JSON.stringify(value, null, 2).replace(
      /[^\u0020-\u007e\n]/g,
      (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
    ) + '\n'
  );
}

const files = { 'evidence-v1.json': evidenceVectors(), 'canonical-v1.json': canonicalVectors() };
if (process.argv.includes('--check')) {
  // Semantic check: the committed vectors must name the same cases with the same outcome class.
  let failed = false;
  for (const [name, fresh] of Object.entries(files)) {
    const committed = JSON.parse(readFileSync(join(outputDir, name), 'utf8'));
    const shape = (c) =>
      `${c.id}:${c.expect?.status ?? ''}:${c.expect?.error ?? c.error ?? c.canonical ?? ''}`;
    const a = committed.cases.map(shape).join('\n');
    const b = fresh.cases.map(shape).join('\n');
    if (a !== b) {
      console.error(`${name}: committed vectors no longer match the reference outcome classes`);
      failed = true;
    }
  }
  process.exitCode = failed ? 1 : 0;
} else {
  mkdirSync(outputDir, { recursive: true });
  for (const [name, content] of Object.entries(files))
    writeFileSync(join(outputDir, name), asciiJson(content));
  console.log(`Wrote ${Object.keys(files).join(', ')} to ${outputDir}`);
}
