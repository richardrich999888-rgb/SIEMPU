import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { canonical, hash, pair, sign } from './helpers/client.mjs';
import { verifyReleaseReceipt } from '../apps/verifier/verify.mjs';

const execute = promisify(execFile);
const cli = fileURLToPath(new URL('../apps/verifier/verify.mjs', import.meta.url));
const wrapper = fileURLToPath(new URL('../tools/verify', import.meta.url));
const packet = (payload, signer) => ({
  payload,
  signature: sign(payload, signer.privateKey),
  keyId: hash(canonical(signer.publicKey)),
});
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-detached-verifier-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const signer = pair();
  const recipientUserId = randomUUID();
  const destinationUnitId = randomUUID();
  const receipt = packet(
    {
      eventId: randomUUID(),
      eventType: 'RELEASE_ISSUED',
      decision: 'RELEASED',
      releaseState: 'RELEASED',
      decisionId: randomUUID(),
      reason: 'CURRENT_AUTHORITY_VALID',
      actorId: recipientUserId,
      sequence: 1,
      previousHash: '0'.repeat(64),
      timestamp: Date.now(),
      epoch: 7,
      objectId: randomUUID(),
      details: {
        objectDigest: hash('independently retained ciphertext'),
        authorityEpoch: 7,
        envelopeDigest: hash('independently retained envelope'),
        senderUserId: randomUUID(),
        senderDeviceId: randomUUID(),
        recipientUserId,
        recipientDeviceId: randomUUID(),
        destinationUnitId,
        missionId: 'SYNTHETIC-MISSION',
        action: 'deliver',
        creationGrantId: randomUUID(),
        creationEpoch: 6,
        creationPolicyDigest: hash('synthetic prior policy'),
        policyReference: {
          fromUnitId: randomUUID(),
          toUnitId: destinationUnitId,
          missionId: 'SYNTHETIC-MISSION',
        },
        policyDigest: hash('synthetic current policy'),
        revocationVersion: 2,
        deviceEvidence: 'software-proof-of-possession',
        proofEvidence: {
          challengeId: randomUUID(),
          challengeDigest: hash('synthetic one-use challenge'),
          sessionId: randomUUID(),
        },
      },
    },
    signer,
  );
  const receiptPath = join(dir, 'receipt.json');
  const keyPath = join(dir, 'trusted-public-key.json');
  const replayStore = join(dir, 'accepted.sqlite');
  await Promise.all([
    writeFile(receiptPath, JSON.stringify(receipt)),
    writeFile(keyPath, JSON.stringify(signer.publicKey)),
  ]);
  const bindings = {
    objectDigest: receipt.payload.details.objectDigest,
    epoch: receipt.payload.epoch,
    objectId: receipt.payload.objectId,
    replayStore,
  };
  const args = (overrides = {}) => {
    const options = {
      '--mode': 'release',
      '--object-digest': bindings.objectDigest,
      '--epoch': String(bindings.epoch),
      '--object-id': bindings.objectId,
      '--replay-store': replayStore,
      ...overrides,
    };
    return [
      receiptPath,
      keyPath,
      ...Object.entries(options)
        .filter(([, value]) => value !== undefined)
        .flat(),
    ];
  };
  const run = (overrides) => execute(process.execPath, [cli, ...args(overrides)]);
  return { dir, signer, receipt, receiptPath, keyPath, replayStore, bindings, args, run };
}
function cliFailure(expected) {
  return (error) => {
    assert.equal(error.code, 1);
    // Node may print its built-in SQLite experimental notice on stderr too.
    const line = error.stderr.split('\n').find((line) => line.startsWith('{'));
    assert.ok(line, error.stderr);
    const failure = JSON.parse(line);
    assert.equal(failure.valid, false);
    assert.match(failure.error, expected);
    return true;
  };
}

test('strict release CLI requires every binding and an explicit durable replay domain', async (t) => {
  const f = await fixture(t);
  for (const flag of ['--object-digest', '--epoch', '--object-id']) {
    await assert.rejects(f.run({ [flag]: undefined }), cliFailure(/requires expected/));
  }
  await assert.rejects(f.run({ '--replay-store': undefined }), cliFailure(/durable replay store/));
  await assert.rejects(f.run({ '--replay-store': ':memory:' }), cliFailure(/durable replay store/));
  await assert.rejects(f.run({ '--mode': 'evidence' }), cliFailure(/requires --mode release/));
  await assert.rejects(f.run({ '--mode': 'unrecognized' }), cliFailure(/Usage:/));
  await assert.rejects(
    f.run({ '--checkpoint': f.receiptPath }),
    cliFailure(/checkpoints separately/),
  );
  await assert.rejects(stat(f.replayStore), { code: 'ENOENT' });
});

test('actual strict verifier rejects wrong signatures, payload tampering, digest, epoch and object substitutions before consuming', async (t) => {
  const f = await fixture(t);
  const wrongSigner = pair();
  const wrongSignature = {
    ...f.receipt,
    signature: sign(f.receipt.payload, wrongSigner.privateKey),
  };
  const changed = structuredClone(f.receipt);
  changed.payload.details.objectDigest = 'b'.repeat(64);
  for (const invalid of [wrongSignature, changed]) {
    await writeFile(f.receiptPath, JSON.stringify(invalid));
    await assert.rejects(f.run(), cliFailure(/Signature invalid/));
  }
  await writeFile(f.receiptPath, JSON.stringify(f.receipt));
  await writeFile(f.keyPath, JSON.stringify(wrongSigner.publicKey));
  await assert.rejects(f.run(), cliFailure(/key ID mismatch/));
  await writeFile(f.keyPath, JSON.stringify(f.signer.publicKey));
  for (const [flag, value, message] of [
    ['--object-digest', 'b'.repeat(64), /object digest mismatch/],
    ['--epoch', '8', /authority epoch mismatch/],
    ['--object-id', randomUUID(), /object ID mismatch/],
  ])
    await assert.rejects(f.run({ [flag]: value }), cliFailure(message));
  await assert.rejects(stat(f.replayStore), { code: 'ENOENT' });
  const accepted = JSON.parse((await f.run()).stdout);
  assert.equal(accepted.strictReleaseVerified, true);
  assert.equal(accepted.bindingVerified, true);
  assert.equal(accepted.replayRecorded, true);
});

test('strict API rejects non-release packets, chain exports and missing receipt identity', async (t) => {
  const f = await fixture(t);
  await assert.rejects(verifyReleaseReceipt(f.receipt, f.signer.publicKey), /requires expected/);
  for (const payload of [
    { ...f.receipt.payload, eventType: 'ADMISSION' },
    { ...f.receipt.payload, decision: 'HELD' },
  ])
    await assert.rejects(
      verifyReleaseReceipt(packet(payload, f.signer), f.signer.publicKey, f.bindings),
      /release issuance/,
    );
  const missingId = { ...f.receipt.payload };
  delete missingId.eventId;
  await assert.rejects(
    verifyReleaseReceipt(packet(missingId, f.signer), f.signer.publicKey, f.bindings),
    /event ID/,
  );
  await assert.rejects(
    verifyReleaseReceipt({ records: [f.receipt] }, f.signer.publicKey, f.bindings),
    /single receipt/,
  );
});

test('receipt replay is rejected by a restarted CLI and wrapper even when re-signed', async (t) => {
  const f = await fixture(t);
  assert.equal(JSON.parse((await f.run()).stdout).strictReleaseVerified, true);
  await assert.rejects(f.run(), cliFailure(/Receipt replay detected/));
  const resigned = packet(f.receipt.payload, f.signer);
  await writeFile(f.receiptPath, JSON.stringify(resigned));
  await assert.rejects(execute(wrapper, f.args()), cliFailure(/Receipt replay detected/));
  const db = new DatabaseSync(f.replayStore, { readOnly: true });
  try {
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM accepted_receipts').get().count, 1);
    assert.equal(
      db.prepare('SELECT event_id FROM accepted_receipts').get().event_id,
      f.receipt.payload.eventId,
    );
    assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  } finally {
    db.close();
  }
  assert.equal((await stat(f.replayStore)).mode & 0o777, 0o600);
});

test('concurrent independent CLI processes atomically accept a fresh receipt once and retain the decision', async (t) => {
  const f = await fixture(t);
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => f.run()));
  const accepted = results.filter((result) => result.status === 'fulfilled');
  const rejected = results.filter((result) => result.status === 'rejected');
  assert.equal(accepted.length, 1, JSON.stringify(results));
  assert.equal(rejected.length, 7);
  for (const result of rejected) cliFailure(/Receipt replay detected/)(result.reason);
  await assert.rejects(f.run(), cliFailure(/Receipt replay detected/));
  const db = new DatabaseSync(f.replayStore, { readOnly: true });
  try {
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM accepted_receipts').get().count, 1);
  } finally {
    db.close();
  }
});

test('a distinct issuance remains acceptable in the same store while unavailable storage fails closed', async (t) => {
  const f = await fixture(t);
  await f.run();
  const next = packet(
    { ...f.receipt.payload, eventId: randomUUID(), objectId: randomUUID() },
    f.signer,
  );
  await writeFile(f.receiptPath, JSON.stringify(next));
  const accepted = await f.run({ '--object-id': next.payload.objectId });
  assert.equal(JSON.parse(accepted.stdout).receiptId, next.payload.eventId);
  const before = await readFile(f.replayStore);
  await assert.rejects(
    f.run({
      '--object-id': next.payload.objectId,
      '--replay-store': join(f.dir, 'missing', 'store.sqlite'),
    }),
    cliFailure(/ENOENT/),
  );
  assert.deepEqual(await readFile(f.replayStore), before);
  const invalidStore = join(f.dir, 'corrupt.sqlite');
  await writeFile(invalidStore, 'not a SQLite database');
  await assert.rejects(
    f.run({ '--object-id': next.payload.objectId, '--replay-store': invalidStore }),
    cliFailure(/not a database/),
  );
});

test('strict verifier rejects signed missing schema fields and contradictory release references before replay consumption', async (t) => {
  const f = await fixture(t);
  const rejectPayload = async (payload, expected = /./) =>
    assert.rejects(
      verifyReleaseReceipt(packet(payload, f.signer), f.signer.publicKey, f.bindings),
      expected,
    );
  // A signature alone must not elevate a partial or legacy packet to a complete decision.
  for (const field of Object.keys(f.receipt.payload)) {
    const payload = structuredClone(f.receipt.payload);
    delete payload[field];
    await rejectPayload(payload);
  }
  for (const field of Object.keys(f.receipt.payload.details)) {
    const payload = structuredClone(f.receipt.payload);
    delete payload.details[field];
    await rejectPayload(payload);
  }
  for (const [path, value, expected] of [
    [['decisionId'], 'invalid', /decisionId/],
    [['sequence'], 0, /sequence/],
    [['previousHash'], 'wrong', /previous hash/],
    [['sequence'], 2, /genesis/],
    [['timestamp'], -1, /timestamp/],
    [['releaseState'], 'HELD', /release state/],
    [['reason'], 'USER_REVOKED', /release reason/],
    [['actorId'], randomUUID(), /actor and recipient/],
    [['details', 'envelopeDigest'], 'wrong', /envelopeDigest/],
    [['details', 'creationPolicyDigest'], 'wrong', /creationPolicyDigest/],
    [['details', 'policyDigest'], 'wrong', /policyDigest/],
    [['details', 'senderUserId'], 'unknown', /senderUserId/],
    [['details', 'recipientDeviceId'], null, /recipientDeviceId/],
    [['details', 'missionId'], 'invalid mission', /mission/],
    [['details', 'action'], 'other', /action/],
    [['details', 'creationEpoch'], 8, /creation epoch/],
    [['details', 'revocationVersion'], -1, /revocation version/],
    [['details', 'authorityEpoch'], 6, /inconsistent/],
    [['details', 'policyReference', 'fromUnitId'], null, /policy unit/],
    [['details', 'policyReference', 'toUnitId'], randomUUID(), /policy reference mismatch/],
    [['details', 'policyReference', 'missionId'], 'OTHER', /policy reference mismatch/],
    [['details', 'deviceEvidence'], 'hardware-attested', /device evidence/],
    [['details', 'proofEvidence', 'challengeId'], null, /proof evidence/],
    [['details', 'proofEvidence', 'challengeDigest'], 'wrong', /proof evidence/],
    [['details', 'proofEvidence', 'sessionId'], 'unknown', /proof evidence/],
    [['details', 'proofEvidence'], { source: 'internal-call-no-http-proof' }, /members/],
    [['extra'], 'unexpected', /members/],
    [['details', 'extra'], 'unexpected', /members/],
  ]) {
    const payload = structuredClone(f.receipt.payload);
    let target = payload;
    for (const key of path.slice(0, -1)) target = target[key];
    target[path.at(-1)] = value;
    await rejectPayload(payload, expected);
  }
  // Exercise the CLI boundary too, including a correctly re-signed contradiction.
  for (const payload of [
    { ...f.receipt.payload, releaseState: 'HELD' },
    { ...f.receipt.payload, decisionId: 'not-a-uuid' },
    {
      ...f.receipt.payload,
      details: { ...f.receipt.payload.details, recipientUserId: randomUUID() },
    },
  ]) {
    await writeFile(f.receiptPath, JSON.stringify(packet(payload, f.signer)));
    await assert.rejects(f.run(), cliFailure(/release state|decisionId|actor and recipient/));
  }
  await assert.rejects(stat(f.replayStore), { code: 'ENOENT' });
  await writeFile(f.receiptPath, JSON.stringify(f.receipt));
  assert.equal(JSON.parse((await f.run()).stdout).strictReleaseVerified, true);
});
