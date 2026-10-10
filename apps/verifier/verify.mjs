#!/usr/bin/env node
/** Offline verification: no service, credentials, or authority database required. */
import { createHash, createPublicKey, verify as nativeVerify } from 'node:crypto';
import { open } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { canonical } from '../../packages/protocol/canonical.mjs';

const GENESIS = '0'.repeat(64);
const digest = (value) => createHash('sha256').update(canonical(value)).digest('hex');
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
function keys(value, names) {
  assert(value && typeof value === 'object' && !Array.isArray(value), 'Expected object');
  // Compare member lists element-wise. Joining with a separator is ambiguous: a single member
  // named "keyId|payload" would otherwise satisfy the expected pair "keyId", "payload".
  const actual = Object.keys(value).sort();
  const expected = [...names].sort();
  assert(
    actual.length === expected.length && actual.every((name, index) => name === expected[index]),
    'Unexpected or missing packet members',
  );
}
function signatureBytes(value) {
  assert(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), 'Invalid signature encoding');
  const raw = Buffer.from(value, 'base64url');
  assert(raw.length === 64 && raw.toString('base64url') === value, 'Invalid P1363 signature');
  return raw;
}
function trustedVerifier(publicJwk) {
  assert(
    publicJwk?.kty === 'EC' && publicJwk?.crv === 'P-256' && !('d' in publicJwk),
    'Trusted key must be public P-256 JWK',
  );
  for (const part of ['x', 'y']) {
    assert(typeof publicJwk[part] === 'string', 'Invalid trusted key coordinate');
    const coordinate = Buffer.from(publicJwk[part], 'base64url');
    assert(
      coordinate.length === 32 && coordinate.toString('base64url') === publicJwk[part],
      'Invalid trusted key coordinate',
    );
  }
  const key = createPublicKey({ key: publicJwk, format: 'jwk' });
  const expectedKeyId = digest(publicJwk);
  return (packet) => {
    keys(packet, ['payload', 'signature', 'keyId']);
    assert(packet.keyId === expectedKeyId, 'Signing key ID mismatch');
    assert(
      nativeVerify(
        'sha256',
        Buffer.from(canonical(packet.payload)),
        { key, dsaEncoding: 'ieee-p1363' },
        signatureBytes(packet.signature),
      ),
      'Signature invalid',
    );
    return packet.payload;
  };
}
function checkpointPayload(packet, verify) {
  const payload = verify(packet);
  keys(payload, ['sequence', 'headHash', 'issuedAt']);
  assert(
    Number.isSafeInteger(payload.sequence) && payload.sequence >= 0,
    'Invalid checkpoint sequence',
  );
  assert(
    Number.isSafeInteger(payload.issuedAt) && payload.issuedAt >= 0,
    'Invalid checkpoint time',
  );
  assert(
    typeof payload.headHash === 'string' && /^[0-9a-f]{64}$/.test(payload.headHash),
    'Invalid checkpoint hash',
  );
  return payload;
}
function expectedBindings(payload, { objectDigest, epoch, objectId }) {
  assert(
    payload?.eventType === 'RELEASE_ISSUED' && payload?.decision === 'RELEASED',
    'Expected a release issuance receipt for object binding checks',
  );
  assert(
    typeof payload.details?.objectDigest === 'string' &&
      /^[0-9a-f]{64}$/.test(payload.details.objectDigest),
    'Receipt lacks a valid object digest',
  );
  assert(
    Number.isSafeInteger(payload.epoch) &&
      payload.epoch > 0 &&
      payload.details?.authorityEpoch === payload.epoch,
    'Receipt authority epoch is missing or inconsistent',
  );
  assert(
    typeof payload.objectId === 'string' && payload.objectId.length > 0,
    'Receipt lacks an object ID',
  );
  const checked = {};
  if (objectDigest !== undefined) {
    assert(
      typeof objectDigest === 'string' && /^[0-9a-f]{64}$/.test(objectDigest),
      'Expected object digest must be lowercase SHA-256 hex',
    );
    assert(payload.details.objectDigest === objectDigest, 'Expected object digest mismatch');
    checked.objectDigest = objectDigest;
  }
  if (epoch !== undefined) {
    assert(
      Number.isSafeInteger(epoch) && epoch > 0,
      'Expected epoch must be a positive safe integer',
    );
    assert(payload.details.authorityEpoch === epoch, 'Expected authority epoch mismatch');
    checked.authorityEpoch = epoch;
  }
  if (objectId !== undefined) {
    assert(
      typeof objectId === 'string' && objectId.length > 0 && objectId.length <= 128,
      'Invalid expected object ID',
    );
    assert(payload.objectId === objectId, 'Expected object ID mismatch');
    checked.objectId = objectId;
  }
  return checked;
}

// Laboratory v3 provenance. The suite table is deliberately duplicated here rather than
// imported from the authority's modules, so a defect there cannot silently widen what the
// independent verifier accepts.
const LAB_SUITES = Object.freeze({
  'ML-KEM-768-ML-DSA-65-AES-256-GCM-v1': 'node-openssl-pqc-lab',
  'ML-KEM-1024-ML-DSA-65-AES-256-GCM-v1': 'node-openssl-pqc-lab',
  'X-WING-ML-DSA-65-AES-256-GCM-v1': 'noble-xwing-lab',
});
function strictCryptoEvidence(value) {
  keys(value, [
    'envelopeVersion',
    'providerId',
    'suiteId',
    'suiteVersion',
    'senderKeyId',
    'recipientKeyId',
    'creationPolicyRevision',
    'currentPolicyRevision',
    'policyDigest',
  ]);
  assert(value.envelopeVersion === 3 && value.suiteVersion === 1, 'Invalid crypto version');
  assert(
    Object.hasOwn(LAB_SUITES, value.suiteId) && LAB_SUITES[value.suiteId] === value.providerId,
    'Unsupported crypto provider or suite',
  );
  for (const field of ['senderKeyId', 'recipientKeyId', 'policyDigest'])
    assert(
      typeof value[field] === 'string' && /^[a-f0-9]{64}$/.test(value[field]),
      `Invalid crypto ${field}`,
    );
  assert(
    Number.isSafeInteger(value.creationPolicyRevision) &&
      value.creationPolicyRevision > 0 &&
      Number.isSafeInteger(value.currentPolicyRevision) &&
      value.currentPolicyRevision >= value.creationPolicyRevision,
    'Invalid crypto policy revision',
  );
}

// Intentionally independent of the admission service's evidence constructor.
// Strict release mode accepts the current HTTP issuance schema only; legacy
// packets remain inspectable through verifyEvidence without acceptance.
function strictReleaseSchema(payload) {
  const uuid = (value) =>
    typeof value === 'string' &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
  const sha256 = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  assert(uuid(payload.eventId), 'Receipt lacks a valid event ID');
  keys(payload, [
    'sequence',
    'previousHash',
    'eventId',
    'eventType',
    'timestamp',
    'epoch',
    'actorId',
    'decisionId',
    'objectId',
    'decision',
    'releaseState',
    'reason',
    'details',
  ]);
  for (const field of ['decisionId', 'objectId', 'actorId']) {
    assert(uuid(payload[field]), `Invalid release ${field}`);
  }
  assert(
    Number.isSafeInteger(payload.sequence) && payload.sequence > 0,
    'Invalid release sequence',
  );
  assert(sha256(payload.previousHash), 'Invalid release previous hash');
  assert(
    (payload.sequence === 1) === (payload.previousHash === GENESIS),
    'Inconsistent release genesis reference',
  );
  assert(
    Number.isSafeInteger(payload.timestamp) && payload.timestamp >= 0,
    'Invalid release timestamp',
  );
  assert(payload.releaseState === 'RELEASED', 'Invalid release state');
  assert(payload.reason === 'CURRENT_AUTHORITY_VALID', 'Invalid release reason');
  const d = payload.details;
  keys(d, [
    'objectDigest',
    'envelopeDigest',
    ...(Object.hasOwn(d, 'objectSchemaVersion') ? ['objectSchemaVersion'] : []),
    'senderUserId',
    'senderDeviceId',
    'recipientUserId',
    'recipientDeviceId',
    'destinationUnitId',
    'missionId',
    'action',
    'creationGrantId',
    'creationEpoch',
    'creationPolicyDigest',
    'policyReference',
    'policyDigest',
    'revocationVersion',
    'authorityEpoch',
    'deviceEvidence',
    'proofEvidence',
    ...(Object.hasOwn(d, 'crypto') ? ['crypto'] : []),
  ]);
  if (Object.hasOwn(d, 'objectSchemaVersion'))
    assert([1, 2, 3].includes(d.objectSchemaVersion), 'Invalid object schema version');
  // A v3 release must carry provenance, and provenance is only valid on a v3 release.
  assert(
    (d.objectSchemaVersion === 3) === Object.hasOwn(d, 'crypto'),
    'Crypto provenance and object schema version disagree',
  );
  if (Object.hasOwn(d, 'crypto')) strictCryptoEvidence(d.crypto);
  for (const field of ['objectDigest', 'envelopeDigest', 'creationPolicyDigest', 'policyDigest']) {
    assert(sha256(d[field]), `Invalid release ${field}`);
  }
  for (const field of [
    'senderUserId',
    'senderDeviceId',
    'recipientUserId',
    'recipientDeviceId',
    'destinationUnitId',
    'creationGrantId',
  ]) {
    assert(uuid(d[field]), `Invalid release ${field}`);
  }
  assert(payload.actorId === d.recipientUserId, 'Release actor and recipient reference mismatch');
  assert(
    typeof d.missionId === 'string' && /^[A-Za-z0-9._:-]{1,80}$/.test(d.missionId),
    'Invalid release mission',
  );
  assert(d.action === 'deliver', 'Invalid release action');
  assert(
    Number.isSafeInteger(d.creationEpoch) &&
      d.creationEpoch > 0 &&
      d.creationEpoch <= d.authorityEpoch,
    'Invalid release creation epoch',
  );
  assert(
    Number.isSafeInteger(d.revocationVersion) && d.revocationVersion >= 0,
    'Invalid release revocation version',
  );
  keys(d.policyReference, ['fromUnitId', 'toUnitId', 'missionId']);
  assert(
    uuid(d.policyReference.fromUnitId) && uuid(d.policyReference.toUnitId),
    'Invalid release policy unit reference',
  );
  assert(
    d.policyReference.toUnitId === d.destinationUnitId &&
      d.policyReference.missionId === d.missionId,
    'Release policy reference mismatch',
  );
  assert(d.deviceEvidence === 'software-proof-of-possession', 'Invalid release device evidence');
  keys(d.proofEvidence, ['challengeId', 'challengeDigest', 'sessionId']);
  assert(
    uuid(d.proofEvidence.challengeId) &&
      uuid(d.proofEvidence.sessionId) &&
      sha256(d.proofEvidence.challengeDigest),
    'Invalid release proof evidence',
  );
}

/** Throws on failure. A saved external checkpoint limits undetected suffix truncation
 * to records after that checkpoint; neither signatures nor hashes establish truth.
 */
/**
 * Verifies one hash-chain link and returns its record digest (the next chain head).
 * Shared by full-chain and range verification so both apply identical record rules; the
 * messages are normative (spec/SIEPMU-EVIDENCE-v1.md §7) and use the absolute sequence.
 * @param {unknown} record signed evidence packet
 * @param {number} sequence the sequence this record must carry (1-based, absolute)
 * @param {string} previousHash digest of the preceding record, or GENESIS for sequence 1
 * @param {(packet: unknown) => any} verify trusted-key packet verifier
 */
function verifyLink(record, sequence, previousHash, verify) {
  const payload = verify(record);
  assert(
    payload && typeof payload === 'object' && !Array.isArray(payload),
    'Invalid record payload',
  );
  assert(payload.sequence === sequence, `Sequence discontinuity at record ${sequence}`);
  assert(payload.previousHash === previousHash, `Previous hash mismatch at record ${sequence}`);
  assert(
    typeof payload.eventId === 'string' &&
      payload.eventId.length > 0 &&
      typeof payload.eventType === 'string' &&
      payload.eventType.length > 0,
    'Invalid evidence event',
  );
  assert(
    Number.isSafeInteger(payload.timestamp) &&
      payload.timestamp >= 0 &&
      Number.isSafeInteger(payload.epoch) &&
      payload.epoch >= 0,
    'Invalid evidence time or epoch',
  );
  return digest(record);
}

export async function verifyEvidence(
  input,
  trustedPublicKey,
  { checkpoint: externalCheckpoint, objectDigest, epoch, objectId } = {},
) {
  const verify = trustedVerifier(trustedPublicKey);
  const checkBinding = objectDigest !== undefined || epoch !== undefined || objectId !== undefined;
  if (!Array.isArray(input?.records)) {
    assert(!externalCheckpoint, 'A chain export is required with an external checkpoint');
    const payload = verify(input);
    const checked = checkBinding
      ? expectedBindings(payload, { objectDigest, epoch, objectId })
      : undefined;
    return {
      valid: true,
      type: 'signed-packet',
      keyId: input.keyId,
      bindingVerified: checkBinding,
      ...(checked ? { expectedBindings: checked } : {}),
      limitations: [
        'Signature authenticates the packet under the supplied key; it does not prove factual truth or current authorization.',
        'Expected binding checks compare only the supplied expected values with signed receipt fields; they do not establish correctness of omitted expectations.',
      ],
    };
  }
  assert(
    !checkBinding,
    'Expected object bindings apply to a single release receipt; verify the chain separately',
  );
  keys(input, ['records', 'checkpoint']);
  assert(input.records.length <= 100000, 'Evidence export exceeds verifier record limit');
  let headHash = GENESIS;
  const hashes = [GENESIS];
  for (let index = 0; index < input.records.length; index++) {
    headHash = verifyLink(input.records[index], index + 1, headHash, verify);
    hashes.push(headHash);
  }
  const suppliedCheckpoint = checkpointPayload(input.checkpoint, verify);
  assert(
    suppliedCheckpoint.sequence === input.records.length &&
      suppliedCheckpoint.headHash === headHash,
    'Export checkpoint does not match chain head',
  );
  if (externalCheckpoint) {
    const saved = checkpointPayload(externalCheckpoint, verify);
    assert(
      saved.sequence <= input.records.length,
      'Chain truncated before externally saved checkpoint',
    );
    assert(
      hashes[saved.sequence] === saved.headHash,
      'Chain conflicts with externally saved checkpoint',
    );
  }
  return {
    valid: true,
    type: 'evidence-chain',
    records: input.records.length,
    headHash,
    checkpointVerified: true,
    externalCheckpointVerified: Boolean(externalCheckpoint),
    limitations: [
      'Authenticity is relative to the independently supplied trusted public key, not factual truth.',
      externalCheckpoint
        ? 'Suffix-truncation detection is bounded by the externally saved checkpoint.'
        : 'No external checkpoint supplied: an earlier valid chain and its checkpoint can be replayed without detection.',
      'This does not prove hardware-backed signing, reliable wall-clock time, or freedom from authority compromise.',
    ],
  };
}

/** Upper bound on records in one range; a range is an increment, never a whole history. */
export const MAX_RANGE_RECORDS = 4096;

/**
 * Verifies a contiguous evidence range that extends an already-trusted chain head.
 *
 * Input: `{ base: { sequence, headHash }, records, checkpoint }`. `base` is a head the caller
 * has verified earlier (for example an independently retained custody anchor); it is trusted
 * input, not something this function can authenticate. The range is accepted only if record i
 * carries sequence `base.sequence + i + 1`, links to the previous head by hash, verifies under
 * the trusted key, and the signed checkpoint names exactly the resulting head.
 *
 * Soundness (induction on accepted ranges): if `base` is the digest of record `base.sequence`
 * of a chain whose prefix was fully verified, then after acceptance the returned head is the
 * digest of record `checkpoint.sequence` of the same chain, extended by verified links only.
 * Cost is O(records.length), independent of `base.sequence`.
 * @param {{ base: { sequence: number, headHash: string }, records: unknown[], checkpoint: unknown }} input
 * @param {object} trustedPublicKey public P-256 JWK
 * @param {{ maxRecords?: number }} [options]
 */
export function verifyEvidenceRange(
  input,
  trustedPublicKey,
  { maxRecords = MAX_RANGE_RECORDS } = {},
) {
  const verify = trustedVerifier(trustedPublicKey);
  keys(input, ['base', 'records', 'checkpoint']);
  keys(input.base, ['sequence', 'headHash']);
  const base = input.base;
  assert(Number.isSafeInteger(base.sequence) && base.sequence >= 0, 'Invalid range base sequence');
  assert(
    typeof base.headHash === 'string' && /^[0-9a-f]{64}$/.test(base.headHash),
    'Invalid range base hash',
  );
  assert(
    (base.sequence === 0) === (base.headHash === GENESIS),
    'Inconsistent range base genesis reference',
  );
  assert(Array.isArray(input.records), 'Range records must be an array');
  assert(
    Number.isSafeInteger(maxRecords) && maxRecords > 0 && input.records.length <= maxRecords,
    'Evidence range exceeds record limit',
  );
  // Every expected sequence must be a safe integer, so implementations that parse sequences
  // as integers and the reference (which compares numbers) cannot diverge near 2^53.
  assert(
    Number.isSafeInteger(base.sequence + input.records.length),
    'Range end sequence is not a safe integer',
  );
  let headHash = base.headHash;
  for (let index = 0; index < input.records.length; index++)
    headHash = verifyLink(input.records[index], base.sequence + index + 1, headHash, verify);
  const toSequence = base.sequence + input.records.length;
  const supplied = checkpointPayload(input.checkpoint, verify);
  assert(
    supplied.sequence === toSequence && supplied.headHash === headHash,
    'Range checkpoint does not match range head',
  );
  return {
    valid: true,
    type: 'evidence-range',
    fromSequence: base.sequence,
    toSequence,
    records: input.records.length,
    headHash,
    checkpointVerified: true,
    limitations: [
      'Authenticity is relative to the independently supplied trusted public key, not factual truth.',
      'The range proves extension of the supplied base only; the base must come from an independently retained, previously verified head.',
      'This does not prove hardware-backed signing, reliable wall-clock time, or freedom from authority compromise.',
    ],
  };
}

/** Verify and consume one release issuance in a local, durable replay domain.
 * All expectations must come from independently retained context. This verifies
 * a historical decision; it never contacts or substitutes for the authority.
 */
export async function verifyReleaseReceipt(
  input,
  trustedPublicKey,
  { objectDigest, epoch, objectId, replayStore } = {},
) {
  assert(
    objectDigest !== undefined && epoch !== undefined && objectId !== undefined,
    'Strict release verification requires expected object digest, epoch and object ID',
  );
  assert(
    typeof replayStore === 'string' && replayStore.length > 0 && replayStore !== ':memory:',
    'Strict release verification requires a durable replay store path',
  );
  assert(!Array.isArray(input?.records), 'Strict release verification requires a single receipt');
  const receipt = structuredClone(input);
  const verified = await verifyEvidence(receipt, trustedPublicKey, {
    objectDigest,
    epoch,
    objectId,
  });
  strictReleaseSchema(receipt.payload);
  const eventId = receipt.payload.eventId;
  // Create new stores with owner-only permissions before SQLite opens the file.
  // The parent directory must already exist and belong to the verifier operator.
  const handle = await open(replayStore, 'a', 0o600);
  await handle.close();
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(replayStore);
  try {
    db.exec(`PRAGMA busy_timeout=10000; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS accepted_receipts(
        key_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        packet_digest TEXT NOT NULL,
        object_id TEXT NOT NULL,
        authority_epoch INTEGER NOT NULL,
        accepted_at INTEGER NOT NULL,
        PRIMARY KEY(key_id,event_id)
      ) STRICT;`);
    db.exec('BEGIN IMMEDIATE');
    try {
      const inserted = db
        .prepare(
          `INSERT OR IGNORE INTO accepted_receipts
        (key_id,event_id,packet_digest,object_id,authority_epoch,accepted_at)
        VALUES (?,?,?,?,?,?)`,
        )
        .run(receipt.keyId, eventId, digest(receipt), objectId, epoch, Date.now());
      assert(inserted.changes === 1, 'Receipt replay detected: this event was already accepted');
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  } finally {
    db.close();
  }
  return {
    ...verified,
    type: 'release-receipt',
    strictReleaseVerified: true,
    receiptId: eventId,
    replayChecked: true,
    replayRecorded: true,
    limitations: [
      ...verified.limitations,
      'Replay protection covers this trusted-key/event-ID pair only within the retained local replay store; deleting, restoring or replacing that store removes later replay history.',
      'The receipt is consumed before success is printed; a crash after commit can require operator reconciliation. No current authorization or human delivery is established.',
    ],
  };
}

async function readJSON(path) {
  const limit = 64 * 1024 * 1024;
  const file = await open(path, 'r');
  try {
    const metadata = await file.stat();
    assert(metadata.isFile(), 'Verifier input must be a regular file');
    assert(metadata.size <= limit, 'Verifier input file exceeds 64 MiB');
    const chunks = [];
    let total = 0;
    // Read the opened descriptor, not a path that can be replaced after the
    // metadata check. Bound actual bytes as well: an opened file can still grow.
    for (;;) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, limit - total + 1));
      const { bytesRead } = await file.read(chunk, 0, chunk.length, null);
      if (!bytesRead) break;
      total += bytesRead;
      assert(total <= limit, 'Verifier input file exceeds 64 MiB');
      chunks.push(chunk.subarray(0, bytesRead));
    }
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
  } finally {
    await file.close();
  }
}
async function main(args) {
  const usage =
    'Usage: node apps/verifier/verify.mjs receipt-or-export.json trusted-public-key.json [--mode evidence|release] [--checkpoint saved-checkpoint.json] [--object-digest SHA256_HEX] [--epoch INTEGER] [--object-id ID] [--replay-store receipts.sqlite]';
  assert(args.length >= 2 && args.length % 2 === 0, usage);
  const options = {};
  for (let index = 2; index < args.length; index += 2) {
    const option = args[index],
      value = args[index + 1];
    assert(
      [
        '--mode',
        '--checkpoint',
        '--object-digest',
        '--epoch',
        '--object-id',
        '--replay-store',
      ].includes(option) &&
        !(option in options) &&
        value.length > 0,
      usage,
    );
    options[option] = value;
  }
  const mode = options['--mode'] ?? 'evidence';
  assert(['evidence', 'release'].includes(mode), usage);
  assert(
    mode !== 'release' || !options['--checkpoint'],
    'Verify chain checkpoints separately from release receipts',
  );
  assert(
    mode === 'release' || !options['--replay-store'],
    'A replay store requires --mode release',
  );
  let epoch;
  if (options['--epoch'] !== undefined) {
    assert(
      /^[1-9][0-9]*$/.test(options['--epoch']) && Number.isSafeInteger(Number(options['--epoch'])),
      'Expected epoch must be a positive safe integer',
    );
    epoch = Number(options['--epoch']);
  }
  const [input, key, saved] = await Promise.all([
    readJSON(args[0]),
    readJSON(args[1]),
    options['--checkpoint'] ? readJSON(options['--checkpoint']) : undefined,
  ]);
  const bindings = {
    objectDigest: options['--object-digest'],
    epoch,
    objectId: options['--object-id'],
  };
  const result =
    mode === 'release'
      ? await verifyReleaseReceipt(input, key, {
          ...bindings,
          replayStore: options['--replay-store'],
        })
      : await verifyEvidence(input, key, { ...bindings, checkpoint: saved });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(JSON.stringify({ valid: false, error: error.message }) + '\n');
    process.exitCode = 1;
  });
}
