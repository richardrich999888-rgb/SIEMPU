#!/usr/bin/env node
/** Offline verification: no service, credentials, or authority database required. */
import { createHash, createPublicKey, verify as nativeVerify } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
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
  assert(
    Object.keys(value).sort().join('|') === [...names].sort().join('|'),
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

/** Throws on failure. A saved external checkpoint limits undetected suffix truncation
 * to records after that checkpoint; neither signatures nor hashes establish truth.
 */
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
    const record = input.records[index];
    const payload = verify(record);
    assert(
      payload && typeof payload === 'object' && !Array.isArray(payload),
      'Invalid record payload',
    );
    assert(payload.sequence === index + 1, `Sequence discontinuity at record ${index + 1}`);
    assert(payload.previousHash === headHash, `Previous hash mismatch at record ${index + 1}`);
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
    headHash = digest(record);
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

async function readJSON(path) {
  assert((await stat(path)).size <= 64 * 1024 * 1024, 'Verifier input file exceeds 64 MiB');
  return JSON.parse(await readFile(path, 'utf8'));
}
async function main(args) {
  const usage =
    'Usage: node apps/verifier/verify.mjs receipt-or-export.json trusted-public-key.json [--checkpoint saved-checkpoint.json] [--object-digest SHA256_HEX] [--epoch INTEGER] [--object-id ID]';
  assert(args.length >= 2 && args.length % 2 === 0, usage);
  const options = {};
  for (let index = 2; index < args.length; index += 2) {
    const option = args[index],
      value = args[index + 1];
    assert(
      ['--checkpoint', '--object-digest', '--epoch', '--object-id'].includes(option) &&
        !(option in options) &&
        value.length > 0,
      usage,
    );
    options[option] = value;
  }
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
  const result = await verifyEvidence(input, key, {
    checkpoint: saved,
    objectDigest: options['--object-digest'],
    epoch,
    objectId: options['--object-id'],
  });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(JSON.stringify({ valid: false, error: error.message }) + '\n');
    process.exitCode = 1;
  });
}
