// Synthetic ciphertext transport. This contract deliberately excludes the object envelope:
// forwarding its wrapped content key could disclose it before the authority permits release.
import { constants, openSync, fstatSync, closeSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import {
  canonical,
  decode,
  hash,
  verify,
  validateKey,
  verifyPacket,
} from '../../services/control/primitives.mjs';

export const TRANSFER_DOMAIN = 'SIEPMU_SEALED_TRANSPORT_V2';
export const TRANSFER_WINDOW_MS = 300000;
export const MAX_CIPHERTEXT_BYTES = 256 * 1024;
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function insist(ok, code) {
  if (!ok) throw new Error(code);
}
export function exact(value, fields) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join() === [...fields].sort().join()
  );
}
export function validateSource(source) {
  insist(
    exact(source, ['userId', 'deviceId', 'signingPublicKey']) &&
      UUID.test(source.userId) &&
      UUID.test(source.deviceId),
    'TRANSFER_SOURCE_CONFIG',
  );
  insist(exact(source.signingPublicKey, ['kty', 'crv', 'x', 'y']), 'TRANSFER_SOURCE_CONFIG');
  validateKey(source.signingPublicKey);
  return JSON.parse(canonical(source));
}
export function validateDestinations(destinations) {
  insist(
    Array.isArray(destinations) &&
      destinations.length > 0 &&
      destinations.length <= 1000 &&
      destinations.every((x) => typeof x === 'string' && UUID.test(x)) &&
      new Set(destinations).size === destinations.length,
    'TRANSFER_DESTINATION_CONFIG',
  );
  return [...destinations].sort();
}
export function privateDatabase(path) {
  if (path !== ':memory:') {
    const fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    try {
      const s = fstatSync(fd);
      insist(s.isFile() && (s.mode & 0o077) === 0, 'TRANSFER_DATABASE_PERMISSIONS');
    } finally {
      closeSync(fd);
    }
  }
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
  return db;
}
export function bindDatabase(db, configuration, table) {
  insist(['transfers', 'sealed_outbox'].includes(table), 'TRANSFER_DATABASE_TABLE');
  const digest = hash(canonical(configuration));
  db.exec(
    'CREATE TABLE IF NOT EXISTS binding(id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL);',
  );
  const row = db.prepare('SELECT digest FROM binding WHERE id=1').get();
  if (!row) {
    insist(db.prepare(`SELECT COUNT(*) n FROM ${table}`).get().n === 0, 'TRANSFER_CONFIG_MISSING');
    db.prepare('INSERT OR IGNORE INTO binding VALUES(1,?)').run(digest);
  }
  insist(
    db.prepare('SELECT digest FROM binding WHERE id=1').get().digest === digest,
    'TRANSFER_CONFIG_MISMATCH',
  );
}
export function validateTransfer(request, source, destinations, now = Date.now()) {
  insist(exact(request, ['manifest', 'signature', 'ciphertext']), 'TRANSFER_SCHEMA');
  const m = request.manifest;
  insist(
    exact(m, [
      'domain',
      'version',
      'requestId',
      'issuedAt',
      'objectId',
      'senderUserId',
      'senderDeviceId',
      'recipientUserId',
      'ciphertextHash',
    ]) &&
      m.domain === TRANSFER_DOMAIN &&
      m.version === 2,
    'TRANSFER_SCHEMA',
  );
  for (const field of [
    'requestId',
    'objectId',
    'senderUserId',
    'senderDeviceId',
    'recipientUserId',
  ])
    insist(typeof m[field] === 'string' && UUID.test(m[field]), 'TRANSFER_SCHEMA');
  insist(
    Number.isSafeInteger(m.issuedAt) && Math.abs(now - m.issuedAt) <= TRANSFER_WINDOW_MS,
    'TRANSFER_EXPIRED',
  );
  insist(
    m.senderUserId === source.userId && m.senderDeviceId === source.deviceId,
    'TRANSFER_SENDER_DENIED',
  );
  insist(destinations.includes(m.recipientUserId), 'TRANSFER_DESTINATION_DENIED');
  insist(
    typeof m.ciphertextHash === 'string' && /^[a-f0-9]{64}$/.test(m.ciphertextHash),
    'TRANSFER_SCHEMA',
  );
  insist(
    typeof request.ciphertext === 'string' &&
      request.ciphertext.length <= Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3),
    'TRANSFER_SIZE',
  );
  let bytes;
  try {
    bytes = decode(request.ciphertext);
  } catch {
    throw new Error('TRANSFER_ENCODING');
  }
  insist(
    bytes.length >= 16 && bytes.length <= MAX_CIPHERTEXT_BYTES && hash(bytes) === m.ciphertextHash,
    'TRANSFER_DIGEST',
  );
  insist(
    typeof request.signature === 'string' &&
      request.signature.length === 86 &&
      verify(source.signingPublicKey, m, request.signature),
    'TRANSFER_SIGNATURE',
  );
  return bytes;
}
export async function makeTransfer(endpoint, sealed, requestId, issuedAt) {
  const e = sealed.envelope;
  const manifest = {
    domain: TRANSFER_DOMAIN,
    version: 2,
    requestId,
    issuedAt,
    objectId: e.objectId,
    senderUserId: e.senderUserId,
    senderDeviceId: e.senderDeviceId,
    recipientUserId: e.recipientUserId,
    ciphertextHash: e.ciphertextHash,
  };
  return {
    manifest,
    signature: await endpoint.crypto.sign(endpoint.profile.keys.signing.privateKey, manifest),
    ciphertext: sealed.ciphertext,
  };
}
export function acceptedSubmission(authorityKey, result, sealed) {
  const p = result?.receipt?.payload;
  insist(
    verifyPacket(authorityKey, result?.receipt) &&
      result?.object?.id === sealed.envelope.objectId &&
      p?.eventType === 'SUBMITTED' &&
      p.objectId === sealed.envelope.objectId &&
      p.details?.objectDigest === sealed.envelope.ciphertextHash &&
      p.details?.envelopeDigest === hash(canonical(sealed.envelope)),
    'TRANSFER_ADMISSION_RECEIPT',
  );
  return result.receipt;
}
