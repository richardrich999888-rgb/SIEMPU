import { exactMembers } from './incremental.mjs';
import { keyId, publicJwk, validateKey, verifyPacket, packet } from '../control/primitives.mjs';

export const FENCED_CUSTODY_VERSION = 3;
const insist = (ok, code) => {
  if (!ok) throw new Error(code);
};
export function validGeneration(value) {
  return Number.isSafeInteger(value) && value > 0;
}
export function validateAuthorityFloor(value) {
  insist(
    exactMembers(value, ['epoch', 'revocationVersion']) &&
      validGeneration(value.epoch) &&
      Number.isSafeInteger(value.revocationVersion) &&
      value.revocationVersion >= 0,
    'FENCE_AUTHORITY_STATE_INVALID',
  );
  return value;
}
export function validateWriterPublicKey(key) {
  insist(key && !Object.hasOwn(key, 'd'), 'FENCE_PUBLIC_KEY_REQUIRED');
  validateKey(key);
  return publicJwk(key);
}
export function normalizeWriter(writer) {
  insist(
    exactMembers(writer, ['key', 'generation']) && validGeneration(writer.generation),
    'FENCE_CONFIG_INVALID',
  );
  insist(typeof writer.key?.d === 'string', 'FENCE_PRIVATE_KEY_REQUIRED');
  const key = structuredClone(writer.key);
  validateKey(publicJwk(key));
  // Validate the configured private key at startup, without exposing the probe or key.
  const probe = packet(key, { kind: 'WRITER_KEY_SELF_TEST' });
  insist(verifyPacket(publicJwk(key), probe), 'FENCE_KEY_INVALID');
  return Object.freeze({ key: Object.freeze(key), generation: writer.generation });
}
export function fencedRequest(writer, authority, request) {
  const row = authority.epoch();
  return packet(writer.key, {
    version: FENCED_CUSTODY_VERSION,
    kind: 'FENCED_CHECKPOINT',
    generation: writer.generation,
    authority: { epoch: row.epoch, revocationVersion: row.revocation_version },
    request,
  });
}
export function validateFencedRequest(envelope, fence) {
  insist(fence, 'FENCE_STATE_MISSING');
  const p = envelope?.payload;
  insist(
    exactMembers(p, ['version', 'kind', 'generation', 'authority', 'request']) &&
      p.version === FENCED_CUSTODY_VERSION &&
      p.kind === 'FENCED_CHECKPOINT' &&
      validGeneration(p.generation),
    'FENCE_REQUEST_INVALID',
  );
  validateAuthorityFloor(p.authority);
  insist(
    p.generation === fence.generation && verifyPacket(JSON.parse(fence.public_key), envelope),
    'WRITER_FENCED',
  );
  return { writerKeyId: envelope.keyId, generation: p.generation, authority: p.authority };
}
export function checkWriterFence(fence, context) {
  insist(fence && context, 'FENCING_REQUIRED');
  insist(
    fence.generation === context.generation &&
      keyId(JSON.parse(fence.public_key)) === context.writerKeyId,
    'WRITER_FENCED',
  );
  insist(
    context.authority.epoch >= fence.epoch &&
      context.authority.revocationVersion >= fence.revocation_version,
    'AUTHORITY_EPOCH_ROLLBACK',
  );
}
export function unwrapFencedLease(response, writer, custodianKey, authority) {
  insist(verifyPacket(custodianKey, response), 'CUSTODIAN_SIGNATURE');
  const p = response.payload,
    row = authority.epoch();
  insist(
    exactMembers(p, ['version', 'kind', 'generation', 'writerKeyId', 'authority', 'lease']) &&
      p.version === FENCED_CUSTODY_VERSION &&
      p.kind === 'FENCED_LEASE' &&
      p.generation === writer.generation &&
      p.writerKeyId === keyId(publicJwk(writer.key)),
    'FENCE_LEASE_INVALID',
  );
  validateAuthorityFloor(p.authority);
  insist(
    p.authority.epoch === row.epoch && p.authority.revocationVersion === row.revocation_version,
    'FENCE_LEASE_STATE_MISMATCH',
  );
  return p.lease;
}
