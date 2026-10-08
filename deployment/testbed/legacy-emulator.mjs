/** Independent synthetic legacy peer. Uses Node crypto, not adapter/canonical implementation. */
import { createHash, createPrivateKey, sign, randomUUID } from 'node:crypto';
const encode = (v) =>
  v && typeof v === 'object'
    ? Array.isArray(v)
      ? `[${v.map(encode).join(',')}]`
      : `{${Object.keys(v)
          .sort()
          .map((k) => `${JSON.stringify(k)}:${encode(v[k])}`)
          .join(',')}}`
    : JSON.stringify(v);
export function signSyntheticSubmission({
  sourceId,
  signingKey,
  signingPublicKey,
  submission,
  idempotencyKey = randomUUID(),
  nonce = randomUUID(),
  now = Date.now(),
}) {
  const context = {
    protocol: 'SIEPMU-SYNTHETIC-INGRESS',
    version: 1,
    sourceId,
    keyId: createHash('sha256').update(encode(signingPublicKey)).digest('hex'),
    nonce,
    idempotencyKey,
    issuedAt: now,
    expiresAt: now + 60000,
    submission,
  };
  const signature = sign('sha256', Buffer.from(encode(context)), {
    key: createPrivateKey({ key: signingKey, format: 'jwk' }),
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  return { context, signature };
}
