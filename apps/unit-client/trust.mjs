import { canonical } from '../../packages/protocol/canonical.mjs';
import { sha256 } from '../../packages/crypto/crypto.mjs';
import { authorityPublicJwk } from './authority-pin.mjs';

/** Authority trust accepts a public P-256 verification key, never arbitrary key material. */
export async function publicAuthorityKey(value) {
  const projected = authorityPublicJwk(value);
  await crypto.subtle.importKey('jwk', projected, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'verify',
  ]);
  return projected;
}

export async function authorityFingerprint(value) {
  return sha256(canonical(await publicAuthorityKey(value)));
}

/** Only this public allowlist may be cached for offline signature verification. */
export async function publicMetadata(value) {
  if (
    !value ||
    typeof value.version !== 'string' ||
    value.version.length > 80 ||
    typeof value.securityProfile !== 'string' ||
    value.securityProfile.length > 500
  )
    throw new Error('Invalid public authority metadata.');
  const serverPublicKey = await publicAuthorityKey(value.serverPublicKey);
  const serverKeyId = await authorityFingerprint(serverPublicKey);
  if (value.serverKeyId !== serverKeyId)
    throw new Error('Authority public-key fingerprint mismatch.');
  const limits = {};
  for (const name of ['objectBytes', 'sessionSeconds', 'grantSeconds']) {
    if (!Number.isSafeInteger(value.limits?.[name]) || value.limits[name] < 1)
      throw new Error('Invalid public authority limit.');
    limits[name] = value.limits[name];
  }
  return {
    version: value.version,
    serverPublicKey,
    serverKeyId,
    limits,
    securityProfile: value.securityProfile,
  };
}

/** Migrate a legacy public JWK pin once; new persistence contains only its digest. */
export async function readAuthorityPin(value) {
  if (value === null) return null;
  if (typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)) return value;
  return authorityFingerprint(value);
}
