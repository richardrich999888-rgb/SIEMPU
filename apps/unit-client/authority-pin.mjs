import { publicJwk } from '../../packages/crypto/crypto.mjs';

/** Accept only the exact public P-256 key schema used by authority trust.
 * Reject extra fields before they can enter trust or offline metadata persistence.
 * Curve-point validity is additionally checked by publicAuthorityKey in trust.mjs.
 * @param {JsonWebKey} candidate
 */
export function authorityPublicJwk(candidate) {
  if (
    !candidate ||
    typeof candidate !== 'object' ||
    Array.isArray(candidate) ||
    'd' in candidate ||
    Object.keys(candidate).sort().join(',') !== 'crv,kty,x,y'
  )
    throw new TypeError(
      'Expected an exact public P-256 authority key with no private or extra fields.',
    );
  return publicJwk(candidate);
}
