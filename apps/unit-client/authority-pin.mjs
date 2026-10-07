import { publicJwk } from '../../packages/crypto/crypto.mjs';

/** Public trust material is intentionally durable; credentials never belong here.
 * Project the exact P-256 public coordinates so unrelated imported properties
 * cannot accidentally be persisted beside the authority pin.
 * @param {JsonWebKey} candidate
 */
export function authorityPublicJwk(candidate) {
  if (!candidate || typeof candidate !== 'object' || 'd' in candidate)
    throw new TypeError('Authority pin must contain only public key material');
  return publicJwk(candidate);
}
