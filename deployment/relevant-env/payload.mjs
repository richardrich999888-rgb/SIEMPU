// Deterministic synthetic payload bytes shared by the agents and the conductor. No randomness:
// integrity checks compare SHA-256 digests, and the plaintext-absence scan searches for these
// exact bytes in Host B's storage.

/**
 * @param {number} length bytes
 * @param {number} seed integer; different seeds give different byte sequences
 */
export function syntheticBytes(length, seed) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 131 + seed * 17 + ((i >> 8) ^ seed)) % 256;
  return out;
}
