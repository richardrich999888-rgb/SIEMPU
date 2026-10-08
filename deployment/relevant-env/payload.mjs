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

/** Block length (bytes) for the plaintext-absence scan. */
export const SCAN_BLOCK = 32;

/**
 * Forms a leaked plaintext could take in storage: raw bytes, lowercase hex, and base64 at each of
 * the three byte alignments (base64 output depends on the start offset modulo 3).
 * @param {Uint8Array} bytes
 * @returns {Buffer[]}
 */
export function plaintextRepresentations(bytes) {
  const b = Buffer.from(bytes);
  const reps = [b, Buffer.from(b.toString('hex'))];
  for (const shift of [0, 1, 2]) reps.push(Buffer.from(b.subarray(shift).toString('base64')));
  return reps;
}

/**
 * Index of every SCAN_BLOCK-aligned block of the representations, keyed by the block's first four
 * bytes. Coverage argument: any window of 2·SCAN_BLOCK − 1 or more contiguous bytes of a
 * representation contains one whole aligned block. A 64-byte plaintext window becomes ≥ 64
 * contiguous bytes in every representation (raw 64, hex 128, base64 ≥ 84 in the phase matching its
 * offset), so finding no indexed block proves no 64-byte plaintext window is present in any of
 * these forms. The scan is therefore stricter than the declared criterion.
 * @param {Buffer[]} representations
 * @returns {Map<number, Buffer[]>}
 */
export function blockIndex(representations) {
  const index = new Map();
  const seen = new Set();
  for (const rep of representations)
    for (let q = 0; q + SCAN_BLOCK <= rep.length; q += SCAN_BLOCK) {
      const block = rep.subarray(q, q + SCAN_BLOCK);
      const id = block.toString('hex');
      if (seen.has(id)) continue; // the synthetic payload repeats; keep candidate lists short
      seen.add(id);
      const key = block.readUInt32LE(0);
      if (!index.has(key)) index.set(key, []);
      index.get(key).push(block);
    }
  return index;
}

/**
 * True when `content` contains any indexed block at any byte offset.
 * @param {Buffer} content
 * @param {Map<number, Buffer[]>} index
 */
export function containsIndexedBlock(content, index) {
  for (let i = 0; i + SCAN_BLOCK <= content.length; i++) {
    const candidates = index.get(content.readUInt32LE(i));
    if (candidates?.some((c) => content.compare(c, 0, SCAN_BLOCK, i, i + SCAN_BLOCK) === 0))
      return true;
  }
  return false;
}
