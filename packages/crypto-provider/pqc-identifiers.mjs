// Public wire identifiers and strict decoders for laboratory PQC suites.
// Services (authority, verifier, evidence) import ONLY this module. They must never
// import packages/pqc-lab, which holds endpoint private-key providers and an
// unaudited third-party dependency, and is excluded from offline release bundles.

export const NATIVE_PQC_PROVIDER_ID = 'node-openssl-pqc-lab';
export const NATIVE_MLKEM768_SUITE = 'ML-KEM-768-ML-DSA-65-AES-256-GCM-v1';
export const NATIVE_MLKEM1024_SUITE = 'ML-KEM-1024-ML-DSA-65-AES-256-GCM-v1';
export const XWING_PROVIDER_ID = 'noble-xwing-lab';
export const XWING_SUITE = 'X-WING-ML-DSA-65-AES-256-GCM-v1';

// Encoded sizes in bytes, from FIPS 203 (ML-KEM encapsulation key and ciphertext),
// FIPS 204 (ML-DSA-65 public key and signature) and draft-connolly-cfrg-xwing-kem
// (X-Wing = ML-KEM-768 || X25519: 1184+32 public, 1088+32 ciphertext).
export const MLDSA65_PUBLIC_KEY_BYTES = 1952;
export const MLDSA65_SIGNATURE_BYTES = 3309;

/** Suite table keyed by suite ID. `algorithm` is the KEM; signatures are always ML-DSA-65. */
export const PQC_SUITES = new Map([
  [
    NATIVE_MLKEM768_SUITE,
    {
      providerId: NATIVE_PQC_PROVIDER_ID,
      algorithm: 'ml-kem-768',
      keyBytes: 1184,
      ciphertextBytes: 1088,
    },
  ],
  [
    NATIVE_MLKEM1024_SUITE,
    {
      providerId: NATIVE_PQC_PROVIDER_ID,
      algorithm: 'ml-kem-1024',
      keyBytes: 1568,
      ciphertextBytes: 1568,
    },
  ],
  [
    XWING_SUITE,
    { providerId: XWING_PROVIDER_ID, algorithm: 'x-wing', keyBytes: 1216, ciphertextBytes: 1120 },
  ],
]);

/**
 * Requires a plain object with exactly the named members.
 * @param {unknown} value @param {readonly string[]} fields
 */
export function exactObject(value, fields) {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== fields.length ||
    !fields.every((field) => Object.hasOwn(value, field))
  ) {
    throw new Error('Invalid public cryptographic encoding');
  }
}

/**
 * Decodes canonical unpadded base64url of an exact byte length.
 * @param {unknown} value @param {number} length
 */
export function decodeBytes(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid cryptographic byte encoding');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || bytes.toString('base64url') !== value) {
    throw new Error('Invalid cryptographic byte length or encoding');
  }
  return bytes;
}
