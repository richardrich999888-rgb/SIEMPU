// Algorithm catalog for the KAT harness: what is checked, against which vector source, and
// through which product code path. Pure data. Every source named here is either a file vendored
// in this repository (with its provenance record) or a directory the operator populates with
// published vectors; nothing here asserts that a vector set exists.

/** Vendored vector provenance (see packages/pqc-lab/fixtures/PROVENANCE.md). */
export const VENDORED = Object.freeze({
  mlkemKeygen: {
    file: 'packages/pqc-lab/fixtures/nist-mlkem-keygen.json',
    source: 'NIST ACVP-Server gen-val/json-files/ML-KEM-keyGen-FIPS203 (subset)',
    version: 'usnistgov/ACVP-Server@975de31eb83d87039ec88934fdc47d8c312b892d',
    provenance: 'packages/pqc-lab/fixtures/PROVENANCE.md',
  },
  mldsaKeygen: {
    file: 'packages/pqc-lab/fixtures/nist-mldsa-keygen.json',
    source: 'NIST ACVP-Server gen-val/json-files/ML-DSA-keyGen-FIPS204 (subset)',
    version: 'usnistgov/ACVP-Server@975de31eb83d87039ec88934fdc47d8c312b892d',
    provenance: 'packages/pqc-lab/fixtures/PROVENANCE.md',
  },
  xwing: {
    file: 'packages/pqc-lab/fixtures/xwing.json',
    source: 'draft-connolly-cfrg-xwing-kem author vectors spec/test-vectors.json',
    version: 'dconnolly/draft-connolly-cfrg-xwing-kem@984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd',
    provenance: 'packages/pqc-lab/fixtures/PROVENANCE.md',
  },
});

/**
 * Operator-supplied vector directories (under ./vectors/). The harness reads only files that
 * are present; an empty or missing directory makes the set NOT-RUN with this reason.
 */
export const USER_VECTORS = Object.freeze({
  sha256: {
    dir: 'vectors/sha256',
    accepts: 'NIST CAVP SHAVS byte-oriented .rsp (SHA256ShortMsg.rsp, SHA256LongMsg.rsp)',
  },
  aesGcm: {
    dir: 'vectors/aes-256-gcm',
    accepts: 'NIST CAVP GCMVS .rsp (gcmEncryptExtIV256.rsp, gcmDecrypt256.rsp)',
  },
  hkdf: {
    dir: 'vectors/hkdf-sha256',
    accepts:
      'JSON {source, version, cases:[{id, ikm, salt, info, length, okm}]} transcribing a published set (e.g. RFC 5869 Appendix A, SHA-256 cases)',
  },
  ecdsa: {
    dir: 'vectors/ecdsa-p256',
    accepts: 'NIST CAVP FIPS 186-4 ECDSA SigVer.rsp ([P-256,SHA-256] section)',
  },
});

/** Algorithms in scope, in report order. */
export const ALGORITHMS = Object.freeze([
  {
    id: 'sha256',
    name: 'SHA-256',
    standard: 'FIPS 180-4',
    productPaths: [
      'services/control/primitives.mjs hash() (node:crypto createHash)',
      'packages/crypto/crypto.mjs (WebCrypto digest)',
    ],
  },
  {
    id: 'aes256gcm',
    name: 'AES-256-GCM',
    standard: 'FIPS 197, SP 800-38D',
    productPaths: ['packages/crypto/crypto.mjs content and key wrapping (WebCrypto, 128-bit tag)'],
  },
  {
    id: 'hkdf',
    name: 'HKDF-SHA-256',
    standard: 'RFC 5869 (SP 800-56C Rev. 2 two-step KDF)',
    productPaths: ['packages/crypto-provider/primitives.mjs deriveWrapKey (WebCrypto HKDF)'],
  },
  {
    id: 'ecdsa',
    name: 'ECDSA P-256 / SHA-256',
    standard: 'FIPS 186-4/186-5',
    productPaths: [
      'services/control/primitives.mjs sign/verify (node:crypto, IEEE P1363)',
      'packages/crypto/crypto.mjs (WebCrypto ECDSA)',
    ],
  },
  {
    id: 'mlkem768',
    name: 'ML-KEM-768',
    standard: 'FIPS 203',
    productPaths: ['packages/pqc-lab/native-provider.mjs (LAB ONLY; node:crypto)'],
  },
  {
    id: 'mlkem1024',
    name: 'ML-KEM-1024',
    standard: 'FIPS 203',
    productPaths: ['packages/pqc-lab/native-provider.mjs (LAB ONLY; node:crypto)'],
  },
  {
    id: 'mldsa65',
    name: 'ML-DSA-65',
    standard: 'FIPS 204',
    productPaths: ['packages/pqc-lab/native-provider.mjs (LAB ONLY; node:crypto)'],
  },
  {
    id: 'xwing',
    name: 'X-Wing hybrid KEM (ML-KEM-768 + X25519)',
    standard: 'draft-connolly-cfrg-xwing-kem-11 (Internet-Draft, not a standard)',
    productPaths: ['packages/pqc-lab/xwing-provider.mjs (LAB ONLY; @noble/post-quantum 0.7.1)'],
  },
  {
    id: 'overlay',
    name: 'Overlay hybrid combiner',
    standard: '—',
    productPaths: [],
  },
]);

/** Fixed NOT-RUN reasons for sets that cannot run in this repository. */
export const STRUCTURAL_NOT_RUN = Object.freeze({
  'mlkem768:encapDecap':
    'No vendored ML-KEM encapsulation/decapsulation vectors; node:crypto does not accept caller-supplied encapsulation randomness, so deterministic encapsulation KATs cannot be driven through the native path.',
  'mlkem1024:encapDecap':
    'No vendored ML-KEM encapsulation/decapsulation vectors; node:crypto does not accept caller-supplied encapsulation randomness.',
  'mldsa65:sigGenSigVer': 'No vendored ML-DSA signature generation/verification vectors.',
  'overlay:combiner':
    'No component named "Overlay" exists in this repository (searched file names and sources); the hybrid combiner present is X-Wing, reported separately.',
});
