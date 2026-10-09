// Deterministic failure-mode checks. All inputs are fixed byte patterns; no randomness is
// drawn by this module. (ECDSA signing draws its nonce inside OpenSSL; the verdicts asserted
// here do not depend on that nonce.)

import { createECDH, createHash, createPrivateKey, sign as nodeSign } from 'node:crypto';
import { STATUS } from './core/verdict.mjs';

/** Byte pattern start, start+1, ... (mod 256). */
export const pattern = (length, start) => Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);

const flip = (bytes, index) => {
  const copy = Uint8Array.from(bytes);
  copy[index < 0 ? copy.length + index : index] ^= 0x01;
  return copy;
};

/** Runs a check expecting rejection; acceptance or an unexpected value is FAIL. */
async function expectRejected(algorithm, check, attempt) {
  try {
    await attempt();
    return { algorithm, check, status: STATUS.FAIL, detail: 'accepted' };
  } catch (error) {
    return { algorithm, check, status: STATUS.PASS, detail: `rejected (${error.name})` };
  }
}

/** AES-256-GCM: corrupted tag, corrupted ciphertext, wrong key, truncation, wrong AAD/IV. */
export async function aesGcmFailureModes(adapter) {
  const A = 'AES-256-GCM';
  const key = pattern(32, 0x00);
  const iv = pattern(12, 0xa0);
  const aad = new TextEncoder().encode('SIEPMU KAT AAD');
  const pt = new TextEncoder().encode('SIEPMU KAT failure-mode plaintext (synthetic)');
  const tagBits = 128;
  const sealed = await adapter.aesGcmEncrypt({ key, iv, aad, pt, tagBits });
  const open = (overrides) =>
    adapter.aesGcmDecrypt({ key, iv, aad, ctAndTag: sealed, tagBits, ...overrides });
  const results = [];
  const roundTrip = Buffer.from(await open({})).equals(Buffer.from(pt));
  results.push({
    algorithm: A,
    check: 'control: unmodified ciphertext decrypts to the original plaintext',
    status: roundTrip ? STATUS.PASS : STATUS.FAIL,
    detail: roundTrip ? 'round trip exact' : 'round trip mismatch',
  });
  for (const [check, overrides] of [
    ['corrupted tag (last byte flipped)', { ctAndTag: flip(sealed, -1) }],
    ['corrupted ciphertext (first byte flipped)', { ctAndTag: flip(sealed, 0) }],
    ['wrong key (one bit differs)', { key: flip(key, 0) }],
    [
      'truncated ciphertext (last byte removed)',
      { ctAndTag: sealed.subarray(0, sealed.length - 1) },
    ],
    ['truncated below tag length (15 bytes)', { ctAndTag: sealed.subarray(0, 15) }],
    ['wrong additional data', { aad: flip(aad, 0) }],
    ['wrong IV', { iv: flip(iv, 0) }],
  ])
    results.push(await expectRejected(A, check, () => open(overrides)));
  return results;
}

/** Deterministic P-256 key from a label: d = SHA-256(label) (valid scalar with overwhelming probability). */
export function deterministicP256(label) {
  const d = createHash('sha256').update(label).digest();
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey(null, 'uncompressed');
  return { d, qx: pub.subarray(1, 33), qy: pub.subarray(33, 65) };
}

/** ECDSA P-256/SHA-256: modified message, modified signature, wrong key, truncated signature. */
export async function ecdsaFailureModes(adapter) {
  const A = 'ECDSA P-256 / SHA-256';
  const k1 = deterministicP256('SIEPMU-KAT-ECDSA-NEGATIVE-1');
  const k2 = deterministicP256('SIEPMU-KAT-ECDSA-NEGATIVE-2');
  const msg = new TextEncoder().encode('SIEPMU KAT ECDSA message (synthetic)');
  const priv = createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: k1.d.toString('base64url'),
      x: k1.qx.toString('base64url'),
      y: k1.qy.toString('base64url'),
    },
    format: 'jwk',
  });
  const sig = nodeSign('sha256', msg, { key: priv, dsaEncoding: 'ieee-p1363' });
  const r = sig.subarray(0, 32);
  const s = sig.subarray(32, 64);
  const results = [];
  for (const [name, verify] of [
    ['WebCrypto', adapter.ecdsaVerifyWeb],
    ['node:crypto', adapter.ecdsaVerifyNode],
  ]) {
    const ok = await verify({ qx: k1.qx, qy: k1.qy, msg, r, s });
    results.push({
      algorithm: A,
      check: `control (${name}): valid signature verifies`,
      status: ok ? STATUS.PASS : STATUS.FAIL,
      detail: ok ? 'accepted' : 'rejected a valid signature',
    });
    for (const [check, input] of [
      ['modified message', { qx: k1.qx, qy: k1.qy, msg: flip(msg, 0), r, s }],
      [
        'modified signature (s bit flipped)',
        { qx: k1.qx, qy: k1.qy, msg, r, s: Buffer.from(flip(s, -1)) },
      ],
      ['wrong public key', { qx: k2.qx, qy: k2.qy, msg, r, s }],
      ['public key not on curve', { qx: k1.qx, qy: Buffer.from(flip(k1.qy, -1)), msg, r, s }],
    ]) {
      let accepted;
      try {
        accepted = await verify(input);
      } catch {
        accepted = false;
      }
      results.push({
        algorithm: A,
        check: `${check} (${name})`,
        status: accepted ? STATUS.FAIL : STATUS.PASS,
        detail: accepted ? 'accepted' : 'rejected',
      });
    }
  }
  return results;
}

/** X-Wing: a corrupted ciphertext must not yield the vector's shared secret (implicit rejection). */
export function xwingFailureModes(kem, vector) {
  const A = 'X-Wing hybrid KEM';
  const hex = (s) => Buffer.from(s, 'hex');
  const pair = kem.keygen(hex(vector.seed));
  const results = [];
  for (const [check, ct] of [
    ['corrupted ciphertext, ML-KEM part (byte 0 flipped)', flip(hex(vector.ct), 0)],
    ['corrupted ciphertext, X25519 part (last byte flipped)', flip(hex(vector.ct), -1)],
  ]) {
    let ss = null;
    try {
      ss = Buffer.from(kem.decapsulate(ct, pair.secretKey)).toString('hex');
    } catch {
      ss = null;
    }
    const pass = ss !== vector.ss;
    results.push({
      algorithm: A,
      check,
      status: pass ? STATUS.PASS : STATUS.FAIL,
      detail:
        ss === null ? 'rejected (error)' : pass ? 'different shared secret' : 'same shared secret',
    });
  }
  let truncatedAccepted = true;
  try {
    kem.decapsulate(hex(vector.ct).subarray(0, 100), pair.secretKey);
  } catch {
    truncatedAccepted = false;
  }
  results.push({
    algorithm: A,
    check: 'truncated ciphertext (100 bytes)',
    status: truncatedAccepted ? STATUS.FAIL : STATUS.PASS,
    detail: truncatedAccepted ? 'accepted' : 'rejected (error)',
  });
  return results;
}
