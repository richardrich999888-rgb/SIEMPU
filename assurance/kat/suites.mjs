// Vector-set executors: map parsed vector records to adapter calls and pure verdicts.
// Each executor returns {cases, failures, skipped, notRunReason}. A record whose shape is not
// supported is counted as skipped with a reason, never as a pass.

import { parseRsp } from './core/rsp.mjs';
import { compareHex, compareDecision } from './core/verdict.mjs';
import { fixedWidth, P256_COORDINATE_BYTES } from './adapters/platform.mjs';

const hex = (s) => Buffer.from(s ?? '', 'hex');

/** Runs `check(case)` for each case; collects verdicts and failure details. */
async function runCases(items, check) {
  const cases = [];
  const failures = [];
  for (const item of items) {
    let verdict;
    try {
      verdict = await check(item);
    } catch (error) {
      verdict = { pass: false, reason: `error: ${error.message}` };
    }
    cases.push(verdict);
    if (!verdict.pass) failures.push({ id: item.id, reason: verdict.reason });
  }
  return { cases, failures };
}

/**
 * CAVP SHAVS byte-oriented SHA-256 (Len/Msg/MD). Monte Carlo and bit-oriented files are
 * reported NOT-RUN.
 */
export async function sha256Rsp(text, digest) {
  const { records } = parseRsp(text);
  if (records.some((r) => 'Seed' in r.fields))
    return {
      cases: [],
      failures: [],
      skipped: 0,
      notRunReason: 'Monte Carlo (SHA256Monte) format not supported',
    };
  const items = records
    .filter((r) => 'Len' in r.fields && 'MD' in r.fields)
    .map((r, i) => ({ id: `Len=${r.fields.Len}#${i}`, ...r.fields }));
  if (items.some((r) => Number(r.Len) % 8 !== 0))
    return {
      cases: [],
      failures: [],
      skipped: 0,
      notRunReason: 'bit-oriented SHA vectors not supported',
    };
  const result = await runCases(items, async (r) =>
    compareHex(r.MD, await digest(Number(r.Len) === 0 ? new Uint8Array(0) : hex(r.Msg))),
  );
  return { ...result, skipped: records.length - items.length, notRunReason: null };
}

/** CAVP GCMVS (encrypt: Key/IV/PT/AAD → CT/Tag; decrypt: FAIL flag or PT). 256-bit keys only. */
export async function aesGcmRsp(text, aead) {
  const { records } = parseRsp(text);
  const usable = records.filter((r) => 'Key' in r.fields && 'IV' in r.fields && 'Tag' in r.fields);
  const items = usable
    .filter((r) => (r.section.Keylen ?? String(r.fields.Key.length * 4)) === '256')
    .map((r, i) => ({
      id: `Count=${r.fields.Count}/IVlen=${r.section.IVlen}/Taglen=${r.section.Taglen}#${i}`,
      key: hex(r.fields.Key),
      iv: hex(r.fields.IV),
      aad: hex(r.fields.AAD),
      pt: 'PT' in r.fields ? hex(r.fields.PT) : null,
      ct: hex(r.fields.CT),
      tag: hex(r.fields.Tag),
      tagBits: Number(r.section.Taglen ?? r.fields.Tag.length * 4),
      expectFail: r.flags.includes('FAIL'),
    }));
  const result = await runCases(items, async (c) => {
    const ctAndTag = Buffer.concat([c.ct, c.tag]);
    if (c.expectFail || c.pt === null) {
      // Decryption case.
      let plain = null;
      try {
        plain = await aead.aesGcmDecrypt({
          key: c.key,
          iv: c.iv,
          aad: c.aad,
          ctAndTag,
          tagBits: c.tagBits,
        });
      } catch {
        plain = null;
      }
      if (c.expectFail) return compareDecision(false, plain !== null);
      return { pass: false, reason: 'decrypt record without PT or FAIL' };
    }
    const encrypted = await aead.aesGcmEncrypt({
      key: c.key,
      iv: c.iv,
      aad: c.aad,
      pt: c.pt,
      tagBits: c.tagBits,
    });
    const enc = compareHex(ctAndTag.toString('hex'), encrypted);
    if (!enc.pass) return enc;
    // Every positive case is also decrypted, so both directions are exercised.
    const plain = await aead.aesGcmDecrypt({
      key: c.key,
      iv: c.iv,
      aad: c.aad,
      ctAndTag,
      tagBits: c.tagBits,
    });
    return compareHex(c.pt.toString('hex'), plain);
  });
  return { ...result, skipped: records.length - items.length, notRunReason: null };
}

/** Operator-transcribed HKDF-SHA-256 cases (JSON). */
export async function hkdfJson(text, kdf) {
  const doc = JSON.parse(text);
  if (!doc || typeof doc.source !== 'string' || !Array.isArray(doc.cases))
    throw new Error('HKDF vector file must have {source, version, cases[]}');
  const result = await runCases(
    doc.cases.map((c, i) => ({ id: c.id ?? String(i), ...c })),
    async (c) =>
      compareHex(
        c.okm,
        await kdf({
          ikm: hex(c.ikm),
          salt: hex(c.salt),
          info: hex(c.info),
          length: Number(c.length),
        }),
      ),
  );
  return {
    ...result,
    skipped: 0,
    notRunReason: null,
    source: doc.source,
    version: doc.version ?? null,
  };
}

/** CAVP FIPS 186-4 ECDSA SigVer, [P-256,SHA-256] section only. */
export async function ecdsaSigVerRsp(text, verifyFn) {
  const { records } = parseRsp(text);
  const items = records
    .filter((r) => r.section.label === 'P-256,SHA-256' && 'Result' in r.fields)
    .map((r, i) => ({
      id: `#${i}`,
      msg: hex(r.fields.Msg),
      qx: fixedWidth(r.fields.Qx, P256_COORDINATE_BYTES),
      qy: fixedWidth(r.fields.Qy, P256_COORDINATE_BYTES),
      r: fixedWidth(r.fields.R, P256_COORDINATE_BYTES),
      s: fixedWidth(r.fields.S, P256_COORDINATE_BYTES),
      expectAccept: r.fields.Result.trim().startsWith('P'),
    }));
  const result = await runCases(items, async (c) =>
    compareDecision(c.expectAccept, await verifyFn(c)),
  );
  return { ...result, skipped: records.length - items.length, notRunReason: null };
}

/** Vendored ACVP ML-KEM keyGen subset: (d || z) → ek, filtered to one parameter set. */
export async function mlkemKeygen(vectors, parameterSet, keygen) {
  const items = vectors
    .filter((v) => v.parameterSet === parameterSet)
    .map((v, i) => ({ id: v.tcId ?? `#${i}`, ...v }));
  const result = await runCases(items, async (v) =>
    compareHex(v.ek, await keygen({ parameterSet, seed: hex(v.d + v.z) })),
  );
  return { ...result, skipped: vectors.length - items.length, notRunReason: null };
}

/** Vendored ACVP ML-DSA-65 keyGen subset: seed → pk. */
export async function mldsaKeygen(vectors, keygen) {
  const result = await runCases(
    vectors.map((v, i) => ({ id: v.tcId ?? `#${i}`, ...v })),
    async (v) => compareHex(v.pk, await keygen({ seed: hex(v.seed) })),
  );
  return { ...result, skipped: 0, notRunReason: null };
}

/** X-Wing author vectors: keygen(seed) → pk, sk; encapsulate(pk, eseed) → ct, ss; decapsulate. */
export async function xwing(vectors, kem) {
  const result = await runCases(
    vectors.map((v, i) => ({ id: `#${i}`, ...v })),
    async (v) => {
      const pair = kem.keygen(hex(v.seed));
      for (const [label, expected, actual] of [
        ['pk', v.pk, pair.publicKey],
        ['sk', v.sk, pair.secretKey],
      ]) {
        const c = compareHex(expected, actual);
        if (!c.pass) return { pass: false, reason: `${label} ${c.reason}` };
      }
      const enc = kem.encapsulate(pair.publicKey, hex(v.eseed));
      for (const [label, expected, actual] of [
        ['ct', v.ct, enc.cipherText],
        ['ss', v.ss, enc.sharedSecret],
        ['decapsulated ss', v.ss, kem.decapsulate(hex(v.ct), pair.secretKey)],
      ]) {
        const c = compareHex(expected, actual);
        if (!c.pass) return { pass: false, reason: `${label} ${c.reason}` };
      }
      return { pass: true, reason: null };
    },
  );
  return { ...result, skipped: 0, notRunReason: null };
}
