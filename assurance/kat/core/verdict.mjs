// Pure comparison and aggregation for known-answer tests. No IO, no crypto.

/** Outcome vocabulary. NOT-RUN always carries a reason; it is never counted as PASS. */
export const STATUS = Object.freeze({ PASS: 'PASS', FAIL: 'FAIL', NOT_RUN: 'NOT-RUN' });

/**
 * Lower-case hex of bytes.
 * @param {Uint8Array} bytes
 */
export const toHex = (bytes) => Buffer.from(bytes).toString('hex');

/**
 * Compares an expected hex string (case-insensitive) with produced bytes.
 * @param {string} expectedHex
 * @param {Uint8Array} actual
 * @returns {{pass: boolean, reason: string|null}}
 */
export function compareHex(expectedHex, actual) {
  if (typeof expectedHex !== 'string' || !/^[0-9a-fA-F]*$/.test(expectedHex))
    return { pass: false, reason: 'expected value is not hex' };
  const got = toHex(actual);
  return got === expectedHex.toLowerCase()
    ? { pass: true, reason: null }
    : { pass: false, reason: `mismatch (expected ${expectedHex.length / 2} B)` };
}

/**
 * Verdict for a case whose expected outcome is acceptance or rejection.
 * @param {boolean} expectAccept
 * @param {boolean} accepted
 */
export function compareDecision(expectAccept, accepted) {
  return expectAccept === accepted
    ? { pass: true, reason: null }
    : { pass: false, reason: expectAccept ? 'rejected a valid case' : 'accepted an invalid case' };
}

/**
 * Status of one vector set from its case verdicts.
 * @param {Array<{pass: boolean}>} cases
 * @param {string|null} notRunReason non-null when the set could not be executed
 */
export function setStatus(cases, notRunReason = null) {
  if (notRunReason !== null) return STATUS.NOT_RUN;
  if (cases.length === 0) return STATUS.NOT_RUN;
  return cases.every((c) => c.pass) ? STATUS.PASS : STATUS.FAIL;
}

/**
 * Status of an algorithm from its sets: FAIL dominates, then PASS (at least one set passed),
 * otherwise NOT-RUN. A PASS with some sets NOT-RUN is reported as PASS (partial) by the caller.
 * @param {string[]} statuses
 */
export function algorithmStatus(statuses) {
  if (statuses.includes(STATUS.FAIL)) return STATUS.FAIL;
  if (statuses.includes(STATUS.PASS)) return STATUS.PASS;
  return STATUS.NOT_RUN;
}
