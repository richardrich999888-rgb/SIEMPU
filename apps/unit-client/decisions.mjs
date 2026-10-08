// Operator-facing explanations of authority decisions (ADR-013).
//
// Pure and content-free by construction: every function takes only a decision code or object
// state, never message content, identities or key material, so an explanation cannot disclose
// what was sent or to whom. The authority remains the only enforcement point; this module only
// explains its decisions. Coverage of every code the authority can emit is enforced by
// apps/unit-client/decisions.test.mjs, which scans the authority sources.

/** @typedef {'retry' | 'resend' | 'administrator' | 'security' | 'wait'} DecisionAction */
/**
 * @typedef {object} DecisionExplanation
 * @property {string} code        Authority code, shown verbatim for support and audit.
 * @property {string} title       Short operator-facing summary.
 * @property {string} explanation What the authority decided and why, in operator terms.
 * @property {DecisionAction} action Who or what can change the outcome.
 * @property {string} guidance    The concrete next step for the operator.
 * @property {'info' | 'warning' | 'blocked'} severity
 */

/** @type {Readonly<Record<DecisionAction, string>>} */
const GUIDANCE = Object.freeze({
  retry: 'Refresh and try again; nothing else needs to change.',
  resend: 'Create and send a new object; this one cannot be released.',
  administrator: 'Contact your administrator. The object stays held until authority changes.',
  security: 'Report this to your security officer. Do not retry or resend.',
  wait: 'Wait for the system to recover. No key is released in this state.',
});

/** @type {Readonly<Record<string, readonly [string, string, DecisionAction]>>} */
const DECISIONS = Object.freeze({
  // Current-authority re-check at release (Authority.authorityReason).
  USER_REVOKED: [
    'Account deactivated',
    'The sender or recipient account is no longer active.',
    'administrator',
  ],
  DEVICE_REVOKED: [
    'Device not approved',
    'The sending or receiving device is revoked or not yet approved.',
    'administrator',
  ],
  DEVICE_OWNER_MISMATCH: [
    'Device ownership changed',
    'A device involved in this exchange no longer belongs to the same user.',
    'administrator',
  ],
  ROLE_DENIED: [
    'Role not permitted',
    'The sender or recipient role does not permit this exchange.',
    'administrator',
  ],
  ROLE_PRIORITY_DENIED: [
    'Duty role not permitted',
    'A duty role does not permit this message priority or domain.',
    'administrator',
  ],
  DUTY_PROFILE_REQUIRES_V2: [
    'Priority labels required',
    'Duty-role users exchange only objects carrying priority and domain labels.',
    'resend',
  ],
  UNIT_CHANGED: [
    'Unit assignment changed',
    'The sender or recipient unit changed after the object was created.',
    'resend',
  ],
  MISSION_DENIED: [
    'Mission assignment removed',
    'The sender or recipient is no longer assigned to this mission.',
    'administrator',
  ],
  GRANT_SCOPE: [
    'Creation grant out of scope',
    'The creation grant does not cover this sender, device, unit or mission.',
    'resend',
  ],
  STALE_GRANT: [
    'Creation grant expired',
    'The creation grant is expired or invalid; it never authorises a later release.',
    'resend',
  ],
  EXPIRED_OBJECT: ['Object expired', 'The object passed its expiry time.', 'resend'],
  RECIPIENT_KEY_CHANGED: [
    'Recipient key changed',
    'The recipient rotated or replaced the key this object was sealed to.',
    'resend',
  ],
  POLICY_DENIED: [
    'No current exchange policy',
    'Current unit and mission policy does not allow this exchange.',
    'administrator',
  ],
  EPOCH_MISMATCH: [
    'Authority changed meanwhile',
    'Authority changed after your view was loaded; the release was re-evaluated.',
    'retry',
  ],
  // FLASH dual control (Authority.approvalReason).
  FLASH_APPROVAL_REQUIRED: [
    'Commander approval required',
    'FLASH objects need a unit commander approval for the current authority state.',
    'administrator',
  ],
  FLASH_APPROVAL_INVALID: [
    'Commander approval no longer valid',
    'The recorded FLASH approval no longer satisfies current authority.',
    'administrator',
  ],
  // Current cryptographic policy (services/crypto-policy/registry.mjs).
  CRYPTO_SUITE_FORBIDDEN: [
    'Cryptographic suite not allowed',
    'Current cryptographic policy does not allow this suite.',
    'resend',
  ],
  CRYPTO_POLICY_REVISION: [
    'Cryptographic policy changed',
    'The object was created under a cryptographic policy revision that is no longer accepted.',
    'resend',
  ],
  CRYPTO_KEY_UNREGISTERED: [
    'Key not registered',
    'An endpoint key used by this object is not registered.',
    'administrator',
  ],
  CRYPTO_KEY_INACTIVE: [
    'Key not active',
    'An endpoint key used by this object is not active.',
    'administrator',
  ],
  CRYPTO_KEY_REVOKED: ['Key revoked', 'An endpoint key used by this object was revoked.', 'resend'],
  CRYPTO_KEY_BINDING: [
    'Key binding mismatch',
    'An endpoint key is not bound to the device that used it.',
    'security',
  ],
  CRYPTO_CONTEXT_INVALID: [
    'Cryptographic context invalid',
    'The object cryptographic metadata does not match policy.',
    'security',
  ],
  PQC_LAB_DISABLED: [
    'Laboratory cryptography disabled',
    'Laboratory post-quantum suites are disabled on this deployment.',
    'administrator',
  ],
  PROVIDER_SIGNATURE_INVALID: [
    'Provider signature invalid',
    'The cryptographic provider signature on this object failed verification.',
    'security',
  ],
  // Stored-object integrity (services/admission/integrity.mjs).
  OBJECT_SIGNATURE_INVALID: [
    'Object signature invalid',
    'The stored object failed sender signature verification.',
    'security',
  ],
  OBJECT_BINDING_MISMATCH: [
    'Object binding mismatch',
    'The stored object does not match its recorded binding.',
    'security',
  ],
  OBJECT_ENVELOPE_INVALID: [
    'Object envelope invalid',
    'The stored object envelope is malformed.',
    'security',
  ],
  OBJECT_ENVELOPE_NONCANONICAL: [
    'Object envelope altered',
    'The stored object envelope is not in its signed canonical form.',
    'security',
  ],
  OBJECT_ENVELOPE_SCHEMA: [
    'Object schema not accepted',
    'The stored object uses a schema the authority does not accept.',
    'security',
  ],
  // Service state seen by clients.
  RECOVERY_QUARANTINED: [
    'Authority in recovery quarantine',
    'The authority could not prove its state is current with independent custody, so it releases nothing.',
    'wait',
  ],
});

const UNKNOWN_DECISION = Object.freeze({
  title: 'Held by the authority',
  explanation: 'The authority did not release this object. The code below identifies the reason.',
});

/** Authority codes this module explains (for coverage checks and documentation). */
export const EXPLAINED_CODES = Object.freeze(Object.keys(DECISIONS));

/** @param {DecisionAction} action @returns {DecisionExplanation['severity']} */
const severityOf = (action) =>
  action === 'retry' ? 'info' : action === 'security' ? 'blocked' : 'warning';

/**
 * Explains an authority decision code. Unknown or malformed codes fail safe: they are reported
 * as held, the code is preserved for support, and nothing suggests the object was released.
 * @param {unknown} code
 * @returns {DecisionExplanation}
 */
export function explainDecision(code) {
  const known = typeof code === 'string' && Object.hasOwn(DECISIONS, code);
  if (!known) {
    const shown =
      typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : 'UNKNOWN';
    return {
      code: shown,
      ...UNKNOWN_DECISION,
      action: 'administrator',
      guidance: GUIDANCE.administrator,
      severity: 'blocked',
    };
  }
  const [title, explanation, action] = DECISIONS[code];
  return {
    code,
    title,
    explanation,
    action,
    guidance: GUIDANCE[action],
    severity: severityOf(action),
  };
}

/** @type {Readonly<Record<string, string>>} */
const STATES = Object.freeze({
  PENDING: 'Ciphertext stored; awaiting a current-authority check.',
  READY: 'Current authority allows release to the intended recipient.',
  HELD: 'Not released: current authority does not allow it.',
  RELEASED: 'Key released to the recipient after a current-authority check.',
  DELIVERED: 'Recipient acknowledged receipt.',
});

/**
 * One-line, content-free description of an object state.
 * @param {unknown} state
 * @returns {string}
 */
export function describeState(state) {
  return typeof state === 'string' && Object.hasOwn(STATES, state)
    ? STATES[state]
    : 'State not recognised by this client; treat the object as not released.';
}

/**
 * Text for compact displays: "Title (CODE). Guidance".
 * @param {unknown} code
 * @returns {string}
 */
export function decisionSummary(code) {
  const d = explainDecision(code);
  return `${d.title} (${d.code}). ${d.guidance}`;
}
