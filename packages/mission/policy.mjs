// DISC-14 PS-69 filed role/priority vocabulary. Synthetic laboratory policy only.
// A duty role is an additional restriction, not a source of new generic privileges.
export const MESSAGE_PRIORITIES = Object.freeze(['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE']);
export const MESSAGE_DOMAINS = Object.freeze(['GENERAL', 'INTEL']);
export const DUTY_ROLES = Object.freeze([
  'UNIT_COMMANDER',
  'SIGNALS_OFFICER',
  'INTELLIGENCE_ANALYST',
  'FIELD_OPERATOR',
  'AUDIT_OFFICER',
  'SYSTEM_ADMIN',
]);

/** @type {Readonly<Record<string, readonly string[]>>} */
const priorityMatrix = Object.freeze({
  UNIT_COMMANDER: ['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE'],
  SIGNALS_OFFICER: ['FLASH', 'IMMEDIATE', 'PRIORITY', 'ROUTINE'],
  INTELLIGENCE_ANALYST: ['IMMEDIATE', 'PRIORITY', 'ROUTINE'],
  FIELD_OPERATOR: ['PRIORITY', 'ROUTINE'],
  AUDIT_OFFICER: [],
  SYSTEM_ADMIN: [],
});

/** @param {unknown} priority @param {unknown} domain */
export function validMissionProfile(priority, domain) {
  return (
    typeof priority === 'string' &&
    typeof domain === 'string' &&
    MESSAGE_PRIORITIES.includes(priority) &&
    MESSAGE_DOMAINS.includes(domain)
  );
}

/** @param {string} genericRole @param {string | null | undefined} dutyRole */
export function compatibleDutyRole(genericRole, dutyRole) {
  if (dutyRole === null || dutyRole === undefined) return true;
  if (!DUTY_ROLES.includes(dutyRole)) return false;
  if (dutyRole === 'SYSTEM_ADMIN') return genericRole === 'admin';
  if (dutyRole === 'AUDIT_OFFICER') return genericRole === 'auditor';
  return genericRole === 'operator' || genericRole === 'viewer';
}

// Both sender and recipient are checked again at transactional key issuance.
// The generic role gate remains mandatory; this function never grants access.
/** @param {string} dutyRole @param {string} priority @param {string} domain */
export function dutyMessageAllowed(dutyRole, priority, domain) {
  if (!DUTY_ROLES.includes(dutyRole) || !validMissionProfile(priority, domain)) return false;
  if (!priorityMatrix[dutyRole].includes(priority)) return false;
  if (dutyRole === 'INTELLIGENCE_ANALYST') return domain === 'INTEL';
  if (dutyRole === 'FIELD_OPERATOR') return domain === 'GENERAL';
  return true;
}

/** @param {string} genericRole @param {string} dutyRole @param {string} priority @param {string} domain */
export function senderDutyAllowed(genericRole, dutyRole, priority, domain) {
  return (
    genericRole === 'operator' &&
    compatibleDutyRole(genericRole, dutyRole) &&
    dutyMessageAllowed(dutyRole, priority, domain)
  );
}

/** @param {string} genericRole @param {string} dutyRole @param {string} priority @param {string} domain */
export function recipientDutyAllowed(genericRole, dutyRole, priority, domain) {
  return (
    (genericRole === 'operator' || genericRole === 'viewer') &&
    compatibleDutyRole(genericRole, dutyRole) &&
    dutyMessageAllowed(dutyRole, priority, domain)
  );
}
