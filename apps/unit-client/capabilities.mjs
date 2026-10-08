// Permission-separated interface model (ADR-012).
//
// Mirrors, and never extends, the role checks the control authority enforces in
// services/control/core.mjs. It decides only what an interface offers; every operation is still
// authorised by the authority. Unknown roles or duty roles receive no capabilities (deny by
// default). Drift against the authority's role checks is tested in capabilities.test.mjs.

/**
 * @typedef {'exchange.send' | 'exchange.receive' | 'exchange.approveFlash' | 'admin.manage'
 *   | 'evidence.export'} Capability
 * @typedef {'unit-operator' | 'administrator' | 'security-evaluation'} Experience
 */

/** @type {Readonly<Record<string, readonly Capability[]>>} */
const BY_ROLE = Object.freeze({
  // Authority.grant requires 'operator'; authorityReason requires sender 'operator' and
  // recipient 'operator' or 'viewer'.
  operator: Object.freeze(/** @type {Capability[]} */ (['exchange.send', 'exchange.receive'])),
  viewer: Object.freeze(/** @type {Capability[]} */ (['exchange.receive'])),
  // Authority.change and admin routes require 'admin'; evidence export allows 'admin', 'auditor'.
  admin: Object.freeze(/** @type {Capability[]} */ (['admin.manage', 'evidence.export'])),
  auditor: Object.freeze(/** @type {Capability[]} */ (['evidence.export'])),
});

/** @type {Readonly<Record<string, Experience>>} */
const EXPERIENCE = Object.freeze({
  operator: 'unit-operator',
  viewer: 'unit-operator',
  admin: 'administrator',
  auditor: 'security-evaluation',
});

/**
 * Capabilities offered to a signed-in user. Only own string-valued roles are recognised.
 * @param {{ role?: unknown, dutyRole?: unknown } | null | undefined} user
 * @returns {ReadonlySet<Capability>}
 */
export function capabilitiesFor(user) {
  const role = user?.role;
  if (typeof role !== 'string' || !Object.hasOwn(BY_ROLE, role)) return new Set();
  const capabilities = new Set(BY_ROLE[role]);
  // Authority.authorizeRelease: operator with duty role UNIT_COMMANDER.
  if (role === 'operator' && user?.dutyRole === 'UNIT_COMMANDER')
    capabilities.add('exchange.approveFlash');
  return capabilities;
}

/**
 * The single interface a user is offered; null when the role is unknown.
 * @param {{ role?: unknown } | null | undefined} user
 * @returns {Experience | null}
 */
export function experienceFor(user) {
  const role = user?.role;
  return typeof role === 'string' && Object.hasOwn(EXPERIENCE, role) ? EXPERIENCE[role] : null;
}

/**
 * @param {{ role?: unknown, dutyRole?: unknown } | null | undefined} user
 * @param {Capability} capability
 * @returns {boolean}
 */
export const can = (user, capability) => capabilitiesFor(user).has(capability);
