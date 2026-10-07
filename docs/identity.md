# Identity, device and role implementation

[Control source](../services/control/core.mjs) separates users, units, roles, devices and sessions. Users authenticate with scrypt-verified password and mandatory RFC6238 TOTP. TOTP replay floor survives restart. Login limits are persisted (40/IP and 8/username per minute); authenticated sessions have a separate 500/minute bucket. Sessions last 15 minutes, are stored as token digests and can be explicitly revoked or logged out.

Each software device has different signing and encryption keys. Enrollment proves possession of the signing key and creates a pending device; an approved administrator must approve before session binding. Sensitive operations require a one-use signed challenge bound to session/device, exact operation and request-body hash. Revoked device keys cannot simply be reapproved. Administrator provisioning uses the explicit [bootstrap](../scripts/bootstrap.mjs) path; login never creates a fallback account.

| Role     | Capability                                                                    |
| -------- | ----------------------------------------------------------------------------- |
| operator | Create/send and receive within unit/mission policies                          |
| viewer   | Receive only within policy                                                    |
| admin    | Manage identities/policies; view security, not override content authorization |
| auditor  | Read redacted operations/evidence, not mutate policy                          |

[Authority tests](../tests/authority.test.mjs) exercise MFA replay, approval, device/session revocation, wrong role and current-state rechecks. Device possession is software authentication, not TPM posture or proof of absence of compromise. External IdP/PKI integration, production enrollment/recovery ceremony, phishing-resistant MFA and exact filed IAF duty-position roles remain work. [Offline administrator recovery](../scripts/recover-identity.mjs) rotates password and MFA, revokes every session, increments authority and records evidence; [boundary tests](../tests/additional-boundaries.test.mjs) cover it. It requires controlled local maintenance and a new private output file. No self-service password/MFA recovery route is implemented.
