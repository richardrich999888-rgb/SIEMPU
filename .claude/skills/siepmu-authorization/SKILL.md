---
name: siepmu-authorization
description: The policy-epoch-bound release transaction, revocation semantics, duty roles, message priorities and FLASH dual-control approval in the SIEPMU control authority. Use before changing services/control/core.mjs admission, prepare, claim, ack, policy, users, devices, duty roles or evidence, and whenever reasoning about whether a revoked recipient can obtain keys.
---

# SIEPMU authorization and release

## Core idea

Creation authorization (was the sender allowed to create?) is separate from **release
authorization** (is the recipient still allowed **now**?). Key release is one SQLite write
transaction in `Authority.claim()` that re-evaluates current state and writes the signed
decision and the issuance together. Revocation committed first blocks issuance. An issuance
committed first may already be usable and **cannot be recalled**. Never claim otherwise.

## Read these before editing (all in `services/control/core.mjs` unless noted)

| Function                                        | Role                                                                                                                                                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tx(fn)`                                        | write transaction wrapper; everything below runs inside it                                                                                                                                       |
| `bound(s)`, `operation(s, b, op)`, `proof(...)` | session, device binding and signed per-operation proof                                                                                                                                           |
| `validateSubmission(s, b)`                      | exact schema, sender identity, grant signature/scope, destination, recipient key, sizes, digests                                                                                                 |
| `authorityReason(row)`                          | **the** current-policy check: persisted integrity, grant, expiry, user/device status and ownership, generic role, duty role, unit, mission, grant scope, recipient key, unit-to-unit policy edge |
| `approvalReason(row)`                           | FLASH dual control: approval bound to envelope digest and current epoch; approver is an active `UNIT_COMMANDER` operator in the sender's unit and mission, not the sender                        |
| `authorizeRelease(...)`                         | records FLASH approval (`release_approvals`, migration 004)                                                                                                                                      |
| `prepare`, `claim`, `ack`                       | state machine and evidence; `claim` adds `EPOCH_MISMATCH`                                                                                                                                        |
| `dutyVisible(s, row)`                           | duty-role concealment; called after commit (ADR-009)                                                                                                                                             |
| `services/admission/integrity.mjs`              | stored-envelope schema, canonical bytes, column binding, sender signature                                                                                                                        |
| `services/evidence/decision.mjs`                | one evidence schema for ALLOW/READY/HOLD/RELEASE                                                                                                                                                 |
| `packages/mission/policy.mjs`                   | duty-role matrix (`senderDutyAllowed`, `recipientDutyAllowed`, `compatibleDutyRole`)                                                                                                             |
| `services/evidence/custody.mjs`                 | recovery guard: no key-bearing response before the head is independently retained                                                                                                                |

## Forbidden regressions

- Checking policy only at creation, or caching a release decision across transactions.
- Releasing outside `tx`, or writing evidence in a different transaction from the state change.
- Throwing a concealment 404 **inside** the transaction (rolls back the signed decision).
- Policy keyed on `schemaVersion === 2`; use `hasMissionLabels()` so v3 cannot bypass FLASH or duty checks.
- Returning `wrappedKey`, priority metadata or receipts to a duty-restricted party.
- `JSON.parse` of a stored envelope before `storedObjectIntegrityReason` (use `storedEnvelope`).
- Dynamic route dispatch from request values (CodeQL hardening; keep exact static matches).
- Allowing the sender to approve their own FLASH object, or approval surviving an epoch change.
- Bypassing `recoveryGuard` for any key-bearing route.

## Duty roles and priorities

Six duty roles (`UNIT_COMMANDER`, `SIGNALS_OFFICER`, `INTELLIGENCE_ANALYST`, `FIELD_OPERATOR`,
`AUDIT_OFFICER`, `SYSTEM_ADMIN`) restrict, never grant. Four priorities FLASH > IMMEDIATE >
PRIORITY > ROUTINE; domains GENERAL, INTEL. A duty-profile user cannot use v1 to omit labels.
This matrix is a **provisional applicant policy**, not IAF-approved (`docs/application/`).

## Required tests (run all after any change here)

```sh
node --test --test-concurrency=1 tests/authority.test.mjs tests/admission-integrity.test.mjs \
  tests/versioned-envelope.test.mjs tests/protocol-reconciliation.test.mjs tests/flash-approval.test.mjs \
  tests/filed-mission-authority.test.mjs tests/filed-mission-policy.test.mjs tests/checkpoint-custody.test.mjs \
  tests/routing-boundary.test.mjs tests/auth-routing.test.mjs tests/verifier-replay.test.mjs
npm run test:e2e        # vertical slice, authorized backlog, revocation
```

Race and crash behaviour: `tests/helpers/crash-worker.mjs`, `policy-worker.mjs` (used by
`tests/authority.test.mjs`). Network revocation during disconnection:
`tests/network-failure/recovery.test.mjs`.

## Definition of done

Every new denial path has a negative test asserting state, reason, signed evidence (verify the
signature) and zero issuances; `npm run validate` passes; OpenAPI and
`docs/protocols/IMPLEMENTATION_CONTRACT.md` updated for route or semantic changes.

## Known limitations

Single-host SQLite serialises the authority; no distributed consensus. Compromise of the
authority can cause premature release (it holds wrapped keys and decides). Software
proof-of-possession is not hardware attestation.
