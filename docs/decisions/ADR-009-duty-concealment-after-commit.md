# ADR-009: duty-role concealment happens after the signed decision commits

Status: accepted, 2026-10-08. Commit `2fc827e`.

## Context

When a sender or recipient later receives a duty role that forbids an object's priority/domain,
the object must not reveal its priority metadata to that party. PR #15 rejected such a party
inside `owned()` with an opaque 404 before any decision was recorded, and its object listing
called `JSON.parse` on every row, so one unreadable envelope returned HTTP 500 for the whole list.
PR #16 recorded a durable HOLD and signed denial first, then concealed the response.

## Decision

`Authority.dutyVisible()` (tolerant of corrupt rows via `storedEnvelope`) decides visibility.
`prepare` and `claim` commit the HOLD and signed evidence in the transaction, then return
`404 OBJECT_NOT_FOUND` after commit. `ack` and listing filter with the same predicate. Non-parties
still receive an opaque 404 without any mutation. Label-dependent policy uses
`hasMissionLabels()` (schema v2 and v3), never `schemaVersion === 2`.

## Consequences

Denials by a party are auditable; unrelated users cannot cause state changes. Tests:
`tests/protocol-reconciliation.test.mjs`, `tests/versioned-envelope.test.mjs`,
`tests/filed-mission-authority.test.mjs`.
