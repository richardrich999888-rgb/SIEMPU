# ADR-015: PS-69 mission readiness and exchange dependency health

Status: implemented for laboratory evaluation, 7 November 2026.
Base: `09b18103268603b35a9801b2679fa589bf54160c`.

## Context

AIRON–SIEPMU targets IAF DISC-14 PS-69: authorized personnel exchange sensitive
information over the public Internet. Hosting is a delivery model; it does not make
this an open consumer service. The existing gateway readiness route checked only
the authority database. A failed ciphertext relay could therefore leave the gateway
reporting ready even though exchange was unavailable.

## Decision

- `/health` and `/health/live` on the gateway remain liveness signals.
- Gateway `/health/ready` calls control `/ready`, which checks its database and the
  configured relay. A missing probe, malformed response, wrong service identity,
  timeout, redirect or non-200 response cannot yield readiness. The relay probe
  uses the existing configured transport (including mTLS in secure profiles), a
  one-second deadline and a 1 KiB response bound. No request selects its destination.
- Readiness is availability of those dependencies only. It neither renews custody
  leases nor bypasses per-operation release authorization; monitoring, storage
  capacity, external ingress, custodian availability and qualification are outside
  this probe. Keep the public response content-free.
- Add `GET /api/admin/readiness` behind the existing session, approved-device and
  admin/auditor checks. It reports configuration observations, public crypto policy
  and inventory, current custody state, build declarations and external evidence
  gates. It does not expose endpoint content, private keys, credentials or TLS paths.
- The admin console displays this report and can export its unsigned snapshot.
  The snapshot is an operator aid, not signed decision evidence. Local observations
  cannot change `NOT_QUALIFIED` or raise the historical provisional TRL 4 baseline.
- Bump the immutable service-worker shell generation to v8 for the changed UI.

## Consequences and verification

Load balancers using gateway readiness now remove an instance during relay failure.
Existing local fixture relays explicitly implement health; unspecified probes fail
closed. Authentication, release transactions, cryptographic primitives, duty roles
and offline delivery rules are unchanged.

`tests/mission-readiness.test.mjs` covers HTTP authorization, unbound and revoked
devices, auditor read-only behavior, no qualification from green observations, real
relay outage/restart, malformed upstream responses and bounded relay probes.
The browser runner covers the mission view, downloaded snapshot and health action.
Operational qualification still requires the evidence in `docs/trl/PS69_QUALIFICATION_PLAN.md`.
