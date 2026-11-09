# ADR 018 Fence authority writers at independent checkpoint commit

Status: laboratory candidate for review, 9 November 2026. G06 remains PARTIAL_LAB.

An expiring lease alone does not fence a paused writer. The publicly documented
[etcd guarantees](https://etcd.io/docs/v3.6/learning/api_guarantees/) and
[coordination guidance](https://etcd.io/docs/v3.6/learning/why/) distinguish coordination from
enforcement at the protected resource. No etcd or new runtime dependency is added here.

Each authority writer receives a distinct P-256 key and an explicit, non-expiring generation.
Custody protocol v3 wraps the existing v1/v2 evidence request in a writer signature and returns
a custodian-signed, generation-bound lease. The custodian verifies the configured writer and
checks ownership again inside the same `BEGIN IMMEDIATE` transaction as checkpoint advancement.
It also retains policy-epoch and revocation-version floors. Lower values are rejected even when
the submitted history is correctly signed. Once a fence exists, legacy requests are rejected.
Qualification deployments additionally require `SIEPMU_CUSTODY_REQUIRE_FENCING=1` so missing
metadata cannot enable legacy mode. The qualification harness configures both sides explicitly.

Handover is a local maintenance operation with expected generation, exact retained anchor,
unchanged floors and a fresh public writer key. A compare-and-swap decides one winner across
independent SQLite connections/processes; generation and signed handover receipt commit together.
There is no HTTP handover route, automatic takeover, TTL ownership or fallback to an old key.
Authority/custodian keys cannot be reused as writer keys. See the
[recovery runbook](../qualification/P0-041_RECOVERY_RUNBOOK.md).

The final custody check precedes return of a key-bearing response. If partition or handover wins
that boundary, the client receives a quarantine error. A locally committed but unacknowledged
issuance may remain and must be reconciled; it is not delivered evidence. A response already
accepted before handover can be in flight, and a previously received key cannot be recalled.
These are ordering boundaries, not a promise of retroactive revocation or exactly-once delivery.

The custodian remains a trusted, single availability dependency. This is manual fenced recovery,
not full HA, consensus replication or full disaster recovery. Cloning the currently valid writer
credential is not distinguishable from that writer. Custodian database/signing-key rollback or
compromise needs independently retained receipts, operational controls and further design. Hardware
custody, key destruction, independent administration and witnessed RPO/RTO remain external work.

Run `node --test --test-concurrency=1 tests/writer-fencing.test.mjs
tests/transport/secure-stack.test.mjs`. Tests include two real child processes, barriers during
verification, state-floor rollback, partition before/after issuance, interrupted maintenance
writes, restart, missing metadata and incompatible signed leases. Simulated SQLite errors are
not physical power-loss qualification.
