# Database and migrations

[Migration 001](../database/migrations/001-initial.sql) creates authority epoch/revocation state, units, users, devices, sessions, challenges, policies, objects, evidence, issuances, alerts and rate limits. [Migration 002](../database/migrations/002-observability.sql) adds counters and the evidence index. Foreign keys, unique keys, role/state constraints and participant/time indexes enforce relevant structural invariants.

[Authority.migrate](../services/control/core.mjs) applies ordered SQL files at startup, records SHA-256 checksums and rejects edits to already-applied migrations. `BEGIN IMMEDIATE`, WAL, synchronous FULL and foreign keys are enabled. Policy mutation and final release issuance share this database; issuance, object state and evidence commit together. One issuance per object is a primary-key invariant.

Relay storage is separate and contains ciphertext plus workload replay records. Private identity keys stay in protected files; password hashes and encrypted TOTP seeds live in the authority database. Routing, identity and audit metadata are visible to a database administrator.

[Recovery tests](../tests/recovery.test.mjs) cover v1→v2 migration, changed-migration rejection and encrypted backup/restore. No destructive downgrade migration is supplied. For rollback, stop writers and restore a coherent reviewed backup; revalidate authority before reopening release. [Recovery procedure](disaster-recovery.md) describes the scope. Retention/compaction of historic objects, alerts and evidence needs an approved operational policy; this prototype does not claim unlimited storage.
