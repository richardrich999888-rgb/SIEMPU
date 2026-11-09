# ADR 017 Bind committed authorization state to signed history

Status: candidate for review, 9 November 2026. Replaces the incomplete digest coverage in
PR 40 for the qualification profile. This is a security correction, not a qualification decision.

## Reproduced failure

At baseline `62b8e6634cc6ba2a634b3170654fc21a34c8c0b4`, custody omitted crypto policy,
crypto keys, FLASH approvals, sessions, challenges, credentials and MFA replay state. Restoring
an older permitted crypto-policy row after an administrator disabled all suites left the digest
unchanged and a normal recipient obtained a newly issued wrapped key. No signing-key compromise
was needed. The first expanded-digest correction was insufficient: a legitimate unanchored
AUTH_FAILURE event after a postcommit custody outage allowed a selectively restored policy to
advance the retained head. Both failures are retained in the delivery evidence.

## Decision

`services/evidence/authorization-state.mjs` defines `SIEPMU_AUTHORIZATION_STATE_V2`. It hashes
the authority epoch/revocation version, relevant user/device fields, policies, sessions,
challenges, crypto policy/keys, FLASH approvals and the PQC runtime gate. Credentials are inputs
to a digest, never exported as evidence. Every application transaction writes an authority-signed
`AUTHORIZATION_COMMIT` seal over the resulting state digest and evidence head in the same SQLite
transaction. A failed seal write rolls back both state and evidence. Guarded transactions verify
the preceding seal before mutation, and recovery verifies it before presenting state to custody.
Challenge creation and proof consumption now have evidence events. Claim acquires a fresh lease
after consuming the proof, before its synchronous release decision.

An authentic history suffix cannot authenticate unrelated restored rows. Missing or altered seals
fail closed. Independent custody still supplies rollback/fork resistance: a valid old local seal
alone does not prove freshness. Neither mechanism protects against compromise of the authority's
running code and signing key or compromise of independent custody.

## Compatibility and limitations

Migration 007 creates an empty seal table; it does not sign existing history. Old databases and
archives have no accepted seal, and their older custody digests are incompatible. There is no
automatic migration, reseed or fallback. Keep them offline and retain their independent anchors
until a migration protocol has been separately designed, reviewed and witnessed. Fresh synthetic
fixtures create their first seal during bootstrap. The encrypted maintenance restore verifies
the seal read-only before publication and currently supports the default classical runtime gate.
Do not run an unguarded service to manufacture a seal, reset custody, or rebootstrap a restored
database. Trusted runtime configuration and key custody are part of the security boundary.

Full-table hashing adds work proportional to authorization-state size. Retention/compaction and
large-fleet capacity are unresolved; the unchanged offered-load gate measures current behavior.
This is not a claim that all database fields or arbitrary hostile process memory are protected.

## Verification

Run `node --test --test-concurrency=1 tests/authority-state-custody.test.mjs
tests/incremental-custody.test.mjs tests/recovery.test.mjs`. Retain actual TAP and source identity.
The unchanged-head regression now reports the earlier, more specific
`AUTHORIZATION_COMMIT_MISMATCH`; its denial requirement is unchanged.
