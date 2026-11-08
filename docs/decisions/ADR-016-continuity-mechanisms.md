# ADR-016: endpoint and monitoring continuity

Date: 8 November 2026. Base: `fee0ffd52e15fa9a175944a3c599d05e8ec7e8a0` (PR #37).
Status: implementation candidate; exact validation results belong to the candidate PR.

## Live-session renewal

`POST /api/auth/renew` requires an unexpired, unrevoked, approved-device-bound session,
an unused TOTP and an operation proof for `renew-session` bound to `{otp}`. The authority
re-reads the session/user/device under its write transaction, advances the MFA replay floor,
revokes the old session, inserts its replacement bound to the same device, and signs
SESSION_RENEWED evidence in that transaction. It does not grant a role or release content.
The proof is consumed before that transaction; a denied renewal cannot reuse it.

The SDK can opt into renewal before a protected operation when less than two minutes remain.
The managed companion enables it by default. The legacy adapter opts in and checks once per
minute. Concurrent renewals within one SDK instance share a promise. A rejected or ambiguous
renewal clears the local session; it never triggers password login automatically. Expired
sessions require explicit authentication. A lost renewal response can leave a valid server
session until expiry/revocation, while the client holds no replacement token. Renewal uses
the existing laboratory TOTP model, not a production service identity or human-presence claim.
The v2 ciphertext connector continues to have no personnel credentials or session.

## Managed companion outbox

Optional `outbox: {database, key, maxEntries?, maxBytes?}` is supplied separately from public
configuration. The database needs an existing private directory and a separately retained
32-byte Buffer key. Each row is encrypted/authenticated with AES-256-GCM using random 96-bit
nonces; additional data binds its ID and an HMAC-SHA256 configuration/key identity. This is
endpoint software storage, not token custody. The public configuration binds origin,
authority pin, user/device and device-key pins. No token PIN, personnel password or plaintext
file is written to the outbox. Plaintext still exists transiently in endpoint process memory.

`refreshCreationGrant()` caches the authority-signed grant. `queue(recipient,payload,options)`
scans and seals using that cached grant without network I/O. `listQueue()` returns bounded
metadata. `flushQueue(limit=32)` submits original sealed bytes through ordinary device proof,
admission and release policy. Lost submission responses leave work pending for an idempotent
retry. Expired objects become HELD; there is no automatic resealing, lifetime extension or
policy bypass. `removeQueued(id)` explicitly removes local work; it does not recall submitted
content or guarantee physical erasure. Submitted records stay until explicitly removed.

SQLite transactions enforce entry/serialized-byte ceilings across instances; FULL/WAL
durability preserves queued bytes across restart. The storage key is not copied into public
configuration or the package. Swapped/tampered rows and changed key/configuration fail closed.
AEAD does not prove completeness, prevent whole-database rollback/deletion, or secure a
compromised endpoint. SQL/WAL overhead requires host quotas. Cached grants and object expiry
retain their existing time limits. Browser vaults and document outboxes are separate stores.

## Checkpoint-aware restore CLI

The restore CLI requires both an independently retained authority public key and signed
checkpoint. It rejects malformed, newer or same-sequence/conflicting anchors before writing
restored files. Null is not an anchor. The module API retains its explicitly optional anchor
for existing laboratory callers. This is a minimum checkpoint comparison, not a proof of
every post-anchor record or a substitute for current custody/policy checks on restart.
Coordinated all-service backup, geographic recovery and endpoint backup custody remain open.

## Durable monitoring delivery

The configured control server now uses a private `telemetry-export.sqlite` cursor store.
The authority signs the configuration binding, evidence/alert cursors, source anchors and
one pending redacted batch. Cursor state binds source and collector keys and destination URL.
Evidence is read by ascending sequence and alerts by append-only SQLite rowid, in bounded
batches. Gaps, changed anchors or rollback stop progress. Evidence signatures/hash links are
checked before export. Alerts retain their original event-time epoch. The source log is
the durable backlog; no full source log or protected content is duplicated in the cursor.

A pending signed batch is persisted before transmission and replayed byte-for-byte after
restart or a lost acknowledgement. Progress commits only after an authenticated collector
receipt matches the exact batch digest. Concurrent local calls coalesce; competing processes
cannot overwrite changed cursor state. The collector deduplicates records. A five-second
drain loop works without user traffic; each call sends at most one bounded batch. Existing
per-request delivery remains. States distinguish BATCH_DELIVERED, CAUGHT_UP and DEGRADED.
CAUGHT_UP refers only to the retained source rows observed at that read.

Collector capacity/time-window rejection keeps the pending batch and reports degradation;
records are never silently skipped to advance a cursor. Source retention, key/configuration
migration, complete archive export and external SOC mapping require separate work. Deleting
the local cursor replays retained history; whole-source rollback is addressed by the separate
custody boundary, not this cursor. This is not a claim of lossless delivery under arbitrary
source deletion, retention expiry, disk exhaustion or authority compromise.

## Validation and assessment

Tests cover revoked/expired sessions, reused MFA and proof substitution, HTTP contract shape,
outbox restart/tampering/capacity, lost monitoring ACKs, backlog beyond the old recent-event
window, cursor binding/rollback and stale restore anchors. Native acceptance exercises the
extracted companion with SoftHSM, isolated ClamAV, TLS, queue restart and revocation.
Freeze one candidate before full validation and retain actual hosted outcomes.
Provisional TRL4 and open qualification gaps remain unchanged. SAG grading is not established.
