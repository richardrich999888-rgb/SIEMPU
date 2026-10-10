# ADR-014: Incremental checkpoint custody (fix for D-T5-01)

Status: accepted for implementation, 2026-10-10. Branch `claude/siepmu-sovereign-research-w886dv`,
based on `assurance/kat-and-gap-2026-10` (`86744a8`, which contains PR #19's head `2b3f9ab`).

## Context

D-T5-01 (`docs/trl5/PERFORMANCE_REPORT.md`, baseline `docs/assurance/d-t5-01-baseline.md`):
`Authority.dispatch` serialises every protected request and calls `recoveryGuard.authorize()` twice.
Each authorisation sent the **whole** evidence chain (`authoritySnapshot`) and the custodian
re-verified every signature from genesis (`verifyEvidence`) before anchoring the head. The baseline
measured 0.156 ms per record per authorisation (15.6 s per authorisation at 100,000 records).

Root cause: the custodian re-derived trust in the whole chain on every request, although it had already
verified and durably retained a head it trusts (the anchor). Nothing new is learned by re-verifying the
anchored prefix.

The defect has a second, worse consequence that the performance report did not state: **an availability
cliff**. The verifier rejects exports above 100,000 records and the custodian HTTP route rejects bodies
above 16 MiB (about 40,000 records at roughly 400 bytes each). Beyond that length every authorisation
fails, so the authority fails closed permanently. Correct (fail-closed), but fatal for operation.

## Decision

Add custody protocol **version 2 (range)** beside version 1 (full chain). Both share one anchor table and
one lease format.

1. **Range request** (signed by the authority):
   `{version: 2, nonce, issuedAt, stateDigest, base: {sequence, headHash}, records, checkpoint}` with at
   most `DELTA_MAX_RECORDS` = 512 records. Unknown members, versions or malformed positions fail closed.
2. **Custodian acceptance** (`CheckpointCustodian.accept`, `services/evidence/incremental.mjs`):
   - `verifyEvidenceRange` (`apps/verifier/verify.mjs`) checks that record _i_ carries sequence
     `base.sequence + i + 1`, links by `previousHash`, verifies under the authority key, and that the
     signed checkpoint names exactly the resulting head. Record rules are the **same function**
     (`verifyLink`) used by full-chain verification; the 63 frozen conformance vectors are unchanged.
   - Inside one `BEGIN IMMEDIATE` transaction, `checkAnchorTransition` compares with the retained anchor,
     in this order: no anchor → only an explicit bootstrap from genesis; head below anchor →
     `RECOVERY_ROLLBACK_OR_FORK`; base ≠ anchor → `CHECKPOINT_BASE_MISMATCH`; head = anchor with a
     different hash or authorization-state digest → `RECOVERY_ROLLBACK_OR_FORK`.
   - On success the anchor moves to the new head and a lease (unchanged format) is signed.
3. **Anchor query** (`POST /v1/anchor`): a signed, read-only `{version: 2, kind: 'ANCHOR_QUERY', nonce,
issuedAt}`; the custodian answers with its signed anchor and the nonce. Used once after the guard
   starts or after any failure, so a restarted authority resumes without shipping its history.
4. **Guard** (`createRecoveryGuard` with `anchorQuery`): learns the anchor, plans the catch-up in
   bounded ranges (`planRanges`), ships each range, verifies each lease, and tracks the anchor from
   verified leases. Any failure quarantines (503), clears the lease **and forgets the tracked anchor**, so
   the next attempt re-learns it from the custodian rather than trusting local state. The production
   control server (`services/control/server.mjs`) now passes `anchorQuery`.
5. **Kept unchanged:** version 1 acceptance and the full-chain guard mode (bootstrap seeding in
   `deployment/secure/harness.mjs`, offline audit, and the in-build baseline for benchmarks); the
   independent full-chain verifier CLI; lease format and lifetime; `allows()`; the two authorisations per
   request in `dispatch`; the release transaction; the TLA+ model's abstract anchor semantics.

## Why this is sound

Invariant _I_: the retained anchor `(s, h)` is the digest of record `s` of a chain whose records 1..s
have each been verified under the authority key, once, by this custodian (or by the v1 path).

- Bootstrap: an anchor is created only from genesis (`base.sequence = 0`) with `allowBootstrap`, or by a
  v1 full-chain verification. _I_ holds.
- Step: a range is accepted only if `base = (s, h)` and every record links to its predecessor by hash
  and verifies. The new head is therefore record `s + k` of the same chain, and records `s+1..s+k` are
  verified. _I_ holds.

SHA-256 linkage means a different record at any position ≤ s would change `h`. Hence, relative to the
retained anchor, a range is accepted only when it is a verified, append-only extension. This is the same
guarantee version 1 gave by recomputation, at cost O(k) instead of O(s + k). Each record is verified by
the custodian once over its lifetime (amortised O(1) per record).

## Threat cases and their tests

| Case                                                           | Detected by                                  | Test (`tests/…`)                                          |
| -------------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------- |
| Rollback: database restored from before a revocation           | head < anchor                                | `incremental-custody` rollback after revocation           |
| Fork: validly signed divergent history, longer than the anchor | `previousHash` ≠ anchor hash / base mismatch | `incremental-custody` fork                                |
| Gap: record missing from a range                               | sequence discontinuity                       | `incremental-custody` gap…; `-core` range rejects gap     |
| Reorder                                                        | sequence discontinuity                       | same                                                      |
| Tamper / foreign key                                           | signature / key ID                           | same                                                      |
| Truncated range, wrong checkpoint                              | checkpoint ≠ computed head                   | same                                                      |
| Replay of an earlier valid increment; stale base               | base ≠ anchor                                | `incremental-custody` replayed increment                  |
| Authorization changed without evidence                         | equal head, different state digest           | `incremental-custody` state changed without a chain event |
| Hole in the authority's own store                              | `AUTHORITY_EVIDENCE_GAP` before sending      | `incremental-custody` storage hole                        |
| Forged or replayed anchor answer                               | custodian signature, nonce, freshness        | `incremental-custody` anchor answers are authenticated    |
| Crash between catch-up batches                                 | intermediate anchor is a valid verified head | `incremental-custody` crash between batches               |
| Custodian or authority restart                                 | durable anchor + anchor query                | `incremental-custody` long catch-up… restart              |
| Oversize range, unknown version, extra members, stale request  | request validation                           | `incremental-custody` gap…; `-core` request validation    |

## Alternatives considered

- **Merkle tree with consistency proofs (RFC 6962/9162 Certificate Transparency, Trillian).** Gives
  O(log n) proofs that a new tree head extends an old one **without sending the new entries**, and
  inclusion proofs for single records. The custodian must see and verify every new record anyway (it
  attests a chain of signed decisions, not a log of opaque leaves), so the delta is already the minimal
  consistency proof and a Merkle tree adds a second structure to keep consistent. Merkle inclusion
  proofs remain a candidate for **endpoint receipt verification** (proving one release record is in the
  anchored history without exporting the chain); recorded as future work, not adopted here.
- **Custodian caches verified prefix in memory, keep v1 wire format.** Removes CPU cost but still ships
  O(n) bytes per request and keeps the 16 MiB cliff.
- **Verify only every N requests.** Weakens the guarantee between checks. Rejected: no weakening of
  custody to gain speed.
- **Forward-secure / MAC-chained audit logs (Schneier–Kelsey 1999; Crosby–Wallach, USENIX Security
  2009).** Address tampering by a later-compromised logger and efficient historical queries. Out of scope:
  the threat here is rollback/fork of the authority's database, with an independent verifier holding
  state.

## Prior art and originality statement

Verifying only the extension of a trusted, retained hash-chain head is a standard technique (hash-chained
logs with checkpoints; CT's signed tree heads; database WAL replay from a checkpoint). This ADR claims no
novelty for it. What is specific to SIEPMU is the composition: the anchor binds both the evidence head and
a digest of the current **authorization state**, the authority may serve key-release requests only under a
fresh lease for that exact pair, and the lease is re-established before and after every protected request.
Whether that composition is patentable is an open question for professional IP review; nothing here should
be published as a novelty claim without the founder's authorisation (see
`docs/research/sovereign/IP_AND_ORIGINALITY.md`).

## Consequences and limits

- Per-authorisation cost no longer depends on chain length (measured in
  `docs/assurance/d-t5-01-incremental.md`). Remaining per-request costs: the authorization-state digest
  reads all users, devices and policies (O(identities)); each authorisation is a custodian round trip; and
  dispatch remains serialised. Those are separate items, not part of D-T5-01.
- The one-time catch-up after a restart is O(records since the anchor), in bounded batches.
- If something other than the guard advances the anchor (another authority instance, a manual v1 seed),
  the guard fails closed once with `CHECKPOINT_BASE_MISMATCH`, re-learns the anchor and continues
  (tested). A second authority instance against one custodian is still not a supported topology.
- The custodian still trusts the authority's signing key. A compromised authority key can sign any
  history; custody detects rollback and fork of the authority's **database**, not key compromise
  (unchanged from v1).
- **Formal model coverage.** `formal/ReleaseAuthority.tla` abstracts the custodian as "save the head only if
  it extends the saved prefix" (`Anchor`), which the range check implements exactly under SHA-256 collision
  resistance. `npm run formal:check` was re-run on this branch with TLA+ tools 1.8.0 (pinned SHA-256): faithful
  3,837,180 distinct states, no error; `nonatomic` and `unguarded` mutants still violate their properties. The
  chunked catch-up (intermediate anchors) is **not** covered: the model appends at most one record per guarded
  transaction, so the custodian is never two records behind. An `AnchorPrefix` action was added and checked;
  TLC showed it unreachable (an invariant `step # "anchor-prefix"` held over all states), so it was removed
  rather than kept as a vacuous action. Chunked catch-up is covered by the integration tests (long catch-up,
  crash between batches). Modelling multi-record transactions is future work.
- Relevant-environment re-run on `1a0218d` (three namespaces, same declared matrix): 33/33 PASS; T8.1
  1.56 → 5.93 exchanges/s; custodian CPU 72.3 % → 17.1 % (`docs/trl5/evidence/1a0218d/`). Hosted CI on this
  branch is still required before D-T5-01 is recorded as closed in the TRL dossier.
