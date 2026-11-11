# P0-046 branch reconciliation

Pinned common ancestor: `92353e1224e3eedb35db9d7420b6820a2574632a` (PR #42). PR #43 and PR #45 descend from that ancestor;
PR #44 branches directly from it. The integration base is PR #45 because its lineage preserves
fresh checkpoint-head optimization and the bounded control/relay verifier. PR #44 is imported
selectively with provenance, not merged into main or another agent's branch.

## Pinned ancestry

| PR  | Head                                     | Parent PR |
| --- | ---------------------------------------- | --------- |
| 39  | 09e33daf96b4732fd92babac6cce3d842b7c7118 | 38        |
| 40  | 62b8e6634cc6ba2a634b3170654fc21a34c8c0b4 | 39        |
| 41  | 64cce099f1729b899c6da702c85d438c22162a06 | 40        |
| 42  | 92353e1224e3eedb35db9d7420b6820a2574632a | 41        |
| 43  | 07ab59762f5a086152835709ea5df60d07890e74 | 42        |
| 44  | 9dab1a71121df09e51cc139727577600638a6bb6 | 42        |
| 45  | 6ac57e5e6e561c73525de08b09950263d2fe7dee | 43        |

All were observed open and draft on 11 November 2026. Full commit parents and PR metadata
are retained in the accompanying evidence. No old test count is transferred to this candidate.

## File decisions

| Path                                                   | Origin              | Resolution                                                                             |
| ------------------------------------------------------ | ------------------- | -------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`                             | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `assurance/bench/checkpoint-cost.mjs`                  | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `assurance/bench/recovery-growth.mjs`                  | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `assurance/iaf/plan.json`                              | Both branches       | Union of ADV-04 tests; no threshold or gap closure.                                    |
| `assurance/qualification/run.mjs`                      | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `assurance/sag/catalogue.json`                         | Both branches       | Union of CR-19 mechanisms/source/tests; hashes regenerated from reviewed merged bytes. |
| `docs/decisions/ADR-019-guarded-synthetic-recovery.md` | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `docs/disaster-recovery.md`                            | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `docs/engineering/CURRENT_STATE.md`                    | Both branches       | Preserve both histories and prepend the unified handover.                              |
| `docs/qualification/GUARDED_DISASTER_RECOVERY.md`      | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `docs/qualification/P0-041_GAPS.md`                    | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `docs/qualification/P0-043_CHECKPOINT_COST.md`         | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `docs/qualification/P0-044_RECOVERY_STORES.md`         | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `package.json`                                         | Both branches       | Union of security/engineering test entries and recovery commands; added unified tests. |
| `packages/release/offline.mjs`                         | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `scripts/backup.mjs`                                   | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `scripts/build.mjs`                                    | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `scripts/guarded-recovery.mjs`                         | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `scripts/recovery-rehearsal.mjs`                       | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `services/control/core.mjs`                            | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `services/evidence/authorization-state.mjs`            | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `services/evidence/custody.mjs`                        | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/evidence-head.test.mjs`                         | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/guarded-recovery.test.mjs`                      | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/helpers/recovery-rehearsal.mjs`                 | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/helpers/recovery-worker.mjs`                    | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/legacy-migration.test.mjs`                      | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/offline-release.test.mjs`                       | PR #44 only         | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/recovery-stores.test.mjs`                       | PR #45 lineage only | Preserved from its originating branch; changed behavior reviewed.                      |
| `tests/sag-evaluation.test.mjs`                        | Both branches       | Exact union of expected inventory members; strict equality retained.                   |

## Shared security boundaries

Both branches require independently retained history evidence and reject missing authorization
seals. Neither recreates a missing custodian. PR #44 adds monitoring custody, exact schemas,
review approval, single-writer handover and fresh live leases. PR #45 adds bounded decoding,
content hashes and signed-envelope/reference checks before publication. The two known error
messages from the earlier verifier are translated at the guarded caller only; all other errors
propagate unchanged. Both original regression files are retained byte-for-byte.

The new verification API reports QUARANTINED or VERIFIED with activationAuthorised=false.
ACTIVATION-AUTHORISED is an external procedure state, never an automatic transition. The
source-only synthetic rehearsal is not an operational activation command.

No SQL migration, crypto algorithm, dependency, release threshold or authority transaction is
changed. Source-only scripts remain excluded from application and offline release bundles.

## Failures retained

The initial import conflicted in five shared files; the conflict log and original patch are retained.
The combined original recovery suites passed 79 tests before additional work (working tree,
not final-source evidence). The first nine-test extension passed six and failed three because
ApiClient.ok throws a plain Error without an HTTP status property. The corrected harness sends
the claim request directly and asserts the exact refusal status plus unchanged issuance counts.
This was a harness assertion error, not a demonstrated unauthorized release.
