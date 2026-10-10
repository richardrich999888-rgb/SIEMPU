# Sovereign SIEPMU core — research and engineering record

Branch `claude/siepmu-sovereign-research-w886dv`, based on `assurance/kat-and-gap-2026-10` (`86744a8`, which
contains PR #19 → #18 → #17 → `main`). Synthetic data only.
The work is not IAF-approved, not SAG-graded, not independently assessed and not certified; no TRL
level is raised.

| #   | Deliverable                             | Document                                                                                                                                             | Status                         |
| --- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| 1   | Architecture and dependency audit       | [01-REPOSITORY_AUDIT.md](01-REPOSITORY_AUDIT.md)                                                                                                     | Done                           |
| 2   | Sovereign technology ownership matrix   | [02-SOVEREIGNTY_MATRIX.md](02-SOVEREIGNTY_MATRIX.md), [CSV](sovereignty-matrix.csv)                                                                  | Done; test-guarded             |
| 3   | Public prior art and comparison         | [03-PRIOR_ART_AND_COMPARISON.md](03-PRIOR_ART_AND_COMPARISON.md)                                                                                     | Done                           |
| 4   | D-T5-01 root cause and redesign         | [04-D-T5-01_ROOT_CAUSE_AND_REDESIGN.md](04-D-T5-01_ROOT_CAUSE_AND_REDESIGN.md), [ADR-014](../../decisions/ADR-014-incremental-checkpoint-custody.md) | Done                           |
| 5   | Incremental custody implementation      | `services/evidence/{incremental,custody,server}.mjs`, `apps/verifier/verify.mjs`                                                                     | Implemented, tested            |
| 6   | Rust reference component                | `native/evidence-verify/src/range.rs`, [range spec](../../../spec/SIEPMU-EVIDENCE-RANGE-v1.md)                                                       | Implemented, vector-conformant |
| 7   | Security regression results             | [10-EVIDENCE.md](10-EVIDENCE.md)                                                                                                                     | Recorded                       |
| 8   | Performance comparison                  | [d-t5-01-incremental.md](../../assurance/d-t5-01-incremental.md), `docs/trl5/evidence/1a0218d/`                                                      | Recorded                       |
| 9   | Storage architecture specification      | [05-STORAGE_ARCHITECTURE.md](05-STORAGE_ARCHITECTURE.md)                                                                                             | Specification only             |
| 10  | Secure exchange protocol specification  | [06-SECURE_EXCHANGE_PROTOCOL.md](06-SECURE_EXCHANGE_PROTOCOL.md)                                                                                     | Consolidation + gaps           |
| 11  | Air-gap deployment architecture         | [07-AIR_GAP_ARCHITECTURE.md](07-AIR_GAP_ARCHITECTURE.md)                                                                                             | Architecture + gaps            |
| 12  | Indian crypto-provider integration plan | [08-INDIAN_CRYPTO_PROVIDER_PLAN.md](08-INDIAN_CRYPTO_PROVIDER_PLAN.md)                                                                               | Plan; no provider integrated   |
| 13  | TRL readiness update                    | [09-TRL_READINESS_UPDATE.md](09-TRL_READINESS_UPDATE.md)                                                                                             | TRL 4 retained                 |
| 14  | Source-linked engineering evidence      | [10-EVIDENCE.md](10-EVIDENCE.md)                                                                                                                     | Recorded                       |
| —   | IP, provenance and licences             | [IP_AND_ORIGINALITY.md](IP_AND_ORIGINALITY.md)                                                                                                       | Public-safe fields only        |

Also fixed: CodeQL `js/file-system-race` that failed Security run 38046629878 on `86744a8`: fixed here in `50303b5`, then superseded by the base branch's broader fix `f62fd04` on merge; the regression tests from `50303b5` are kept.

Not attempted (would not be credible in the time available, or needs external inputs): a new database engine,
a new transport protocol implementation, PKCS#11/TPM providers (no hardware or vendor interface), Secure BOSS
Linux runs, self-hosted CI.
