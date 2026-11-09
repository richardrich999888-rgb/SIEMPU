# P0 041 Baseline reconciliation

PR 40 was inspected at `62b8e6634cc6ba2a634b3170654fc21a34c8c0b4`, tree
`ca33ba91a8de96759eaa206426a17bd3c4f614fd`. Its head was unchanged on 9 November 2026.
Results below distinguish fresh applicant reproduction from historical hosted evidence.
This is not an independent assessor's TRL or accreditation decision.

| Evidence                      | Observation                                                                            | Classification                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Native validation             | Ten gates passed; 473 tests, no failures/skips/cancellations                           | Fresh on clean exact baseline; Node 24.22.1 Linux                         |
| Adversarial campaign          | 264 passed across nine families                                                        | Fresh exact baseline; overlaps native tests                               |
| IUDX/comparison               | 14 passed; local TLS and synthetic interfaces only                                     | Fresh exact baseline; overlaps native tests                               |
| Focused custody/recovery      | 17 passed                                                                              | Fresh exact baseline; overlaps other suites                               |
| Downloaded evaluation package | 687 manifest entries match independently retained digest; 18 source tests passed again | Fresh integrity/reproduction of historical hosted artifact                |
| T8.1 sustained traffic        | 188/188 delivered, zero refusals/mismatches/failures                                   | Historical hosted run at identical source tree; rerun required for P0-041 |
| Network matrix                | 35/35, plus 1% and 3% loss profiles 5/5 each                                           | Historical hosted single-kernel namespaces; not independent machines      |
| Hosted CI and Security        | All four final workflow runs successful                                                | Historical exact head or identical PR merge tree                          |

Native source digest: `e430261b2735ddd35b6e78f89dbefef08bea1b6b88c65183c949c1088723c58d`.
Hosted runs: CI 42567545080, Security 42567545082, push CI 42567538931 attempt 2,
push Security 42567538589. The initial push container scan hit a Trivy HTTP 504;
retrying the failed job succeeded. Preserve that failure; it was not a software-test failure.

Downloaded package manifest SHA-256:
`2d46fb8e6e079e04b868701d52a95280e7c0dd908bfe06252bb78863f6509b28`.
Downloaded artifact ZIP SHA-256:
`6e38a7c0252281e4acc5ca5df29cb38b803b4d9daaeabc7d5c2882f3baaf03ae`.
The artifact records PR merge commit `aa7dc8206ad026580d3390a534079406eb54b923`;
its tree matches the specified head. This equivalence was checked, not assumed.

Fresh baseline benchmarking overlapped other verification work and is not used as an uncontended
performance comparison. Candidate comparisons run sequentially under a separately declared scope.
No counts are added across overlapping suites or transferred to a new commit.

All 19 gaps in `assurance/iaf/plan.json` remain owned and explicitly retained. The highest-risk
new reproduced engineering defect was selective authorization rollback (ADR 017), followed by
writer conflict/floor enforcement (ADR 018). These corrections require new candidate validation.
External identity, approved crypto, hardware custody, independent host administration, integration
contracts, operational acceptance and final qualification remain unestablished. Provisional TRL 4
is unchanged; an upgrade requires applicable assessment evidence.
