# 09 — TRL readiness update (2026-10-10)

**Decision unchanged: provisional TRL 4** — validated laboratory prototype with the TRL 5 advancement tests
completed and gates outstanding. `tests/trl-matrix.test.mjs` is unchanged and still holds every element at
TRL ≤ 4 while the relevant environment is not defined by the sponsor.

## Effect of this branch on the four blocking reasons (`docs/trl5/READINESS_DECISION.md`)

| #   | Blocking reason                           | Status after this branch                                                                                                                                                                                                        |
| --- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Environment is not a relevant environment | **Unchanged.** Namespaces on one kernel; sponsor definition still missing (Q14).                                                                                                                                                |
| 2   | No independent witness                    | **Unchanged.**                                                                                                                                                                                                                  |
| 3   | Scaling defect D-T5-01 bounds throughput  | **Resolved in code and re-tested in the same environment**: 33/33, T8.1 1.56 → 5.93 exchanges/s, custodian CPU 72.3 % → 17.1 % (`docs/trl5/evidence/1a0218d/`). Not yet run in hosted CI on this branch at the time of writing. |
| 4   | Packet loss only on namespaces            | **Unchanged** (this container has no netem; loss not emulated in the re-run).                                                                                                                                                   |

Reasons 1, 2 and 4 are each sufficient on their own. Removing reason 3 removes the only engineering blocker
that was inside the applicant's control; the remainder are external gates.

## CTE-level effect

| CTE                     | Before                           | After                                                                                |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------ |
| CTE-06 evidence custody | Candidate, with a scaling defect | Candidate; defect fixed with negative tests, TLC re-run, relevant-environment re-run |
| Others                  | Unchanged                        | Unchanged                                                                            |

## What would justify proposing TRL 5 (not claimed)

1. Sponsor-defined relevant environment (Q14) with separate machines or VMs and a defined network.
2. Witnessed execution of the declared matrix on that environment, including packet-loss profiles.
3. Hosted CI green on the fixed revision (CI and Security workflows) and the frozen evidence linked to it.

Status vocabulary follows `.claude/skills/siepmu-trl-readiness/`: this branch adds **engineering
implementation** and **laboratory validation** only.
