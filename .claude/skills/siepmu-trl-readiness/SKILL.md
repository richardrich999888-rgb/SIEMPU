---
name: siepmu-trl-readiness
description: TRL 5/6 readiness tracking for SIEPMU - work packages WP01-WP23, critical technology elements, acceptance evidence, external gates, and the exact status vocabulary to use. Use when reporting progress, updating readiness matrices, planning next work, or writing anything that mentions TRL, readiness, validation, demonstration, acceptance or approval.
---

# SIEPMU TRL readiness

## Definitions used here

- **TRL 5**: critical technology elements validated in a relevant environment.
- **TRL 6**: representative integrated prototype demonstrated in a relevant environment.
- Unit tests, green CI or a demo are inputs to these, not a TRL decision. Formal TRL assignment,
  the "relevant environment" and acceptance criteria are for the sponsor/assessor (WP06, WP20).

## Separate status axes (report each independently)

1. Engineering implementation (code exists, tests pass on a SHA)
2. Reproducible laboratory validation (hosted CI or scripted run, artefacts retained)
3. Relevant-environment validation (agreed environment; not yet defined - WP06)
4. Representative prototype demonstration
5. Independent security assessment (not engaged)
6. Sponsor acceptance (not engaged)
7. SAG cryptographic grading (external; WP11)
8. Operational deployment authorization (external)

Only axes 1 and 2 can be established inside this repository.

## Where the records live

| Record                                     | Path                                                               | Notes                                |
| ------------------------------------------ | ------------------------------------------------------------------ | ------------------------------------ |
| Work packages WP01-WP23                    | `research/trl56/18-work-packages.md`                               | statuses frozen at the main baseline |
| CTE readiness                              | `research/trl56/cte-readiness-matrix.csv`                          | CTE01-CTE09                          |
| Requirements -> tests                      | `research/trl56/requirement-traceability.csv`                      | R1-R12                               |
| TRL5 / TRL6 matrices                       | `research/trl56/trl5-test-matrix.csv`, `trl6-readiness-matrix.csv` | planned tests                        |
| Risk register                              | `research/trl56/14-technical-risk-register.md`                     |                                      |
| Engineering evidence on the current branch | `docs/engineering/WORK_PACKAGE_REGISTER.md`                        | maps WP IDs to code, tests, CI runs  |
| Current state                              | `docs/engineering/CURRENT_STATE.md`                                | single authoritative status          |

`research/trl56/validate.py --self-test` enforces consistency (including mutation checks) of the
research CSV/JSON records. Do not edit those statuses to reflect branch work without updating the
validator's expectations in the same change; record branch evidence in the engineering register.

## Workflow

1. Identify the WP and CTE affected.
2. Produce evidence: command, SHA, artefact, hosted run URL.
3. Update `docs/engineering/WORK_PACKAGE_REGISTER.md` (axis 1/2 status) and `CURRENT_STATE.md`.
4. If external input is needed, add the question to `research/trl56/16-iaf-clarification-register.md`.

## Vocabulary

Use: IMPLEMENTED_LAB, VALIDATED_LAB (hosted, on SHA), PARTIAL, PLANNED, EXTERNAL_BLOCKED,
NOT_ENGAGED. Never: "TRL 5 achieved", "TRL 6 ready", "accepted", "certified", "approved",
unless an external body's decision document is cited.

## Definition of done

Every status change cites evidence on an exact SHA; no axis-3+ claim without an external record;
`python3 research/trl56/validate.py --self-test` and `npm run audit:claims` pass.

## Current assessment (integration branch)

The authoritative CTE matrix for the integration branch is `docs/trl/cte-trl-matrix.json`
(report `docs/trl/TRL_ASSESSMENT.md`): system provisional TRL 4; CTE-03/04/05/06 are TRL 5
candidates; CTE-07/08/09 at TRL 3. `tests/trl-matrix.test.mjs` fails if any element exceeds 4
while the relevant environment is undefined, or if an external axis is marked complete.
`research/trl56/cte-readiness-matrix.csv` remains the frozen `main` baseline.
