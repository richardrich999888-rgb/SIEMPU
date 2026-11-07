# Verified work-package register (engineering axes only)

7 November 2026 follow-up, WP16 integration / CTE-08: source-sealed transport and protected
outbox IMPLEMENTED_LAB candidate (ADR-015), 14 initial new tests passed. The initial
preflight passed 46/46 integration/boundary/package tests. After the readiness correction,
33/33 focused tests, all ten native gates / 410 tests, 3/3 E2E and the 220-test adversarial
campaign passed on `11f0768` (see CURRENT_STATE). Hosted final-candidate validation
remains pending at this edit. G05 remains open as PARTIAL_LAB, with
legacy migration and real-interface/host acceptance pending. WP06/WP20 external inputs
and the provisional TRL 4 assessment are unchanged.

Work-package IDs and definitions: `research/trl56/18-work-packages.md` (statuses there are frozen
at the `main` baseline and validated by `research/trl56/validate.py`). This register records only
**axis 1 (engineering implementation)** and **axis 2 (reproducible laboratory validation)** for the
integration branch. Axes 3–8 (relevant environment, demonstration, independent assessment, sponsor
acceptance, SAG grading, operational authorisation) are external and not established by any entry.

Status vocabulary: `IMPLEMENTED_LAB` (code + passing tests on a SHA), `VALIDATED_LAB` (hosted CI
green on that SHA), `PARTIAL`, `PLANNED`, `EXTERNAL_BLOCKED`, `NOT_ENGAGED`.

| WP      | Title                                                    | Axis 1/2 status                      | Evidence (code / tests)                                                                                                                                                                                                                                                     | Hosted evidence                | Gap                                  |
| ------- | -------------------------------------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ------------------------------------ |
| WP04    | Branch inventory and research reconciliation             | VALIDATED_LAB                        | `docs/engineering/RECONCILIATION_MATRIX.md`, ADR-006                                                                                                                                                                                                                        | see CURRENT_STATE              | —                                    |
| WP07    | TLS ingress and mTLS identities                          | IMPLEMENTED_LAB                      | `packages/transport/tls.mjs`; `tests/transport/*.test.mjs`                                                                                                                                                                                                                  | CI native                      | No real PKI/OCSP                     |
| WP08    | Isolated multi-node testbed                              | IMPLEMENTED_LAB                      | `deployment/testbed/provision.mjs`, `run.mjs`                                                                                                                                                                                                                               | CI testbed job                 | Single runner, containers            |
| WP09    | Deterministic network impairment                         | IMPLEMENTED_LAB                      | netem `profiles.json`; userspace `fault-proxy.mjs`; `tests/network-failure/`                                                                                                                                                                                                | CI testbed + native            | Not a WAN                            |
| WP10    | Versioned crypto provider boundary                       | IMPLEMENTED_LAB                      | `crypto.mjs` provider port, `packages/crypto-provider/`; `tests/crypto-provider.test.mjs`, `tests/crypto-agility/`                                                                                                                                                          | CI native, pqc-lab             | No HSM/PKCS#11 provider              |
| WP11    | SAG evaluation and provider dossier                      | EXTERNAL_BLOCKED                     | `research/trl56/04-sag-crypto-integration-pathway.md`                                                                                                                                                                                                                       | —                              | SAG engagement                       |
| WP12    | Independent checkpoint custody                           | IMPLEMENTED_LAB                      | `services/evidence/custody.mjs`; `tests/checkpoint-custody.test.mjs`                                                                                                                                                                                                        | CI native                      | Custodian on same host               |
| WP13    | Restore rollback containment                             | VALIDATED_LAB                        | recovery guard; `tests/recovery.test.mjs`, `checkpoint-custody.test.mjs`; mission workflow step 16 (live snapshot restore -> 503); TLA+ `AckedRevocationHolds`                                                                                                              | CI native, rust-native, formal | —                                    |
| WP14    | WAN outage and revocation experiment                     | IMPLEMENTED_LAB                      | `tests/network-failure/recovery.test.mjs`; `scripts/trust-before-release.mjs` (fault proxy outage, revocation during outage, selective release); testbed N4/N5                                                                                                              | CI native                      | No real WAN                          |
| WP15    | Hardware login and key custody                           | PLANNED                              | `docs/security-assurance/key-custody-matrix.md`                                                                                                                                                                                                                             | —                              | Hardware authorisation               |
| WP16    | Synthetic integration adapter                            | IMPLEMENTED_LAB                      | `services/integration/`, `apps/document-system/`; `tests/independent-services.test.mjs`, `tests/integration-adapter.test.mjs`, `tests/document-system.test.mjs`; Demo 3                                                                                                     | CI native                      | Synthetic interface only             |
| WP17    | Redacted event collection                                | IMPLEMENTED_LAB                      | `services/monitoring/`; `tests/monitoring.test.mjs`, `tests/access-alerts.test.mjs`, `tests/threat-detections.test.mjs`; Demo 4 (telemetry stall fixed `0e8d1b9`); mission step 18 leak scan with positive controls                                                         | CI native                      | No external SIEM                     |
| WP18    | Latency and capacity envelope                            | PARTIAL                              | `scripts/benchmark.mjs`, testbed measurements                                                                                                                                                                                                                               | CI testbed                     | No sponsor targets                   |
| WP19    | Signed offline release                                   | IMPLEMENTED_LAB                      | `packages/release/offline.mjs`; `tests/offline-release.test.mjs`                                                                                                                                                                                                            | CI native                      | Lab key only                         |
| WP20    | Independent assessment and demonstration                 | NOT_ENGAGED                          | —                                                                                                                                                                                                                                                                           | —                              | External                             |
| WP21    | Filed role and priority policy                           | IMPLEMENTED_LAB (provisional policy) | `packages/mission/policy.mjs`, FLASH approval; `tests/filed-mission-*.test.mjs`, `flash-approval.test.mjs`                                                                                                                                                                  | CI native                      | Sponsor confirmation                 |
| WP23    | Integrate concurrent candidates                          | VALIDATED_LAB                        | this branch                                                                                                                                                                                                                                                                 | see CURRENT_STATE              | —                                    |
| PQC-E2E | Lab PQC end-to-end application flow (not in the WP list) | IMPLEMENTED_LAB                      | `packages/pqc-lab/envelope.mjs`, `services/crypto-policy/`, authority v3 path (ADR-010); `tests/pqc/end-to-end.test.mjs`, `tests/crypto-agility/wrap-derivation.test.mjs`, X-Wing case in `laboratory.check.mjs`; spec `research/cryptographic-standards/V3_COMPOSITION.md` | CI native, pqc-lab             | Independent review, SAG, browser PQC |

Added on `claude/siepmu-trl56-recovery-9o6qet` (hosted CI and Security green on `7b01d1a`):

| ID        | Title                                        | Axis 1/2 status | Evidence (code / tests)                                                                                           | Hosted evidence    | Gap                                                |
| --------- | -------------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------ | -------------------------------------------------- |
| RUST-1    | Rust reference evidence verifier (ADR-012)   | VALIDATED_LAB   | `native/evidence-verify`; `spec/`; 63+16 vectors; `tests/native/evidence-differential.check.mjs`; `cargo audit`   | CI rust-native     | Strict release mode stays Node; slower than Node   |
| FORMAL-1  | TLA+ release/revocation/recovery model       | VALIDATED_LAB   | `formal/ReleaseAuthority.tla`; `scripts/formal-check.mjs` (faithful passes, two mutants fail)                     | CI formal          | Bounded instance; code conformance argued only     |
| MISSION-1 | Core Mission Workflow (18 steps, 2 profiles) | VALIDATED_LAB   | `scripts/mission-workflow.mjs`; `docs/engineering/MISSION_WORKFLOW.md`                                            | CI rust-native     | Single host; no relevant environment               |
| UI-1      | Decision explanations and capability model   | VALIDATED_LAB   | `apps/unit-client/decisions.mjs`, `capabilities.mjs` (ADR-013); unit tests; browser assertion for `POLICY_DENIED` | CI native, browser | Security/evaluation view, usability and a11y audit |

WP01–WP03, WP05, WP06, WP22 are documentation, evidence-freezing or external items; see the research dossier.
"CI native" means the `native` job of `.github/workflows/ci.yml`; the run URL for the SHA is in
`docs/engineering/CURRENT_STATE.md`. An entry is never upgraded without a command and SHA.

## WP11 preparation increment (7 November 2026)

Applicant dossier and executable package builder/verifier: `assurance/sag/`,
`tests/sag-evaluation.test.mjs`, `docs/security-assurance/SAG_EVALUATION_DOSSIER.md`.
The preparation implementation is separate from the WP11 external grading decision,
which remains EXTERNAL_BLOCKED. Commands, candidate revision and final evidence are
recorded in CURRENT_STATE and the preparation PR; no external axis is upgraded here.

## Adversarial qualification preparation (7 November 2026)

WP16/18: bounded adapter submissions, request snapshots/freshness, authenticated
readiness, local session cleanup and redacted startup diagnostics are implemented.
Nine executable laboratory families and nineteen open qualification gaps are recorded
in `assurance/iaf/plan.json` and `docs/trl/TRL8_QUALIFICATION.md`. Exact execution evidence
is in the candidate PR and campaign report. No external readiness axis is upgraded.
The plaintext integration boundary and prior unexplained startup failure remain open.

## PS-69 requirement review and threat detection increment (7 November 2026)

Official PS-69 pages 161–162 were retrieved and visually verified. WP17 now includes
persistent signed threat-signal detections, bounded correlation windows/storage,
restart/replay suppression and operator-only disposition; targeted tests pass.
The defaults are applicant laboratory rules, not IAF incident policy or an SLA.
WP06 relevant-environment agreement and WP20 independent assessment remain external.
The old D-T5-01 scaling fix is retained as completed historical work; it is not a new
claim on this increment. Exact full-candidate results belong to CURRENT_STATE and
the final draft PR handover. No external status is upgraded.
