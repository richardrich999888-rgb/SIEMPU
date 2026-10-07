# Implementation status

This ledger separates the inspected starting point, accepted design and measured implementation. It must be updated from actual build/test artifacts before release. A design decision or source file is not a passing result.

## Verified starting baseline

Inspected starting commit: `f0d1db2e8c1415aa99543c96939ae00374ca6c5a`.

Command: `git ls-tree -r --name-only f0d1db2e8c1415aa99543c96939ae00374ca6c5a`.

Observed output: `LICENSE`, `README.md`. README contained only the repository title; LICENSE was Apache-2.0. There were no source files, framework, package manager configuration, database, frontend/backend, build commands, tests, Docker files, CI/CD, migrations or runtime environment configuration at that commit. There was no existing build or test suite to execute; this is **NOT AVAILABLE**, not a passing baseline.

The research report and implementation brief informed the new design. No private portfolio code was imported. The repository slug is `SIEMPU`; the official requirement and product acronym is `SIEPMU`.

## Implemented engineering checkpoint

Status: **PROTOTYPE with measured engineering tests**. The initial empty baseline above remains the historical starting point. Source and execution evidence now exist; this replaces the earlier planned-only table. It does not imply operational acceptance.

Recorded local Node test output: **57 tests passed, 0 failed**, in `artifacts/test-coverage.txt` at documentation capture. Core authority coverage: 93.77% lines, 89.27% branches. Whole-run coverage scope is different: use the exact report and package filters; do not compare unqualified percentages. Additional changes require rerunning the gates. Actual Chromium validation and the measured benchmark have committed evidence records linked below.

| Component                         | Current implementation / test status                                                              | Security scope / missing work                                                                          | Priority              |
| --------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | --------------------- |
| Runtime / services                | Three real Node processes; HTTP integration exercised                                             | Single-host; no HA                                                                                     | P1 pilot              |
| Identity / MFA                    | Password, mandatory TOTP, durable replay/session revoke and offline administrator recovery tested | External IdP, self-service recovery and phishing-resistant MFA absent                                  | P1                    |
| Roles / object authority          | Current state checked at API and release; negative tests passed                                   | Generic roles, not approved IAF duty matrix                                                            | P1                    |
| Devices                           | Enrollment/approval/possession/revoke tested                                                      | Software keys only                                                                                     | P1                    |
| E2EE / vault                      | Native/WebCrypto interoperability and browser text passed                                         | No forward secrecy/hardware custody; file browser path untested                                        | P1                    |
| Relay                             | Ciphertext-only separate store; workload auth/replay tests                                        | Host and control authority remain trusted                                                              | P1                    |
| Epoch release                     | Independent-process races, crash/restart/retry tests passed                                       | Commit issuance guarantee, no recall or global revoke                                                  | P0 retained invariant |
| Evidence                          | Detached verifier and anchored negative tests passed                                              | Independent checkpoint custody required                                                                | P1                    |
| Database / recovery               | v1/v2 migrations and encrypted restore tests passed                                               | No automatic full-snapshot anti-rollback                                                               | P1                    |
| Browser / admin                   | Real Chromium MFA/exchange/hold/release/offline-reload passed                                     | Other engines and browser download journey untested; subsequent enrollment/approval run passed         | P1                    |
| Monitoring                        | Structured logs, alerts, metrics and admin view                                                   | No distributed traces/SIEM; retention work                                                             | P1                    |
| Integration                       | Authenticated synthetic schema adapter                                                            | Live IAF integration not implemented                                                                   | External              |
| Quality/security                  | Local syntax/lint/format/scoped types/tests/build/SBOM run                                        | Type checking partial; hosted scans are separate evidence                                              | P1                    |
| Docker / CI                       | Definitions and actual hosted build/start attempted; three services reached healthy               | Exact-head end-to-end probe/scanner results must pass; earlier probe failed and fix under verification | P0 release gate       |
| HPSC                              | HTTP scenario executed; real browser scenario separately passed                                   | Combine rehearsed live story and approved programme material                                           | P1                    |
| Performance                       | 30 sequential 4 KiB loopback objects: 12.21/s measured                                            | WAN, maximum capacity and server resources not measured                                                | P1                    |
| SAG / IAF / independent assurance | NOT APPROVED / NOT PERFORMED                                                                      | Sponsor and independent acceptance required                                                            | External              |

Use [execution checklist](EXECUTION_CHECKLIST.md) for every section of both implementation briefs, [traceability](TRACEABILITY_MATRIX.md) for PS-69, [testing](testing.md), [browser evidence](testing/browser-validation.md), [performance](performance.md) and [limitations](limitations.md). An actual container build is distinct from a fully passed deployment, scan or release pipeline.

## Evidence update rule

For each update record full commit (or dirty-tree digest), configuration, exact command, date, exit status, evidence path, workload and limitation. Preserve failed attempts where they explain fixes. Distinguish implemented/unverified, executed/passing, simulated, measured and externally approved. Do not mark remote CI, container execution, restore or hardware tests passed from the presence of their scripts.

Status vocabulary: PROTOTYPE → DEMO-READY → ENGINEERING-VALIDATED → PILOT-READY → PRODUCTION-READY → FORMALLY/EXTERNALLY ASSURED. Progress is evidence- and scope-dependent; a successful happy path does not move the whole platform through this sequence.
