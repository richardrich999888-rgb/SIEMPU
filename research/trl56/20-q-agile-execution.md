# Quantum-agile execution addendum

Started 8 October 2026. This addendum tracks the new implementation programme without rewriting the earlier frozen research evidence. It is not a TRL determination, a SAG grade or IAF approval. Public comparative research is in [defence comparison](../defence-comparison/README.md); hardware and independent review gates are in [the custody matrix](../../docs/security-assurance/key-custody-matrix.md).

## Fresh starting baseline

| Record                   | Observed value                                                          | Scope                                                                                                |
| ------------------------ | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Starting `main`          | `ad80210a0bc0185d74887b34e4d213350a86e4c3`                              | Clean working tree before new edits                                                                  |
| Local verification       | `npm run verify`, exit 0; 87 tests, zero failures                       | Baseline only; does not test integration of PR2 and PR13                                             |
| Verification log SHA-256 | `661219f216e165d7264dacfa31c9d3334e1add56412a9384d1543a276c7cd3f8`      | Generated baseline record under `artifacts/q-agile-baseline/`                                        |
| Runtime                  | Node `v24.19.0`, embedded OpenSSL `3.5.7`, x64                          | Runtime actually used for baseline                                                                   |
| OS                       | `Linux-6.18.44-x86_64-with-glibc2.39`                                   | Local environment; not target equipment                                                              |
| Dependency inventory     | No npm runtime dependencies; 84 development dependency entries recorded | Does not mean no runtime/platform dependencies                                                       |
| Integration checkpoint   | `b9a40f827c8db4461bfa63b1df788aa995d03bbe`                              | Local foundation merge; combined candidate verification pending when this addendum was first written |

Earlier documents and CSV matrices intentionally retain their named historical snapshots. Their 87-test or hosted-job evidence must not be transferred to a new code revision. New results below require an exact source revision/digest, command, outcome and retained artifact. A test plan is not a pass.

## Work-package status

`IN_PROGRESS` means implementation is underway with no final combined-tree result recorded here. `PLANNED` means acceptance work is not yet evidenced. `EXTERNAL_BLOCKED` names an unavailable external dependency. None implies achieved TRL.

| Work package                               | Status at this update                                                          | Existing requirement / CTE mapping         | Acceptance evidence still required                                                                                                                              |
| ------------------------------------------ | ------------------------------------------------------------------------------ | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q01 — PR2/PR13 reconciliation              | PASS — local combined tests                                                    | R2/R7/R12; CTE01/02/03/06; INT-01          | Strict v1/v2 canonical contract; valid legacy/current exchange; modified signature, context, stored envelope and downgrade rejection; fresh combined regression |
| Q02 — classical provider boundary          | PASS — local provider tests                                                    | R2/R5/R9/R10; CTE01/09; T5-12              | Classical ciphertext compatibility; declared suites/key IDs; lifecycle/failure tests with no weaker fallback                                                    |
| Q03 — isolated PQ laboratory candidate     | PASS — isolated vectors/interoperability/benchmark                             | R2/R5/R9; CTE01/09; T5-12                  | Vetted implementation and license inventory; authoritative vectors, interoperability, endpoint key secrecy, explicit lab scope and measurements                 |
| Q04 — dynamic release and signed evidence  | PASS — local release/race/recovery/verifier tests                              | R2/R7/R12; CTE03/06; T5-05/T5-07/INT-01    | Revocation/role/mission change before release, retry, crash and restore tests; independently checked outcomes                                                   |
| Q05 — interrupted-connectivity experiments | PASS — userspace constrained/interrupted profiles                              | R1/R2/R10/R11; CTE04/05; T5-02/T5-09/T5-11 | Executed impairment profile, exact-byte recovery, duplicate semantics, latency/resource data; distinguish proxy and netem evidence                              |
| Q06 — authenticated transport / testbed    | PASS — local TLS1.3/mTLS listener tests                                        | R1/R4/R6; CTE04; TLS-01/T5-10              | Actual TLS/mTLS execution, service trust rejection, independent nodes and repeatable secure installation                                                        |
| Q07 — hardware authentication/custody      | EXTERNAL_BLOCKED for qualification; software experiment may proceed            | R5/R10; CTE02/09; T5-03/T5-12              | Separate WebAuthn, provider-handle and attestation evidence; actual target hardware and HQ gates                                                                |
| Q08 — independent synthetic adapter        | PASS — synthetic authenticated emulator; actual IAF interface EXTERNAL_BLOCKED | R8; CTE08; T5-06                           | Independent authenticated emulator, strict schema, replay/idempotency and audit correlation; authorized real specification later                                |
| Q09 — Trust Before Release demonstration   | PARTIAL — constituent scenarios pass                                           | R2/R5/R7/R10/R12; CTE01/02/03/05/06/09     | Executed synthetic deny-after-revocation plus eligible exact-byte exchange; independent evidence and rejected downgrade; reset and measured profiles            |
| Q10 — external assurance and TRL decision  | EXTERNAL_BLOCKED                                                               | R9/R12; CTE09; SAG-01                      | Independent design review, sponsor-approved relevant environment, witnessed results and competent acceptance decision                                           |

## Evidence ledger

| Evidence                                       | Revision                                   | Result                                                                  | Limitation                                                                             |
| ---------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Fresh starting verification                    | `ad80210a0bc0185d74887b34e4d213350a86e4c3` | PASS: 87 native tests in `npm run verify`                               | Local classical starting baseline only                                                 |
| Combined protocol/security regression          | `b9a40f8`                                  | PASS: 197 tests; `npm run verify` exit 0                                | Earlier PR2 and PR13 green checks do not establish their combined behaviour            |
| PQ conformance / interoperability              | `b9a40f8`                                  | PASS: isolated vectors/interoperability and four profiles benchmarked   | No conformance, performance or production claim made                                   |
| Network/hardware/independent-custody execution | `b9a40f8`                                  | PASS: TLS/mTLS, userspace impairment, adapter and browser upgrade tests | No actual target devices or independently operated relevant environment evidenced here |
| Hosted candidate CI / PR                       | Not published yet                          | PENDING: exact branch head and hosted workflow still required           | Must identify actual remote branch/head/run after publication                          |

Update this ledger only from completed runs and reviewed artifacts. For a failed gate, retain the failure and its remediation evidence; do not rename an unexecuted or failing scenario into a pass.

## TRL 5 and TRL 6 exit boundaries

TRL 5 preparation requires integrated CTE evidence under an agreed relevant environment: authenticated networking, secure exchange, current-policy release, interruption recovery, provider interoperability and independently checked evidence. Before evaluating a gate, the sponsor/assessor must accept the workload, environmental assumptions, measurable limits and witness arrangements. Internal provisional targets remain provisional.

TRL 6 preparation additionally needs representative independently operated nodes and managed endpoints, qualified hardware where required, an authenticated integration adapter, controlled monitoring, deployment/recovery repeatability and an independently reproducible demonstration. A same-host process topology and emulator can advance engineering but cannot substitute for these conditions. Formal maturity and approval decisions remain external.

Open scope decisions from the filed application remain open: mandatory duty-role/action mapping, highest-priority approval workflow, actual IAF identity/interface definitions, graded-provider requirements and custody/recovery policy. Comparative U.S./Russian material does not settle any of them. No new radio waveform, tactical peer-to-peer network, cross-domain classified transfer or unsupported AI detector is added by this programme.
