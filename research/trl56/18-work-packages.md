# Implementation work packages

Generated from `integration-backlog.csv` by `python3 research/trl56/validate.py --write-views`. All owners are role placeholders, not named appointments or contracted staff. Estimates are rough engineering person-days; external lead time is additional.

WP01–WP03 are evidenced only at the frozen implementation. WP04 is a completed repository reconciliation. WP05's document comparison is complete, but presentation corrections and owner/programme decisions remain open. Other packages are future work.

| ID   | Work package                                              | Phase / priority | State                         | Depends on                              | Person-days                  |
| ---- | --------------------------------------------------------- | ---------------- | ----------------------------- | --------------------------------------- | ---------------------------- |
| WP01 | Image vulnerability remediation                           | P0 / P0          | EVIDENCED_FROZEN_BASELINE     | None                                    | 0 remaining at baseline      |
| WP02 | CodeQL SARIF and application findings                     | P0 / P0          | EVIDENCED_FROZEN_BASELINE     | None                                    | 0 remaining at baseline      |
| WP03 | Frozen build and release evidence                         | P0 / P0          | EVIDENCED_FROZEN_BASELINE     | WP01 WP02                               | 0 remaining at baseline      |
| WP04 | All-branch inventory and research reconciliation          | P0 / P0          | RECONCILED                    | WP03                                    | 1-2                          |
| WP05 | Filed proposal and HPSC claim reconciliation              | P0 / P0          | RECONCILED_OWNER_ACTION_OPEN  | WP04                                    | 2-3                          |
| WP06 | Requirements and relevant environment agreement           | P0 / P0          | PLANNED                       | WP05                                    | 3-5                          |
| WP07 | TLS ingress and mTLS service identities                   | P1 / P0          | PLANNED                       | WP03                                    | 4-7                          |
| WP08 | Isolated multi-node testbed                               | P1 / P0          | PLANNED                       | WP07                                    | 3-5                          |
| WP09 | Deterministic network impairment                          | P1 / P0          | PLANNED                       | WP08                                    | 3-5                          |
| WP10 | Versioned cryptographic provider boundary                 | P2 / P1          | PLANNED                       | WP05                                    | 5-10                         |
| WP11 | SAG evaluation and provider decision dossier              | P0 / P0          | EXTERNAL_BLOCKED              | WP05                                    | 2-3 plus agency time         |
| WP12 | Independent checkpoint custody                            | P2 / P0          | PLANNED                       | WP08                                    | 4-6                          |
| WP13 | Restore rollback containment                              | P2 / P0          | PLANNED                       | WP12                                    | 4-8                          |
| WP14 | WAN outage and revocation experiment                      | P2 / P0          | PLANNED                       | WP09 WP13                               | 4-7                          |
| WP15 | Hardware login and separate key-custody study             | P3 / P2          | CONDITIONAL                   | WP10 WP11                               | 5-10                         |
| WP16 | Independent synthetic integration adapter                 | P2 / P1          | PLANNED                       | WP08                                    | 5-8                          |
| WP17 | Redacted event collection and response                    | P1 / P1          | PLANNED                       | WP08                                    | 3-6                          |
| WP18 | Latency and capacity envelope                             | P2 / P1          | PLANNED                       | WP09 WP14                               | 4-7                          |
| WP19 | Signed offline release and dependency qualification       | P3 / P1          | PLANNED                       | WP03 WP10                               | 4-7                          |
| WP20 | Independent assessment and representative demonstration   | P4 / P0          | NOT_ENGAGED                   | WP06 WP11 WP14 WP16 WP17 WP18 WP19 WP21 | 5-10 plus assessor lead time |
| WP21 | Filed role and priority policy mapping                    | P2 / P0          | PARTIAL_BRANCH_IMPLEMENTATION | WP05 WP23                               | 4-7                          |
| WP22 | Field trial, licensing, training and support plan         | P3 / P1          | EXTERNAL_BLOCKED              | WP05 WP06                               | 3-5 plus programme lead time |
| WP23 | Integrate concurrent hardening and duty-policy candidates | P0 / P0          | PLANNED                       | WP04 WP05                               | 3-6                          |

## WP01 — Image vulnerability remediation

Owner role: **DevSecOps** (UNASSIGNED_ROLE). Exit authority: **Security reviewer**.

Traceability: R6 R12; tests CI-01.

Acceptance: Frozen run container job passes unchanged HIGH/CRITICAL gate and actual container exchange; repeat per candidate.

Evidence: `https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37683530326#job-113005587785`.

Dependency or limitation: New advisories require retriage.

## WP02 — CodeQL SARIF and application findings

Owner role: **Security engineering** (UNASSIGNED_ROLE). Exit authority: **Security reviewer**.

Traceability: R6 R12; tests CI-01.

Acceptance: Frozen SARIF gate records zero findings; schema/routing/browser-origin regressions retained.

Evidence: `https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37683530326#job-113005587425`.

Dependency or limitation: Dated scan scope only.

## WP03 — Frozen build and release evidence

Owner role: **Release engineering** (UNASSIGNED_ROLE). Exit authority: **Release reviewer**.

Traceability: R12; tests CI-01.

Acceptance: All six hosted jobs success; 87 tests and nine demo stages pass; 15 browser checks; checksums verified.

Evidence: `baseline-evidence.json`.

Dependency or limitation: Any source change requires fresh candidate run.

## WP04 — All-branch inventory and research reconciliation

Owner role: **Repository maintainer** (UNASSIGNED_ROLE). Exit authority: **Maintainer**.

Traceability: R12; tests CI-01.

Acceptance: All 16 remote branches at refreshed snapshot have frozen heads and dispositions; new draft feature changes reviewed separately from main; no older application code imported.

Evidence: `branch-inventory.json`.

Dependency or limitation: No automatic dependency or feature-branch merge.

## WP05 — Filed proposal and HPSC claim reconciliation

Owner role: **Proposal owner** (UNASSIGNED_ROLE). Exit authority: **Proposal owner and sponsor for scope changes**.

Traceability: R1 R4 R5 R7 R9 R12; tests SAG-01 T5-13.

Acceptance: All three submitted-copy annexures reviewed; every filed deliverable and major claim mapped; unsupported assertions corrected in presentation; owner records any proposed scope change separately.

Evidence: `17-proposal-reconciliation.md; proposal-claim-register.csv`.

Dependency or limitation: Signed application/contract and administrative category unresolved.

## WP06 — Requirements and relevant environment agreement

Owner role: **Systems architect** (UNASSIGNED_ROLE). Exit authority: **Sponsor V&V authority**.

Traceability: R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12; tests T5-08.

Acceptance: Sponsor or authorised V&V records classifications, workload, CTEs and acceptance matrix; no assumed approval.

Evidence: `evidence/requirements/decision-register.json (planned)`.

Dependency or limitation: IAF decisions; no elapsed-time promise.

## WP07 — TLS ingress and mTLS service identities

Owner role: **Security and deployment engineer** (UNASSIGNED_ROLE). Exit authority: **Security reviewer**.

Traceability: R1 R2 R5 R6; tests TLS-01 T5-01.

Acceptance: Authenticated TLS for every untrusted hop; wrong CA/name/client/expiry rejected; rotation and authority outage tested; no downgrade.

Evidence: `evidence/tls/*.json and redacted captures (planned)`.

Dependency or limitation: Synthetic lab can proceed; operational PKI requires sponsor.

## WP08 — Isolated multi-node testbed

Owner role: **Network test lead** (UNASSIGNED_ROLE). Exit authority: **Test lead**.

Traceability: R1 R4; tests T5-10.

Acceptance: Two client zones plus third unauthorised principal; control and relay separately addressable; administration and evidence custody isolated; inventory repeatable.

Evidence: `evidence/testbed/manifest.json and topology (planned)`.

Dependency or limitation: Equipment access; lab-only until environment approved.

## WP09 — Deterministic network impairment

Owner role: **Network test lead** (UNASSIGNED_ROLE). Exit authority: **Test lead**.

Traceability: R2 R3 R11; tests T5-02 T5-09 T5-11.

Acceptance: N0-N9 profiles logged with seed and observed counters; at least three repetitions; clean qdisc rollback; netem kernel/package pins frozen.

Evidence: `evidence/network/profiles-and-observations.json (planned)`.

Dependency or limitation: VM or isolated host with approved network privileges.

## WP10 — Versioned cryptographic provider boundary

Owner role: **Cryptographic engineer** (UNASSIGNED_ROLE). Exit authority: **Independent cryptographic reviewer**.

Traceability: R2 R5 R9 R10; tests T5-12.

Acceptance: Native provider conformance; unsupported suite/downgrade/provider failure rejected; opaque key-handle interface; PQC disposition documented without enabling unreviewed construction.

Evidence: `evidence/crypto/provider-conformance.json (planned)`.

Dependency or limitation: Graded provider SDK and PQC scope require sponsor decision.

## WP11 — SAG evaluation and provider decision dossier

Owner role: **Sponsor liaison** (UNASSIGNED_ROLE). Exit authority: **IAF cryptographic authority**.

Traceability: R9 R12; tests SAG-01.

Acceptance: Obtain attributable grading path, required implementation, exact evaluation scope and lifecycle controls; absent response remains blocked.

Evidence: `Private sponsor decision record; public status only`.

Dependency or limitation: External; not satisfied by primitive names, FIPS or self-labelled protocol.

## WP12 — Independent checkpoint custody

Owner role: **Evidence engineer** (UNASSIGNED_ROLE). Exit authority: **Independent reviewer**.

Traceability: R2 R10 R12; tests T5-07.

Acceptance: Verifier trust root and checkpoint retained outside issuer administration; append and checkpoint export independently verified; expected freshness stated.

Evidence: `evidence/audit/checkpoint-custody.json (planned)`.

Dependency or limitation: Separate custodian/operator needed.

## WP13 — Restore rollback containment

Owner role: **Control and storage engineer** (UNASSIGNED_ROLE). Exit authority: **Security reviewer**.

Traceability: R2 R7 R10 R12; tests T5-07.

Acceptance: Restore older policy/audit snapshot after revocation; compare independent checkpoint before new issuance; quarantine mismatch and missing checkpoint; no global rollback guarantee claimed.

Evidence: `evidence/recovery/rollback-transcript.json (planned)`.

Dependency or limitation: Authority recovery policy and maximum checkpoint gap require agreement.

## WP14 — WAN outage and revocation experiment

Owner role: **Endpoint and V&V engineer** (UNASSIGNED_ROLE). Exit authority: **V&V lead**.

Traceability: R1 R2 R5 R7 R10; tests T5-01 T5-02 T5-03 T5-05.

Acceptance: All network profiles preserve current-authority release; three revocation timing orders; 100 retries per case; locked vault, restart and loss documented.

Evidence: `evidence/wan/issuance-and-vault-results.json (planned)`.

Dependency or limitation: Offline use policy remains provisional.

## WP15 — Hardware login and separate key-custody study

Owner role: **Endpoint security engineer** (UNASSIGNED_ROLE). Exit authority: **Security reviewer**.

Traceability: R5 R10; tests T5-05 T5-12.

Acceptance: FIDO2 wrong-origin and recovery tests; separate TPM/HSM key extraction/removal review; no claim that login token protects content key automatically.

Evidence: `evidence/hardware/mechanism-matrix.json (planned)`.

Dependency or limitation: Exact model/firmware/OS and mechanism support before purchase.

## WP16 — Independent synthetic integration adapter

Owner role: **Integration engineer** (UNASSIGNED_ROLE). Exit authority: **Integration reviewer**.

Traceability: R8; tests T5-06.

Acceptance: Separate process and keys; accepted authorised envelope plus wrong source/schema/signature/stale grant/duplicate failures; no policy bypass.

Evidence: `evidence/interop/mock-results.json (planned)`.

Dependency or limitation: Real IAF interface and identity federation await owner-provided contract.

## WP17 — Redacted event collection and response

Owner role: **Security operations engineer** (UNASSIGNED_ROLE). Exit authority: **Operations reviewer**.

Traceability: R6 R10; tests T5-04.

Acceptance: Independent sink detects seeded failed login/replay/denied action; secret/plaintext canaries absent; operator acknowledges and documents response.

Evidence: `evidence/monitoring/events-and-triage.json (planned)`.

Dependency or limitation: Retention, metadata and agent scope require agreement.

## WP18 — Latency and capacity envelope

Owner role: **Performance test engineer** (UNASSIGNED_ROLE). Exit authority: **Test lead and sponsor for SLA**.

Traceability: R3 R4 R11; tests T5-09 T5-10 T5-11.

Acceptance: Measured online latency and load sweep meet provisional targets or record FAIL; resource/queue/error telemetry; no fleet or horizontal scaling claim.

Evidence: `evidence/performance/raw-and-summary.json (planned)`.

Dependency or limitation: Provisional lab targets are not IAF requirements.

## WP19 — Signed offline release and dependency qualification

Owner role: **Release engineering** (UNASSIGNED_ROLE). Exit authority: **Release and security reviewers**.

Traceability: R4 R10 R12; tests CI-01 T5-10.

Acceptance: Sign build/source/SBOM manifest with independently trusted release key; offline install and signature verification; wrong root, tampered file and downgrade rejected.

Evidence: `evidence/release/offline-verification.json (planned)`.

Dependency or limitation: Offline deployment is not air-gap information exchange; licensing review required.

## WP20 — Independent assessment and representative demonstration

Owner role: **Independent V&V lead** (UNASSIGNED_ROLE). Exit authority: **Sponsor V&V authority**.

Traceability: R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12; tests T5-08 SAG-01.

Acceptance: Witness approved matrix against exact build; critical/high unresolved findings block; each criterion PASS/FAIL/BLOCKED; sponsor issues separate TRL decision.

Evidence: `evidence/assurance/signed-report-and-decision (planned)`.

Dependency or limitation: No assessor engaged or slot booked; crypto approval separate.

## WP21 — Filed role and priority policy mapping

Owner role: **Authorization engineer** (UNASSIGNED_ROLE). Exit authority: **Information owner and security reviewer**.

Traceability: R7; tests T5-13.

Acceptance: Owner maps six filed duty roles and four priorities to approved actions; default deny; full 24 role-priority cross-product plus direct API and issue-time tests; no universal system-admin decrypt privilege; dedicated highest-priority authorization action reviewed separately from write; branch E020 supplies partial implementation only.

Evidence: `evidence/policy/approved-role-matrix-and-tests.json (planned)`.

Dependency or limitation: Filed taxonomy is applicant proposal, not confirmed IAF authority.

## WP22 — Field trial, licensing, training and support plan

Owner role: **Programme and delivery lead** (UNASSIGNED_ROLE). Exit authority: **Programme owner and sponsor**.

Traceability: R8 R12; tests T5-08.

Acceptance: Named trial authority and site, accepted integration scope, costed review plan, training/handover checklist, source licence review and support obligations agreed before rollout.

Evidence: `Private trial/handover/support decision record; public status only`.

Dependency or limitation: Filed 12-month schedule is not signed trial/certification/rollout authorisation.

## WP23 — Integrate concurrent hardening and duty-policy candidates

Owner role: **Integration and security engineer** (UNASSIGNED_ROLE). Exit authority: **Security and release reviewers**.

Traceability: R2 R5 R7 R12; tests INT-01.

Acceptance: Preserve foundation stored-envelope revalidation while supporting authenticated v1/v2 envelopes and current duty policy; no signature/epoch bypass; retain research validator in replacement CI; rerun full combined candidate gates.

Evidence: `evidence/integration/combined-candidate.json (planned)`.

Dependency or limitation: Draft PR2 and PR13 are not combined; proposed role semantics require owner/sponsor decision.

## Execution record required for closure

Record actual owner, start/end, tested commit/tree/source digest, configuration and environment hashes, commands or approved manual procedure, raw evidence paths and checksums, expected versus actual metrics, defects, deviations and reviewer decision. Proposed `evidence/` paths above are an artifact contract, not files already produced. Laboratory runners are not implemented by this documentation update.

Existing runnable commands: `npm run validate`, `npm run test:browser`, and `python3 research/trl56/validate.py --self-test`. Browser validation requires its fresh synthetic deployment and installed Chromium as described in the application runbook. Future lab packages must add their own runnable harnesses before closure.
