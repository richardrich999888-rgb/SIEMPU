# AIRON–SIEPMU: TRL 8 qualification target and remaining work

7 November 2026 (India). Engineering baseline: PR #30,
`3244158f3d1f8fabe1b745b1588392f82884dfcf`. This plan does not assign TRL 8.
The existing provisional TRL 4 self-assessment stays unchanged.

NITI Aayog's published TRL scale describes level 8 as a completed technology system
qualified through testing and demonstration ([Table 2](https://www.niti.gov.in/node/873),
retrieved 7 November 2026). This is a general Indian government reference; the IAF
programme owner must confirm the applicable framework and exit criteria. A passing
repository test suite cannot supply operational trials, independent assessment or an
external decision. The PS-69 mapping uses the repository's reviewed
[requirement ledger](../requirements/README.md), not invented performance requirements.

## Work completed in this increment

Bounded adapter submissions, immutable queued requests, execution-time freshness checks,
real authenticated readiness, failed-authentication session clearing, bounded lab process
supervision and redacted startup diagnostics are implemented with adversarial tests.
The campaign adds nine executable families and preserves nineteen open gaps. Exact results
are published in the candidate report and PR; this document does not copy older passes.

The synthetic adapter's plaintext/key boundary is a confirmed limitation. The earlier
unexplained startup failure remains a separate open investigation. No real issuer,
classified interface, approved crypto module, hardware or HA topology is fabricated.

## Qualification exit sequence

| Gate                                     | Entry and implementation                                                                                                                    | Required exit evidence                                                                                                                                |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q0: requirements and design              | IAF names the sponsor, permitted data, operational roles/modes, endpoints, target topology, interfaces and acceptance thresholds            | Signed baseline, versioned requirement-to-design/test mapping, trust-boundary review, trial authorization                                             |
| Q1: complete engineering candidate       | Resolve P0 design/implementation gaps; integrate permitted identity, crypto and interfaces; freeze all software, firmware and configuration | Exact release inventory, independently repeatable installation, all required controls and maintenance/training documents                              |
| Q2: representative qualification tests   | Independent hosts and administration; real endpoint/crypto hardware; agreed capacity, WAN and outage envelope                               | Witnessed functional, adversarial, performance, recovery and usability results; failures retained and remediated                                      |
| Q3: operational prototype trials         | Authorized personnel and operating environment; agreed monitoring, support and incident procedures                                          | Operational-environment demonstration records, user/operations acceptance and defect disposition                                                      |
| Q4: complete-system qualification target | Final frozen configuration; independent findings closed under agreed criteria; required cryptographic decisions supplied                    | Evaluator's documented qualification decision with scope, version, conditions and change-control rules; operational authorization recorded separately |

These are proposed project gates, not official IAF forms or an automatic TRL ladder.
No fixed qualification date can be justified until sponsor inputs and trial availability
are agreed. Zero unauthorized content-key issuance is an invariant, not a negotiable load
metric. Other limits (latency, users, attachment size, RPO/RTO and soak duration) remain TBD
by the sponsor; a test with an unset acceptance threshold cannot close qualification.

## Executable adversarial coverage

Run commands and evidence format: [assurance/iaf/README.md](../../assurance/iaf/README.md).

| Family                                                      | Requirements    | Adverse case and required result                                                                                                                              |
| ----------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ADV-01: Identity, routing and credential denial             | R1, R5, R7      | No unauthorized session, route bypass or device-bound operation.                                                                                              |
| ADV-02: Revocation, races and separation of duties          | R1, R2, R7      | A revocation committed first produces zero new issuances; no self-approval or concealed metadata leak.                                                        |
| ADV-03: Object tampering and cryptographic downgrade        | R2, R5, R9      | Altered stored objects, unknown suites and unavailable providers cannot reach content-key release.                                                            |
| ADV-04: Custody loss and rollback recovery                  | R2, R6, R10     | Rollback/fork/outage blocks key-bearing operations; recovery retains the independent checkpoint boundary.                                                     |
| ADV-05: Adapter overload, startup and actual trust boundary | R2, R4, R8, R11 | Bound queued requests, preserve exact retry content, reject stale work and false readiness. Record plaintext endpoint exposure as an open deployment blocker. |
| ADV-06: Service identity and transport disruption           | R1, R2, R4, R6  | Wrong service certificates, redirects, oversized/interrupted responses and network revocation must fail closed.                                               |
| ADV-07: Endpoint persistence and offline updates            | R2, R5, R10     | Tampered vault/update, stale state and untrusted authority keys are refused; no silent downgrade.                                                             |
| ADV-08: Evidence transfer and audit integrity               | R2, R6, R12     | Invalid signatures, stale evidence, altered packages and self-awarded approval fail verification.                                                             |
| ADV-09: Monitoring delivery and redaction                   | R3, R6, R11     | Events retain authentication and deduplication; tested telemetry contains no payload/key canaries.                                                            |

The current test families use laboratory fixtures. Full browser, container, Rust/NEXORA,
formal and kernel network jobs remain separate CI evidence. The source-bound report must
include every family; any failed, skipped, cancelled or unexecuted test is a failed campaign.
A boundary-observation test can pass while its corresponding qualification gap remains open.

## Additional independent and representative adverse trials

These trials are planned; native campaign success does not claim their completion.
Run only in the sponsor-authorized environment with agreed containment and recovery.

| Trial | Failure injection / adversary                                                                    | Required observations and retained evidence                                                                           |
| ----- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| AT-01 | Stolen/revoked personnel credentials, cloned software device, issuer unavailable                 | Denied enrollment/session/release, attributable evidence, bounded recovery; selected hardware posture proof           |
| AT-02 | Clock offset/backward jump, expired certificates, stale issuer/revocation state                  | Defined fail-closed freshness behavior, current authorization, trusted time/PKI recovery                              |
| AT-03 | Token/HSM removal, provider failure, corrupt key wrap, forbidden suite                           | No fallback or plaintext release; exact module/error evidence and operator recovery                                   |
| AT-04 | Queue saturation, slow clients, connection floods, oversized/deep inputs, disk/memory exhaustion | Bounded resource use, explicit rejection, no unauthorized release, recovery and agreed useful-service availability    |
| AT-05 | Authority/custodian/relay/collector process or host loss, network partition, duplicate delivery  | Fenced writer, consistent policy and evidence, no duplicate issuance, measured RPO/RTO                                |
| AT-06 | Backup rollback, missing checkpoint, corrupt WAL/database/media, interrupted update              | No stale key release; independently retained evidence; recoverable installation/restore with all failures recorded    |
| AT-07 | Malicious document/file, unsafe viewer, cache/swap/log exposure, lost device                     | E2EE-compatible endpoint controls; canary scans across every declared untrusted store/process; defined residual risks |
| AT-08 | Insider role escalation, self-approval, malicious admin, service identity substitution           | Required separation of duties, authorization denial, tamper-evident alerts and independent review                     |
| AT-09 | Long-duration mixed workload, repeated credential rotation, outages and reconnects               | Percentiles, throughput, queue depth, CPU/RAM/disk and reconnection results against pre-agreed limits                 |
| AT-10 | Supply-chain/update/signing-key compromise and emergency rollback                                | Provenance, complete inventory, key revocation, failed-install containment and independently witnessed recovery       |
| AT-11 | Real integration malformed/replayed/ambiguous messages                                           | Exact contract conformance, endpoint trust-boundary protection, idempotency and current-policy release                |
| AT-12 | Human error, misleading state, accessibility failures and incident handover                      | Representative user task success, correct denial explanations, operations/training acceptance                         |

For each trial retain: requirement ID, authorization and operator, exact source/build and
hardware/firmware/configuration, workload and random seed, injected fault, expected result,
actual result and counters, evidence hashes, independent witness, defect ID, remediation,
retest and acceptance reference. Never overwrite failed-run artifacts or silently reduce
load to obtain a pass. An unresolved disqualifying finding blocks qualification according
to the agreed criteria. The assessor decides acceptable residual risk.

## Remaining implementation and external decisions

`assurance/iaf/plan.json` is the detailed machine-readable register. P0 means a proposed
qualification blocker; P1 is required before final acceptance unless the sponsor records
an explicit scoped disposition. Neither priority implies an official IAF severity rating.

| ID      | Priority / status            | Remaining work                                                                                                                                                                                                                          | Owner                                          | Exit evidence                                                                                                                       |
| ------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| IAF-G01 | P0 / EXTERNAL_INPUT_REQUIRED | **Requirements and permitted operating scope**. Freeze a signed requirements/configuration baseline and permitted Internet data boundary.                                                                                               | IAF programme/security owners                  | Approved scope and traceability covering every requirement; no TBD acceptance limit.                                                |
| IAF-G02 | P0 / EXTERNAL_INPUT_REQUIRED | **Personnel identity and federation**. Integrate the nominated issuer/PKI, joiner/mover/leaver workflows, recovery and issuer-outage policy.                                                                                            | IAF identity owner + SYNTRIASS                 | Witnessed issuer, revoked-user, stale-token, phishing/recovery and account-lifecycle trials.                                        |
| IAF-G03 | P0 / EXTERNAL_INPUT_REQUIRED | **Permitted cryptographic implementation**. Integrate the supplied module/SDK and exact suite/profile; complete the agreed independent review.                                                                                          | IAF sponsor + cryptographic evaluator          | Decision referencing exact module, firmware, configuration and conditions, with negative provider tests.                            |
| IAF-G04 | P0 / PARTIAL_LAB             | **Key custody, rotation and recovery**. Implement required HSM/token/attestation operations, device-loss response, rollover and authorized recovery.                                                                                    | SYNTRIASS + endpoint/crypto owner              | Extractability/removal/rotation/recovery/zeroisation results on selected hardware and agreed policy.                                |
| IAF-G05 | P0 / OPEN_DESIGN_BLOCKER     | **Plaintext boundary of synthetic document integration**. Agree endpoint placement. Move sealing/key ownership into the originating system if the connector must be untrusted; replace the synthetic schema with the supplied contract. | SYNTRIASS + IAF integration owner              | Canary and key scans of every declared untrusted process/store are negative; interface and trust-boundary review is accepted.       |
| IAF-G06 | P0 / IMPLEMENTATION_PENDING  | **High availability without split-brain release**. Design and implement single-writer fencing/failover and durable custody on independently administered hosts.                                                                         | SYNTRIASS + hosting owner                      | Witnessed leader loss, partition, restore and competing-writer trials with zero unauthorized/duplicate issuance and agreed RPO/RTO. |
| IAF-G07 | P0 / PARTIAL_LAB             | **Internet perimeter and resource exhaustion**. Configure permitted ingress, firewall, service isolation, request/connection budgets and load shedding.                                                                                 | SYNTRIASS + infrastructure/SOC owners          | Independent slow-client, connection flood, memory/disk exhaustion and lateral movement results on agreed topology.                  |
| IAF-G08 | P0 / PARTIAL_LAB             | **Backup, retention and disaster recovery**. Implement approved retention and deletion, encrypted backup custody, restore procedures and regular drills.                                                                                | SYNTRIASS + operations owner                   | Witnessed restore from damaged/missing media with retained checkpoints, measured RPO/RTO and no stale authorization.                |
| IAF-G09 | P0 / IMPLEMENTATION_PENDING  | **Long-running adapter authentication lifecycle**. Implement bounded supervised reauthentication with the agreed service identity and recovery policy.                                                                                  | SYNTRIASS + identity owner                     | Soak spans multiple credential expiries; failed renewal stays unavailable and revoked credentials never regain access.              |
| IAF-G10 | P1 / PARTIAL_LAB             | **Scale, latency and communication modes**. Agree modes and load envelope; implement missing modes and queue/backpressure/capacity controls; run sustained representative tests.                                                        | SYNTRIASS + IAF product owner                  | Latency percentiles, throughput, resource ceilings and long-duration recovery satisfy sponsor-agreed limits.                        |
| IAF-G11 | P1 / IMPLEMENTATION_PENDING  | **Content safety and endpoint data handling**. Implement required endpoint scanning, safe viewers, storage/session-lock and leakage controls consistent with the approved E2EE boundary.                                                | SYNTRIASS + endpoint/security owner            | Malicious-file, unsafe-viewer, disk-cache, clipboard/print and lost-device procedures are tested for the approved scope.            |
| IAF-G12 | P1 / PARTIAL_LAB             | **Operational monitoring and incident response**. Integrate agreed event schema/transport, alert escalation, monitoring availability and retention.                                                                                     | SYNTRIASS + SOC owner                          | Redaction and event completeness verified with SOC ingestion, outage replay and a witnessed response exercise.                      |
| IAF-G13 | P1 / EXTERNAL_INPUT_REQUIRED | **Managed fleet and device posture**. Integrate nominated MDM/attestation, OS/browser support, update policy and device-loss response.                                                                                                  | IAF endpoint owner + SYNTRIASS                 | Supported fleet matrix, disallowed posture, expired certificates and lost-device recovery tested on actual hardware.                |
| IAF-G14 | P1 / PARTIAL_LAB             | **Usability, accessibility and support material**. Complete role-based user/admin/training/maintenance manuals and task-based accessibility trials.                                                                                     | SYNTRIASS + IAF users/training owner           | Representative personnel complete enrollment, approvals, exchange, denial and recovery tasks against agreed criteria.               |
| IAF-G15 | P0 / PARTIAL_LAB             | **Final release and supplier assurance**. Freeze final hardware/runtime/modules, complete supplier inventory and protected signing/revocation/rollback ceremonies.                                                                      | SYNTRIASS release owner + evaluator            | Independent offline installation/update/rollback and full inventory verified against exact accepted configuration.                  |
| IAF-G16 | P0 / EXTERNAL_INPUT_REQUIRED | **Independent adversarial assessment**. Agree rules of engagement and test profile; execute independent penetration, protocol and cryptographic assessment; remediate and retest.                                                       | IAF nominated lab + independent assessor       | Signed findings and retests against exact candidate, with no unresolved disqualifying defect under agreed criteria.                 |
| IAF-G17 | P1 / EXTERNAL_INPUT_REQUIRED | **Filed-scope and lifecycle support reconciliation**. Reconcile implemented features and omissions with filed/contract deliverables; agree lifecycle support and training.                                                              | SYNTRIASS proposal owner + IAF programme owner | Accepted deliverable matrix, support/maintenance arrangements and licensing records.                                                |
| IAF-G18 | P0 / ROOT_CAUSE_OPEN         | **Historical adapter startup failure**. Retain diagnostics on recurrence; identify the original failure mechanism or establish an agreed closure rationale with soak evidence.                                                          | SYNTRIASS                                      | Reproduction and root-cause fix/retest, or assessor-accepted disposition; later green runs alone do not close it.                   |
| IAF-G19 | P0 / EXTERNAL_INPUT_REQUIRED | **Operational prototype trials and final qualification**. Execute authorized representative and operational-environment trials, close accepted exit criteria, and obtain final qualification decision.                                  | IAF evaluation authority                       | Documented complete-system qualification for exact configuration; TRL decision and operational authorization recorded separately.   |

## Immediate execution order

1. Confirm the originating endpoint/connector boundary and provide the issuer, cryptographic
   provider and integration contracts through controlled channels (G01–G05).
2. Implement service-identity renewal, aggregate resource protection, failover/retention and
   endpoint data-handling controls against that baseline (G06–G13).
3. Complete fleet/user validation, final release inventory and operating manuals (G14–G17).
4. Resolve the startup investigation with captured diagnostics and complete independent and
   operational trials before the external qualification decision (G18–G19).

Keep controlled documents, real personnel credentials and operational content outside the
public repository. Store only permitted references and hashes. The applicant campaign,
TRL assessment, cryptographic grading and deployment authorization are separate records.
