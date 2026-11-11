# D7: relevant-environment and TRL 5 readiness assessment

**Assessment: provisional internal TRL 4 unchanged. P0-047 incomplete.**
SAG grading, TRL 5 qualification and IAF operational approval are not established.

A relevant PS-69 environment must include the approved information boundary, real
endpoint identity/device lifecycle, distinct authority/relay/custody hosts, representative
latency/loss/outage and perimeter conditions, controlled standby handover, supported
hardware, independently retained evidence and sponsor-agreed acceptance criteria.
The proposed profiles exercise only subsets. A laboratory 5G connection alone does
not make the entire application environment representative.

| Critical element                  | Applicant evidence available for reproduction                                      | Readiness limit                                                                             |
| --------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Endpoint encryption and integrity | Real SDK/crypto, signed receipts and hash checks                                   | Full managed companion, physical token and nominated crypto implementation unqualified      |
| Current policy and revocation     | Actual authority checks with queued/delayed ciphertext and fresh denial            | Sponsor personnel PKI, roles and mission lifecycle still external                           |
| Offline continuity                | Real encrypted ManagedOutbox across process restart                                | Host-loss, power-loss, long outage, queue rollback and fleet recovery not established       |
| Recovery integrity                | Reconciled guarded recovery plus bounded control/relay snapshot checks             | Independent-host multi-store ceremony and full-site DR not demonstrated                     |
| Writer fencing                    | Existing generation/CAS/lease tests and synthetic handover                         | No automatic HA, replicated custodian or anti-cloning hardware claim                        |
| Evidence                          | Source manifest, signed application event verification, existing portable verifier | Independent custody/administration and NET-12 reproduction absent                           |
| Network tolerance                 | Adapter code and local actual-service run where reported                           | Namespace execution, independent kernels, external routes and endurance require allocations |
| Performance                       | Short predeclared repeated workload, raw samples                                   | No representative SLA, confidence-bounded tails, comparative advantage or production RTO    |

## Nineteen-gap disposition

All original gap IDs and statuses remain. This table supplements, not replaces,
`assurance/iaf/plan.json` and `docs/qualification/P0-041_GAPS.md`.

| Gap     | Disposition after P0-047 work | Exact next evidence                                                         |
| ------- | ----------------------------- | --------------------------------------------------------------------------- |
| IAF-G01 | EXTERNAL_INPUT_REQUIRED       | Sponsor-signed relevant-environment and information boundary                |
| IAF-G02 | EXTERNAL_INPUT_REQUIRED       | Nominated personnel/PKI lifecycle and outage tests                          |
| IAF-G03 | EXTERNAL_INPUT_REQUIRED       | Approved crypto module/profile and evaluator acceptance                     |
| IAF-G04 | PARTIAL_LAB                   | Physical token/HSM rollover, removal, loss and recovery                     |
| IAF-G05 | PARTIAL_LAB                   | Managed endpoint and sealed integration on representative hosts             |
| IAF-G06 | PARTIAL_LAB                   | NET-07 on independent B/D/F with reviewed custody handover                  |
| IAF-G07 | PARTIAL_LAB                   | Allocated perimeter, ingress budgets and real exhaustion observations       |
| IAF-G08 | PARTIAL_LAB                   | All-store external recovery, retention and independent latest custody       |
| IAF-G09 | PARTIAL_LAB                   | Long-duration supervised reauthentication and credential lifecycle          |
| IAF-G10 | PARTIAL_LAB                   | Representative offered load, 60-minute protocol then agreed endurance       |
| IAF-G11 | PARTIAL_LAB                   | Native scanner/sandbox/token profile and representative corpus              |
| IAF-G12 | PARTIAL_LAB                   | Independent monitoring, exporter/cursor continuity and operational response |
| IAF-G13 | EXTERNAL_INPUT_REQUIRED       | Nominated managed device posture, attestation and update policy             |
| IAF-G14 | PARTIAL_LAB                   | User/admin task and accessibility trials                                    |
| IAF-G15 | PARTIAL_LAB                   | Final supplier/runtime/hardware inventory and signing ceremonies            |
| IAF-G16 | EXTERNAL_INPUT_REQUIRED       | Independent permitted adversarial evaluation and retest                     |
| IAF-G17 | EXTERNAL_INPUT_REQUIRED       | Filed scope/operational support reconciliation by sponsor                   |
| IAF-G18 | ROOT_CAUSE_OPEN               | Accepted historical adapter-failure closure rationale and soak evidence     |
| IAF-G19 | EXTERNAL_INPUT_REQUIRED       | Sponsor-directed representative trial and qualification decision            |

No closure is inferred from a passing local suite, a hosted workflow or a prepared
proposal. TCoE's TRL 5–8 gate remains unmet on this assessment. The immediate external
dependency is a documented allocated host/network set and an independent operator;
CORE/Mininet additionally need privileged namespace access. All external requests remain
unsent pending the founder's explicit instruction.
