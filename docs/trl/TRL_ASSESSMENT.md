# SIEPMU provisional Technology Readiness self-assessment

**Date:** 8 October 2026. **Revision assessed:** `0e8d1b9` on `claude/siepmu-engineering-recovery-3nwgc8`.
**Assessor:** internal engineering self-assessment. This is **not** an independent Technology
Readiness Assessment, sponsor decision or SAG grading. Machine-readable source of truth:
[`cte-trl-matrix.json`](cte-trl-matrix.json) (guarded by `tests/trl-matrix.test.mjs`).

## Result

| Level            | Statement                                                                                                                      |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **System**       | **Provisional TRL 4**: integrated laboratory prototype, validated with automated and scripted evidence on a pinned revision.   |
| TRL 5 candidates | CTE-03 release, CTE-04 relay, CTE-05 offline queue, CTE-06 evidence custody. They need a sponsor-defined relevant environment. |
| Below the system | CTE-07 monitoring, CTE-08 existing-system integration and CTE-09 graded-provider agility are at TRL 3.                         |
| Not claimed      | TRL 5 or 6, IAF approval, SAG grading, independent assessment, operational deployment.                                         |

The earlier independent analysis also put the system at provisional TRL 4. This assessment reaches
the same level from re-executed evidence, not by copying it. Two things have changed since then:

- More elements now have scripted, multi-process evidence.
- Integration work on this branch keeps finding real defects. Examples are the PQC key-wrap failure
  (ADR-010), fixed earlier, and the telemetry stall after an authority change, fixed in `0e8d1b9`.

Finding defects at this rate is consistent with TRL 4, not 5.

## Why TRL 4 and not TRL 5

TRL 5 requires validation **in a relevant environment**: realistic interfaces, data, network
conditions and acceptance criteria agreed with the sponsor. None of these is defined:

- PS-69 does not specify the classification boundary, user count, latency, offline duration,
  permitted hosting or the interfaces to existing systems.
- Every test so far runs on a single machine or a single CI runner. The TRL 5 advancement
  campaign (below) separates the hosts at the network level only.
- The 10-zone netem testbed is a laboratory simulation of network impairment. It is not a relevant
  environment the sponsor has agreed to.
- The integration contract is synthetic.

So the highest defensible level for any element is 4. A claim of TRL 5 would need the gate below
to be passed.

### TRL 5 advancement campaign (8 October 2026)

- **What ran.** A 33-test matrix, declared before execution (`docs/trl5/ACCEPTANCE_MATRIX.md`),
  passed on revision `1348b86`. The environment was three network-namespace hosts (sender,
  platform, recipient) on one kernel. The hosted CI run of the same revision added kernel-netem
  packet loss and passed 35/35.
- **Decision.** `docs/trl5/READINESS_DECISION.md` retains **TRL 4**:
  - the hosts share one kernel;
  - the environment is applicant-defined;
  - there was no witness;
  - the campaign found an open custody scaling defect (D-T5-01, `docs/trl5/PERFORMANCE_REPORT.md`).
- **Effect on the matrix.** Evidence custody is no longer listed as a TRL 5 candidate until
  D-T5-01 is fixed.

## Elements

| ID     | Element                        | TRL | Strongest evidence (rev `0e8d1b9` unless stated)                                                       | Main limitation                                       |
| ------ | ------------------------------ | --: | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| CTE-01 | Endpoint encryption            |   4 | Native and browser interop; plaintext canaries absent from relay and authority stores                  | Classical suite not SAG graded; software keys         |
| CTE-02 | Identity and device security   |   4 | Wrong or replayed OTP refused; revoked device refused at its next request (Demo 4)                     | No hardware attestation; no IAF PKI                   |
| CTE-03 | Authorization and release      |   4 | Both commit orders tested; Trust Before Release 14/14; identical issuance after restart; testbed 75/75 | Single authority host; no recall after issuance       |
| CTE-04 | Ciphertext relay               |   4 | Relay outage leaves no half-written object; recovers on restart (Demo 4)                               | No replication; gateway readiness ignores relay       |
| CTE-05 | Offline queue and reconnection |   4 | Revocation during an outage holds the affected object; an eligible object is released                  | Fault proxy and netem, not WAN or radio               |
| CTE-06 | Evidence and audit custody     |   4 | Node and Rust verifiers agree on vectors and mutations; tampering rejected in Demos 3 and 4            | Custodian on the same host                            |
| CTE-07 | Threat monitoring              |   3 | Rule alerts reach the independent collector; operator acknowledges (Demo 4)                            | No analytics or SIEM; telemetry defect fixed only now |
| CTE-08 | Existing-system integration    |   3 | Synthetic document system through the adapter, 10/10 (Demo 3)                                          | No real interface specification                       |
| CTE-09 | Crypto-provider agility        |   3 | Provider port, policy gate, downgrade rejection; NIST and X-Wing vectors                               | No graded or Indian provider integrated               |
| CTE-10 | Secure sovereign deployment    |   4 | Hardened container job, mTLS stack, signed offline release, 10-zone testbed                            | Lab PKI; no approved hosting                          |

## Status axes (kept separate)

| Axis                            | State                                                                        |
| ------------------------------- | ---------------------------------------------------------------------------- |
| Engineering implementation      | Done for 7 elements; partial or synthetic-only for 3                         |
| Local laboratory testing        | `npm run validate` PASS 249/249 tests, 97.5 % lines; e2e 3/3; Demos 2–4 PASS |
| Hosted CI validation            | See `docs/engineering/CURRENT_STATE.md` for run IDs on the exact revision    |
| Relevant-environment validation | Not started: the environment is not defined                                  |
| Independent assessment          | Not engaged                                                                  |
| Sponsor acceptance              | Not engaged                                                                  |
| Operational qualification       | Not engaged                                                                  |

## Gate to claim TRL 5 for an element

1. The sponsor agrees a relevant-environment definition: network profiles, outage durations,
   identity and interface sources, scale, classification boundary and acceptance thresholds.
2. A multi-host deployment on operator-controlled hardware passes the agreed test matrix,
   with the results recorded on a pinned revision.
3. An independent party witnesses or reviews the evidence.
4. Deviations and failures are recorded and dispositioned, not removed.

Planning detail for TRL 5 and 6: `research/trl56/07-trl5-validation-master-plan.md`,
`research/trl56/10-trl6-demonstration-and-test-plan.md` and `docs/hpsc/FUNDING_PLAN.md`.
