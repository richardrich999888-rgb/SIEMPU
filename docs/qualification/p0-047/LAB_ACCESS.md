# D8: Indian laboratory access request package

Prepared for founder review, 12 November 2026 IST. **Unsent.** No application, contact,
terms acceptance, sponsorship or expenditure is authorised by this document.
Attach the frozen source/evaluation manifest and common technical annex below. Insert
the final PR/source revision from the accompanying release record before submission.
Company statutory documents and institutional forms remain founder-provided inputs.

## 1. C-DOT — Collaborative Research Cell / India 5G Alliance

**Subject: Request for supervised non-classified network validation of AIRON–SIEPMU**

Dear Sir/Madam,

I am Naga Sri Ganesh, Founder and CEO of SYNTRIASS Labs Pvt. Ltd. We are developing
AIRON–SIEPMU for iDEX DISC-14, PS-69, concerning secure information exchange between
military units over public networks. Our current assessment remains provisional TRL 4.
SAG grading, TRL 5 qualification and IAF operational approval are not established.

We request a technical scoping discussion with C-DOT's Collaborative Research Cell and
the appropriate 5G Applications, Enterprise Network or Security consortium regarding
supervised laboratory access. We wish to evaluate our existing application on distinct
computing hosts using synthetic identities and documents, including encrypted exchange,
current-policy key-release denial after revocation, controlled connectivity outages,
writer fencing and integrity checks before recovery activation.

The attached annex proposes six modest Linux hosts/VMs, isolated experiment networking,
separate custody storage and five working days of access. A cellular transport path is
optional and would use only C-DOT's authorised configuration under its supervision.
We will not scan other systems, stress shared tenants or introduce classified information.

Please advise the relevant facility, application process, permissible experiments,
technical supervision, confidentiality/publication arrangements and applicable charges.
As an early-stage startup, we request consideration for research sponsorship or a fee
waiver, subject to your criteria. Any terms and costs would be separately reviewed by us.

Our intended output is a reproducible source-bound evaluation record with signed evidence,
raw measurements, failures and limitations, available for independent verification. We
would welcome nomination of a technical contact to review the scope.

Yours faithfully,
Naga Sri Ganesh
Founder and CEO, SYNTRIASS Labs Pvt. Ltd.

Routing: official [India 5G Alliance interest form](https://www.cdot.in/cdotweb/web/join5g.php).
No unverified email address is supplied.

## 2. DoT 5G Use Case Lab — IIT Tirupati

**To:** ee_office@iittp.ac.in  
**Suggested lab routing:** vijayaakarapu@iittp.ac.in  
**Subject: Request for startup access to the DoT 5G Use Case Lab for supervised validation**

Dear Sir/Madam,

I am Naga Sri Ganesh, Founder and CEO of SYNTRIASS Labs Pvt. Ltd. We request an opportunity
to discuss external-startup access to IIT Tirupati's DoT 5G Use Case Lab for a controlled,
non-classified evaluation of AIRON–SIEPMU, our secure information-exchange prototype
being developed for iDEX DISC-14 PS-69.

The prototype is provisionally TRL 4. We seek evidence from a relevant network environment;
we are not requesting an assumption of military acceptance or certification. The attached
annex specifies actual software services on separate hosts, synthetic endpoint identities,
encrypted messages/files, revocation before key release, bounded network interruptions,
recovery-integrity checks and independently verifiable evidence.

Could the department route this proposal to the responsible faculty and lab operator and
advise whether the lab can provide isolated compute/network access, a supervised data-plane
path and an independent custodian/verifier role? We propose five working days and request
the applicable external-use procedure, resource limits, supervision, charges and any startup
sponsorship or fee-waiver opportunity. All experiments would follow the laboratory's written
scope and licensed radio configuration.

We would provide frozen source, reproducible instructions and raw results, retaining all
failures and documenting the limits of the test environment. We can share the technical
package for a preliminary review or discuss it over Google Meet at your convenience.

Yours faithfully,
Naga Sri Ganesh
Founder and CEO, SYNTRIASS Labs Pvt. Ltd.

## 3. TCoE India — eligibility and future pilot scoping

**To:** pilot@tcoe.in  
**General programme routing:** info@tcoe.in  
**Subject: Pre-application guidance for AIRON–SIEPMU telecom-network validation**

Dear Sir/Madam,

I am Naga Sri Ganesh, Founder and CEO of SYNTRIASS Labs Pvt. Ltd. We are developing
AIRON–SIEPMU for iDEX DISC-14 PS-69 and are preparing supervised validation of secure
application traffic over authorised public/private telecom networks.

We understand that the TDIP pilot-validation programme specifies TRL 5–8 and requires an
eligible recognised entity and identified industry/TSP partner consent. Our current
assessment remains provisional TRL 4. This is therefore a request for technical and
eligibility guidance, not an application claiming that the present prototype meets the gate.

Please advise whether a DoT 5G Use Case Lab or appropriate partner can support the earlier
relevant-environment evaluation described in the attached annex, and what evidence would
be required for a subsequent eligible pilot proposal. We also request confirmation of the
current recognition/ownership documentation, partner letter, cost-sharing requirements,
permitted expenses, application window and any separate support suited to our present stage.

We propose only non-classified synthetic traffic, isolated allocated hosts and supervised
fault injection. Our intended deliverable is independently reproducible evidence of
encrypted exchange, policy revocation, failure behaviour and recovery integrity, with
explicitly recorded failures and remaining qualification gaps.

We would appreciate referral to the appropriate technical or programme contact. No funding
award, host access or maturity advancement is assumed.

Yours faithfully,
Naga Sri Ganesh
Founder and CEO, SYNTRIASS Labs Pvt. Ltd.

## 4. IIT Hyderabad — Indigenous 5G Testbed

**To:** 5gtbadmin@5g.iith.ac.in  
**Subject: Request to scope non-classified AIRON–SIEPMU application testing on the 5G testbed**

Dear Sir/Madam,

I am Naga Sri Ganesh, Founder and CEO of SYNTRIASS Labs Pvt. Ltd. We request guidance on
access to IIT Hyderabad's Indigenous 5G Testbed for supervised evaluation of our
AIRON–SIEPMU secure information-exchange prototype, developed for iDEX DISC-14 PS-69.

Our current assessment is provisional TRL 4. We wish to determine whether our existing
application can retain its security properties on distinct hosts communicating through
an authorised lab network. The attached annex specifies synthetic encrypted messages/files,
revocation before a fresh key release, controlled data-plane outages, reviewed writer
handover and unsafe-recovery rejection. It does not propose RAN attacks or interference.

Please advise whether application-layer end-to-end testing, isolated compute/storage,
independent custody and a separately operated verifier are supported, and whether the
online testbed registration route is appropriate. We request the current resource
configurations, availability, supervision, permitted tests and tariffs. We would welcome
consideration for startup research sponsorship or a fee waiver; the historical free-use
announcement is not assumed to apply today.

We propose five working days, subject to your review, and will provide frozen source,
instructions and a reproducible evidence package. We would be pleased to discuss the
scope with the testbed manager over Google Meet.

Yours faithfully,
Naga Sri Ganesh
Founder and CEO, SYNTRIASS Labs Pvt. Ltd.

## Common technical annex

| Requirement      | Proposed request                                                                                                                                                                                   |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Purpose          | Validate application security under relevant authorised network conditions; no certification request implied                                                                                       |
| Compute          | Six Linux VMs/hosts with distinct kernels and storage; initially 2 vCPU, 4 GiB RAM, 10 GiB private disk each; no GPU                                                                               |
| Topology         | A sender, B authority/web, C ciphertext relay, D independently operated custodian/collector, E recipient, F quarantined standby                                                                    |
| Runtime          | Node 24.x in repository engine range, OpenSSL; pinned dependency lockfile; Python 3 for inventory/emulation; privileged operations only by lab operator                                            |
| Network          | Private experiment VLAN/routed network; TLS 1.3 and internal pinned mTLS; optional authorised 5G UE data path; separate unaffected SSH management                                                  |
| Timing           | NTP/PTP observations and measured host offset; 100 ms initial maximum offset as applicant criterion                                                                                                |
| Initial workload | Text plus 4 KiB and 256 KiB files; 3 × 10-message short benchmark; no unbounded stress load                                                                                                        |
| Fault scope      | Allocated-node link loss/delay/jitter, process termination, controlled authority partition, corrupt synthetic snapshot copies; written approval before each additional host/clock/disk/RF fault    |
| Hardware option  | Physical PKCS11 device with documented serial/firmware only if supplied/approved; software HSM results recorded separately                                                                         |
| Duration         | Day 1 inventory and baseline; days 2–3 approved network/security trials; day 4 independent verification; day 5 remediation/retest/teardown                                                         |
| Supervision      | Lab network administrator plus independent custody/evidence operator; founder technical lead; approve rules of engagement and stop conditions before activation                                    |
| Data safeguards  | Synthetic identities/documents only; no military networks, real personnel data or production credentials; private keys remain with role custodians                                                 |
| Outputs          | Exact source/lock hashes, host inventory, topology, immutable protocol, raw timings/errors, signed application evidence, public verification keys/checkpoints, checksums and assessor observations |
| Capture          | Bounded experiment-only packet headers after permission; exclude management/authentication traffic, secrets and TLS key logs; review metadata before release                                       |
| Costs            | Request existing allocation/sponsorship/waiver; obtain quotation and founder decision before any charge or cost-sharing agreement                                                                  |
| Acceptance       | Zero unauthorised releases/integrity mismatches; unsafe recovery and stale writer refused; deviations retained; sponsor/lab determines relevant-environment sufficiency                            |

Attachments to assemble before submission: founder contact details; incorporation and
DPIIT/Udyam evidence where required; exact source manifest; architecture; experiment
matrix; data/retention plan; authorised personnel; host/network allocation scope; proposed
independent verifier; partner consent for TCoE; fee decision. These inputs are not fabricated.
