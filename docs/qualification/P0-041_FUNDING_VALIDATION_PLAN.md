# AIRON SIEPMU Development funding and validation plan

SYNTRIASS Labs Pvt. Ltd. | Applicant proposal | 9 November 2026

The current software iteration uses existing infrastructure with no authorised new spending.
The following six-month programme is a planning estimate for qualification engineering and
supervised validation, conditional on scope, staffing, laboratory access and funding approval.
It does not purchase SAG grading or promise TRL advancement. Every priced line is a management
estimate, not a supplier quotation or approved budget. Currency is INR; one lakh is INR 100,000.

## Resource model

| Cost item                                                       | Basis                                                                         |    INR lakh | Classification                               |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------: | -------------------------------------------- |
| Backend and distributed-systems engineers                       | 2 people × 6 months × 1.50 lakh/month                                         |       18.00 | Management estimate                          |
| Cryptographic/security engineer                                 | 1 × 6 × 1.75                                                                  |       10.50 | Management estimate                          |
| Adversarial QA engineer                                         | 1 × 6 × 0.90                                                                  |        5.40 | Management estimate                          |
| Reliability and testbed engineer                                | 0.5 × 6 × 1.20                                                                |        3.60 | Management estimate                          |
| Evaluation documentation and coordination                       | 0.25 × 6 × 1.00                                                               |        1.50 | Management estimate                          |
| Representative testbed provision                                | Existing-host reuse preferred; limited equipment allowance if approved        |        2.00 | Management estimate                          |
| Hardware security evaluation equipment                          | Provisional token/HSM/attestation allowance; exact permitted hardware unknown |        3.00 | Management estimate                          |
| Independent technical assessment                                | Scoped external review and witnessed tests                                    |        4.00 | Management estimate                          |
| Operational integration and site work                           | Approved interface workshops, travel and controlled setup                     |        1.50 | Management estimate                          |
| Reliability retesting                                           | Additional fault, soak and recovery campaign capacity                         |        2.00 | Management estimate                          |
| Subtotal                                                        | Personnel 39.00; other estimates 12.50                                        |       51.50 | Calculated from management estimates         |
| Contingency                                                     | 15% of known subtotal                                                         |       7.725 | Management estimate                          |
| Planning total before unknown charges                           | 51.50 + 7.725                                                                 |  **59.225** | Management estimate; not a fixed-price offer |
| Authorised cryptographic SDK/module licence                     | Supplier and permitted interface not nominated                                | **Unknown** | No quotation                                 |
| SAG/laboratory evaluation charges                               | Scope and waiver applicability not confirmed                                  | **Unknown** | No quotation                                 |
| Applicable taxes, bank-guarantee/collateral and financing costs | Contract, tax treatment and disbursement route unresolved                     | **Unknown** | Not silently included as zero                |

The staffing model is 4.75 full-time equivalents for six months. Crypto-provider integration,
authority/recovery changes and operational software integration use the personnel allowance;
they are not charged again as separate engineering lines. Hardware allowance does not establish
that an approved HSM is available at that price. Obtain quotations and revise the budget before
commitment. In-kind host/lab access can reduce cash needs only when documented. Existing contributor
time and infrastructure are not economically costless, although this iteration makes no purchase.

## Milestones and release of work

| Milestone                                    | Target window after authorised start      | Deliverable and evidence gate                                                                                            | Planned share of 51.50 lakh subtotal |
| -------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -----------------------------------: |
| M0 Scope and baseline                        | Weeks 1–2                                 | Sponsor/evaluator decisions, exact requirements, IP/dependency baseline, existing candidate verified                     |                           5% = 2.575 |
| M1 Authority and recovery                    | Weeks 2–6                                 | Reviewed fencing/seals/migration, reconciliation and all-store recovery design; negative regressions and measured limits |                          20% = 10.30 |
| M2 Representative environment                | Weeks 5–10                                | Nominated hosts/administrators, isolation, key ceremony, network profiles and reproducible observer campaign             |                          15% = 7.725 |
| M3 Crypto and endpoint integration           | Weeks 8–16, after authorised SDK/hardware | Provider failure/removal, lifecycle, certificate and identity integration tests on nominated modules                     |                         25% = 12.875 |
| M4 Independent reliability/security campaign | Weeks 15–22                               | Sustained/soak/fault tests, measured RPO/RTO, independent findings and retests under agreed criteria                     |                         25% = 12.875 |
| M5 Evaluation submission candidate           | Weeks 22–26                               | Frozen source/binaries, complete applicant dossier, observer reproduction and disposition of all gaps                    |                           10% = 5.15 |

These allocations are internal planning, not a government disbursement schedule. Contingency is
held separately and released against documented changes. An unavailable module or testbed stops
its dependent milestone; independent engineering continues. M5 means submission material is
ready within the agreed scope, not that SAG has graded the product or an assessor has awarded TRL 5.

## Potential funded pathways

**Make-I.** Published DAP 2020 allows government support up to 70% of prototype development cost,
capped at INR 250 crore per development agency; actual terms are case-specific. Eligible Indian
vendors must meet resident-Indian ownership/control and the applicable technical/financial
criteria. Service identification, AoN, selection/EOI, prototype approval and a contract are
dependencies; an unsolicited proposal is not a sanction. At the maximum share, at least 30%
plus ineligible costs/working capital must be arranged. Make-I normally retains contractor IP
ownership with government-purpose rights; sensitive/classified technology may carry separately
negotiated restrictions. Legal review of the exact EOI/contract and background IP is required. [1,2]

**TDF.** The official scheme portal describes projects up to INR 50 crore and funding up to 90%,
linked to agreed milestones; advances require an equivalent bank guarantee or payment follows
milestone reimbursement. Eligibility includes Indian registration and ownership/control; startup
conditions include DPIIT recognition, at least 51% resident-Indian ownership, no similar-technology
government grant and, for the nascent category, qualifying incubation. Verify the exact invitation
and applicant category with DRDO; these conditions are not certified for SYNTRIASS here. The
published SOP describes jointly owned foreground IP with DRDO. Obtain the applicable current
agreement and identify background software/patents, third-party rights and commercial-use terms
before selecting this route. At maximum support, at least 10% and other uncovered costs remain. [3,4]

For illustration only, if the entire estimated 59.225 lakh were accepted as eligible, maximum-share
Make-I support would be 41.4575 lakh with applicant share 17.7675 lakh; TDF would be 53.3025 lakh
with applicant share 5.9225 lakh. Eligibility of contingency, equipment, salaries and retesting is
unconfirmed. A grant percentage does not remove cash-flow, guarantee or collateral requirements.
No matching funds, grant sanction or investor commitment is established in this proposal.

The reviewed official materials continue to describe DAP 2026 as a draft. This proposal therefore
uses published DAP 2020 terms as a reference and asks the competent authority to confirm the
procedure applicable to a new case; it does not treat draft proposals as effective entitlements. [5]

The MoD's 7 October 2026 announcement describes proof/testing-charge waivers for qualifying iDEX,
TDF, Make and other MoD development projects. Seek written confirmation that this project, facility
and SAG activity qualify. The unknown fee line remains unknown until that confirmation. [6]

## Ownership, approvals and next decisions

SYNTRIASS owns staffing/budget approval and must supply current incorporation, shareholding/control,
DPIIT/Udyam and financial documents as applicable. The IAF sponsor owns operating scope, technical
contact and service-sponsored assessment request. SAG/laboratory owns methods, module scope, access
and fee decision. The funding authority owns eligibility, selection and sanctioned terms. Register
background IP, public Apache-2.0 repository contributions and every third-party licence; no claim
of exclusive ownership of standard primitives or public dependencies is made. No application,
funding commitment, laboratory booking or external communication has been made by this engineering
work. Next action: technical scoping with the nominated sponsor, then obtain quotations and complete
the route-specific eligibility/IP review before submitting a costed application.

## Primary references checked 9 November 2026

1. [DAP 2020, Chapter I para 20; Chapter III paras 5–6, Appendix F and Appendix J](https://www.ddpmod.gov.in/sites/default/files/2024-02/dap-2020-11-nov-21_0_0.pdf).
2. [MoD Make-I summary, 24 March 2025](https://www.pib.gov.in/PressNoteDetails.aspx?ModuleId=3&NoteId=154019&lang=1&reg=1).
3. [Government myScheme TDF entry](https://www.myscheme.gov.in/schemes/tdfs). Indexed official content was available; direct retrieval returned a page shell.
4. [Official TDF SOP, eligibility and joint IP statement](https://tdf.drdo.gov.in/sites/default/files/2021-06/SOP%2B%20Appendix_v2.4_Final.pdf). Indexed text was available; direct PDF retrieval timed out. Obtain the current complete agreement before an IP decision.
5. [MoD draft DAP 2026 consultation](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2227775&lang=1&reg=3).
6. [MoD testing-charge waiver announcement](https://www.pib.gov.in/PressReleseDetailm.aspx?PRID=2320195&lang=1&reg=3).
