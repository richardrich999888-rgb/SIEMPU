# AIRON–SIEPMU Defence Research | 2026-10-08

STATUS: engineering proposal / evidence-based roadmap. Does not establish IAF/SAG approval, TRL progression, vendor quotation or classified access. Baseline f6d75cf6b105319ca0d6942b2bbc196750a0b230.

## Decisions requiring programme authority
| ID | Critical question | Owner | Evidence effect |
|---|---|---|---|
| IAF-01 | Which sensitivity/classification/release policies may SIEPMU exchange on public Internet? | IAF security sponsor | authorised content and test scope |
| IAF-02 | Approved users, roles, units, OS/endpoints and trust anchors? | IAF identity owner | RBAC, MFA, fleet deployment |
| IAF-03 | Required real-time modes, service level, latency, concurrent user and attachment sizes? | IAF product owner | performance exit thresholds |
| IAF-04 | Offline semantics and maximum isolation/revocation window? | data owner | key-release policy |
| IAF-05 | SAG algorithm grade criteria, authority, device/SDK/provisioning pathway? | sponsor/authorised SAG channel | crypto approval cannot be self-declared |
| IAF-06 | Which approved military interface, schema and connector boundary? | IAF system integrator | replace synthetic mock |
| IAF-07 | Which security lab, trials, QA and test record formats are mandated? | programme V&V | formal acceptance |
| IAF-08 | Which on-prem/sovereign/cloud and remote administration models allowed? | hosting/security authority | TRL6 topology |
| IAF-09 | Mandatory monitoring without E2EE content access; metadata/privacy policy? | cyber operations authority | SIEM integration |
| IAF-10 | Device attestation/key rotation/escrow/recovery/zeroization rules? | crypto & endpoint authority | hardware design |
| IAF-11 | What is official agreement budget, milestones, acceptance schedule and hardware procurement ceiling? | iDEX/SPARK contract owner | cost/schedule |
| IAF-12 | Which NDA/IP/public-repo restrictions apply? | SYNTRIASS counsel + sponsor | safe release and disclosure |
| IAF-13 | Which representative environments and CTE-specific TRL criteria will the sponsor accept? | IAF V&V authority | readiness determination |

Each response must contain decision_date, authority, signed/reference document, version, decision status, affected code/test, approval limitations and evidence reviewer. Until then status UNKNOWN / IAF-SPONSOR-REQUIRED.
