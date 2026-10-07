# DISC-14 PS-69: submitted application vs. current source

**Evidence category:** Application declarations vs. frozen code inspection. This is a gap ledger, not a certification statement.

- Submitted document: _Annexure 1 — Proposed Solution_, 2 pages.
- Submitted document: _Annexure 2 — Proposed Technical Solution (Detailed)_, 5 pages.
- Submitted document: _Annexure 3 — Applicant Resume & Relevant Technical Evidence_, 4 pages.
- Applicant: Katta Naga Sri Ganesh; Annexure 1 identifies SYNTRIASS Labs Private Limited as the startup.
- Filed duration: 12 months.
- Repository base: `65a6891a41b57fe9480d1e1df901a1287c66753d`.
- Original PDF copies are held **outside this public repo**. No unverified IAF operational materials, company secrets or original signed annexures are committed.

## Six filed components

| Filed item                                            | Current code equivalent                                 | Status / precise gap                                                                                                                           |
| ----------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| PQ-SIE: SAG inner envelope + ML-KEM-768 and ML-DSA-65 | `packages/crypto/crypto.mjs`                            | Classical P-256/AES-256-GCM demonstrator. NO SAG grading, PQC suite or approved dual-layer provider. Sponsor-approved algorithm path required. |
| ChronoLattice hash-chained audit                      | `services/control/core.mjs`, `apps/verifier/verify.mjs` | Signed events/checkpoints and detached verification implemented; not independently hosted/certified distributed causal ledger.                 |
| ZT-Sync-Server                                        | `services/control`, `services/relay`, `services/web`    | HTTP-based encrypted queue/release, NOT filed WSS/JWT/TLS 1.3 deployment or horizontally-scaled service.                                       |
| MFA-Gate                                              | `services/control/primitives.mjs`                       | RFC 6238 TOTP and authenticator proof tested; no hardware attestation or IAF federation.                                                       |
| Stealth-Dashboard                                     | `apps/unit-client`, `apps/admin-console`                | Browser UI exists, NOT React 18/Vite/TypeScript filed stack. Product demonstration uses a deliberate low-dependency substitute.                |
| Anomaly-Sentinel                                      | `services/control` logs/alerts/counters                 | Basic event alerts and rate controls; no validated behavioural model, anomaly score calibration or external SOC integration.                   |

## Specific filed capabilities and gaps

| Requirement from filed Annexures 1–2                                                                               | State on base commit                          | Planned engineering evidence                                                                                     |
| ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Six duty roles: UNIT_COMMANDER, SIGNALS_OFFICER, INTELLIGENCE_ANALYST, FIELD_OPERATOR, AUDIT_OFFICER, SYSTEM_ADMIN | Four generic roles                            | This branch introduces **additive duty-policy library**; schema-bound enforcement and UI to be tested separately |
| Four message priorities: FLASH, IMMEDIATE, PRIORITY, ROUTINE                                                       | No signed message-priority field              | Versioned signed-context upgrade and policy release checks needed                                                |
| Separate INTEL transmission domain                                                                                 | Unit/mission policy only                      | Add bounded domain label, never treat labels as classified data                                                  |
| Dual SAG/PQC message protection                                                                                    | Unapproved classical E2EE only                | Interoperable provider boundary, authorised guidance, audited suites and independent lab                         |
| Air-gap package/PSK distribution                                                                                   | Local synthetic offline bootstrap             | Sponsor-approved safe custody, provenance and distribution process; do not treat USB copies as certification     |
| Six original source paths and React/WSS stack                                                                      | Names/path mismatch                           | Explicit divergence, no claim of preserved original implementations                                              |
| LDAP/PKI and IAF C2 adapters                                                                                       | Synthetic schema validation only              | Independent synthetic emulator first; actual interfaces **IAF-SPONSOR-REQUIRED**                                 |
| Real-time threat monitoring                                                                                        | Redacted logs/alerts only                     | Rules, replay/DDoS simulations, triage response and independently witnessed tests                                |
| Field trials/certification and multi-station rollout                                                               | No authorised IAF infrastructure access       | External sponsor schedule, approved relevant environment and signed acceptance                                   |
| SDLC evidence/source handover                                                                                      | Threat model, tests, release artifact present | IP/legal review and exact package inventory; licence terms require owner decision                                |

## Non-negotiable trust and claim constraints

No claim of SAG grading, classified network compatibility, IAF field trials, novelty/non-repudiation or production readiness without exact external evidence. Filing terms `SAG-1.0` and `compliant with SAG/DRDO policy` are **applicant wording**, not verified approval. Standard NIST primitives or third-party cryptographic implementations do not alone meet SAG grading. The 12-month roadmap in Annexure 1 relies on sponsor-provided test facilities and cannot be represented as an already-approved schedule. Preserve the established transactional epoch/release invariant and bound all additional metadata into signed encrypted context.
