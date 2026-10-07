# Original DISC-14 application — code delivery tracker

This tracker maps the exact named seven deliverables of Annexure 1 and six components of Annexure 2. Treat named modules as **filed architecture**, not proof of completion.

| Filed deliverable | Implementation workstream | Owner | Exit evidence | State at baseline |
|---|---|---|---|---|
| 1. SIEPMU Core Platform (six components) | integrated versioned service/client, dual crypto, auth, audit, threat monitor | product architect | end-to-end integration + independent review | PARTIAL |
| 2. SAG-1.0 Crypto Library | sponsor-approved provider adapter, KAT, custody | crypto + sponsor | approved module/configuration decision | BLOCKED BY EXTERNAL APPROVAL |
| 3. PQ-SIE Protocol Module | policy-bound provider interface and NIST standard suite trials | cryptography | interoperability and accepted key-management vectors | NOT IMPLEMENTED |
| 4. MFA-Gate + Military RBAC | TOTP, six role and four priority policy | identity/security | wrong-role, spoof, priority downgrade, revocation tests | TOTP PASS; duty policy IN PROGRESS |
| 5. Stealth-Dashboard | role-bound operator UI + threat view | frontend/security | real browser trials, accessibility, signed data | PARTIAL; not filed React technology |
| 6. ChronoLattice Audit Ledger | signed audit receipts and detached checkpoint | backend/V&V | chain tamper and independent checkpoint validation | PARTIAL |
| 7. SDLC Package | exact-source SBOM, threat model, security report, handover, approved licence | DevSecOps/legal | independent assessment and signed release | PARTIAL |

## Original 12-month phases (not an official or approved trial calendar)

- M1–3: source audit, security assessment, formal threat review, SAG guidance.
- M4–6: adapter boundary, identity integration, air-gap packaging; real IAF access subject to authorisation.
- M7–9: controlled relevant-environment verification and sponsor-approved field trials/certification when actually authorised.
- M10–12: handover, training, support, deployment **only if accepted and permitted**.

## Execution rules

1. Proposals, schemas and synthetic tests must never be labelled as SAG/IAF-approved capability.
2. Each delivered component needs exact commit/configuration hash, negative tests, observability and independent reviewer.
3. Source files and simulator mock connectors cannot substitute for certified providers or actual military APIs.
4. Historical applicant claims about novelty, 100% indigenous cryptographic implementations or tested field deployments require separate evidence.
5. No previously issued decryption key can be magically revoked; issue only after current epoch checks.
6. Maintain separate cost and matching-funds evidence for DIO; never commit corporate bank/ID documents to the public repository.
