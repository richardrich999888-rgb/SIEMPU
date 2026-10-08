---
name: siepmu-project-context
description: Background on SYNTRIASS AIRON–SIEPMU, the iDEX DISC-14 IAF Problem Statement 69 challenge, what the IAF requires versus what the applicant proposed, and which documents are authoritative. Use when a task touches scope, requirements, claims, the filed application, terminology (SIEPMU vs SIEMPU), or when deciding whether a feature is mandated, proposed or out of scope.
---

# SIEPMU project context

## Identity

- Organisation: SYNTRIASS. Product: **AIRON–SIEPMU**. Repository slug: `SIEMPU` (keep it);
  user-facing acronym: **SIEPMU**.
- Challenge: **iDEX DISC-14, Indian Air Force Problem Statement 69**, "Secure Information Exchange
  Platform for Military Units (SIEPMU) on Public Internet". Reference page:
  `https://idex.gov.in/challenges-cpt/2507`. The repository's recorded source is
  `E001: PS-69 printed pp161-162` (see `research/trl56/requirement-traceability.csv`).
  The live page could not be fetched on 2026-10-08 (DNS failure from the build environment);
  re-verify it when network access allows and record the date.

## The problem in one paragraph

Geographically separated units exchange authorised information over the public Internet
without trusting the network, relays, storage or hosting. Plaintext and recipient private keys
stay at endpoints. The authority releases a recipient's wrapped content key only after re-checking
**current** policy, and signs evidence of every decision for an independent verifier.
SIEPMU complements AFNET, DCN, tactical radio and C2 systems; it does not replace them.

## Requirements: three different categories (never mix them)

| Category                                                                                                                                                                                 | Where                                                                                                                                          | Status meaning                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| PS-69 published requirements R1–R12 (incl. cloud microservices, E2EE, MFA, secure protocols, threat monitoring, granular RBAC, integration with existing systems, SAG-graded encryption) | `research/trl56/requirement-traceability.csv`, `docs/requirements/README.md`                                                                   | IAF requirement                                      |
| Applicant commitments: six duty roles, FLASH/IMMEDIATE/PRIORITY/ROUTINE, PQC protocol proposal, operational interfaces, 12-month plan                                                    | `docs/application/DISC14_PS69_FILED_BASELINE.md`, `research/trl56/17-proposal-reconciliation.md`, `research/trl56/proposal-claim-register.csv` | Proposed by SYNTRIASS; **not** approved IAF policy   |
| Architectural extensions: disconnected queueing, air-gap profile, PQC lab                                                                                                                | `docs/secure-airgap-profile.md`, `packages/pqc-lab/`                                                                                           | Engineering choices; never claim PS-69 mandates them |

Confidential annexures, private communications, financial records and sponsor specifications
must **not** be committed. `docs/application/` holds only the reconciled public baseline.

## Decisions that remain external

Information classifications, hosting/administration, IAF identity/PKI, approved devices/OS,
cryptographic suites and **SAG grading**, legacy interfaces, availability/performance targets,
audit retention, independent evaluation scope, deployment and support terms. Open questions:
`research/trl56/16-iaf-clarification-register.md`, `docs/requirements/open-questions.md`.
When one blocks work, build a synthetic adapter and add the precise question there.

## Authoritative documents

- Current engineering state: `docs/engineering/CURRENT_STATE.md` (read first).
- Claims discipline: `docs/claims.md`, `CLAIMS_REGISTER.yaml`, `scripts/audit-claims.mjs`.
- Limitations: `docs/limitations.md`. Threat model: `docs/threat-model.md`.
- Research dossier index: `research/trl56/README.md` (validated by `research/trl56/validate.py`).

## Safety checks before writing anything user-facing

1. Is the statement an IAF requirement, an applicant commitment, or an engineering extension? Say which.
2. Is every result tied to an exact SHA and command? If not, do not state it as a result.
3. Avoid: "quantum-proof", "unhackable", "SAG-compliant", "IAF-approved", "certified", "deployed".
4. Synthetic data only. No real unit names, callsigns, locations or personnel.

## Definition of done for scope work

The change cites its source category, updates `docs/engineering/CURRENT_STATE.md` if status
changes, and `npm run audit:claims` passes.

## Known limitations of this skill

The PS-69 text is taken from repository records, not re-fetched this session. The original
submitted annexures are not in the repository; reconciliation relies on `17-proposal-reconciliation.md`.
