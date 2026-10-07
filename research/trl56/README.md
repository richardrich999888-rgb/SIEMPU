# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Research snapshot: 2026-10-08. Scope: synthetic/authorised environments only. Base: codex/siepmu-hpsc @ f6d75cf6b105319ca0d6942b2bbc196750a0b230. Prepared engineering analysis, not IAF approval, independent assurance or verified procurement quote.

Source hierarchy: official iDEX DISC-14 PS-69, printed pp. 161–162: https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf ; authoritative repository code/evidence; public standards/product documentation. Submitted annexures, sponsor directives, PDS/PRU and agreements are unavailable in this research run and must be reconciled before asserting filed commitments.

## Objective
Preserve the existing low-dependency security-critical transaction boundary; close release-blocking CI findings; validate critical technology elements in a relevant lab, then demonstrate a multi-node representative prototype.

## Baseline reality
- main: f0d1db2 — README/LICENSE only.
- feature/repository-foundation: 2df227e — code and tests.
- codex/siepmu-hpsc: f6d75cf — code, expanded browser tests and historical measured records.
- Feature and codex heads have diverged (one independent commit each from common ancestor 596b74c); no automatic merge.
- HPSC HEAD hosted run 37678323924: native, browser and secrets successful; CodeQL SARIF gate and container Trivy high/critical scan failed; release skipped. https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37678323924
- Historical local report: 72 native tests, nine synthetic demo steps; this is not fresh external validation of TRL 5.
- No SAG grading, real IAF integration, public-Internet hardened TLS deployment or independent TRL 5 trial proven.

## Decision rubric
ADOPT = evidence + no hard-gate concern + specific measured gap; PROTOTYPE = justified but needs integration test; DEFER = only later milestone needs it; REJECT = unnecessary attack surface or contradicts E2EE. Scores are provisional expert triage only, never replace legal/cryptographic/sponsor approval.

## Document map
01–16 are the research narrative; machine-readable registries hold candidates, test cases, procurement unknowns and traceability; architecture/*.mmd holds editable Mermaid diagrams. No operational military credentials or restricted data are present.

## Immediate operational constraints
Never deploy local HTTP to public Internet. Do not handle classified/operational IAF content; do not probe real military networks. Commercial FIPS claims cannot be substituted for SAG approval.
