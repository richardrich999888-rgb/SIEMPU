# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Research snapshot: 2026-10-08. Scope: synthetic/authorised environments only. Base: codex/siepmu-hpsc @ f6d75cf6b105319ca0d6942b2bbc196750a0b230. Prepared engineering analysis, not IAF approval, independent assurance or verified procurement quote.

Source hierarchy: official iDEX DISC-14 PS-69, printed pp. 161–162: https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf ; authoritative repository code/evidence; public standards/product documentation. Submitted annexures, sponsor directives, PDS/PRU and agreements are unavailable in this research run and must be reconciled before asserting filed commitments.

## Traceable checks
| Test | Official requirement | Candidate CTE | Responsible | Status at research date |
|---|---|---|---|---|
| T5-01 | R1 R2 R5 R7 | 01 02 03 04 | Crypto/endpoint QA | TO EXECUTE IN RELEVANT LAB |
| T5-02 | R2 R10 | 03 05 | Network/QA | TO EXECUTE |
| T5-03 | R5 R7 | 02 03 | Security/QA | TO EXECUTE |
| T5-04 | R6 | 07 | SOC/QA | TO EXECUTE |
| T5-05 | R2 R5 R10 | 01 02 05 | Endpoint/QA | TO EXECUTE |
| T5-06 | R8 | 08 | Integration/QA | TO EXECUTE |
| T5-07 | R2 R10 R12 | 06 | Evidence/QA | TO EXECUTE |
| T5-08 | R6 R12 | all | Independent assessor | NOT COMMISSIONED |
| SAG-01 | R9 | 09 | Sponsor/SAG authority | EXTERNAL BLOCKER |
| TLS-01 | R6 | 04 | Deployment/security | NOT QUALIFIED |
| CI-01 | R12 | all | DevSecOps | HEAD HOSTED FAILED |

## Verification strategy
T5-01: native/WebCrypto interoperability plus packet capture; observe ciphertext not plaintext on relay. T5-02: netem outages, 100 consecutive retries, process restart and queue replay; compare authoritative object and receipt count. T5-03: schedule revocation before and after claim commit, distinguish post-commit irreversibility. T5-04: synthetic auth attacks only (replay, wrong role, invalid signature) in owned lab, assert event schema with no sensitive content. T5-05: restart browser offline; credential loss and revoked binding; recovery/escrow limitations. T5-06: mock external independent process with invalid schema, signature, duplicate ID and stale grant. T5-07: external audit root, checkpoint export, backup restore + older snapshot adversarially. T5-08: scoped review and re-execution of failing regressions after remediation.

## Required sign-off sequence
Engineer -> test lead -> independent security reviewer -> sponsor witness or authorising agency (when assigned). Do not substitute CI green status for independent assessment. See machine-readable trl5-test-matrix.csv for exact test identifiers.
