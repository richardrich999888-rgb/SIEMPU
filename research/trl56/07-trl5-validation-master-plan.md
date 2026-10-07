# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Research snapshot: 2026-10-08. Scope: synthetic/authorised environments only. Base: codex/siepmu-hpsc @ f6d75cf6b105319ca0d6942b2bbc196750a0b230. Prepared engineering analysis, not IAF approval, independent assurance or verified procurement quote.

Source hierarchy: official iDEX DISC-14 PS-69, printed pp. 161–162: https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf ; authoritative repository code/evidence; public standards/product documentation. Submitted annexures, sponsor directives, PDS/PRU and agreements are unavailable in this research run and must be reconciled before asserting filed commitments.

## Objective and entry gate
Validate each approved CTE in a relevant environment, not simply pass unit tests. Freeze code SHA, dependencies, OS/container digests, policy hashes, externally trusted test identities, lab architecture, approved synthetic information classes and authorised test scope. Hold gate on unresolved HIGH/CRITICAL CVEs without formal risk disposition.

## Mandatory acceptance scenarios
| Test | Procedure outline | Must observe | Evidence |
|---|---|---|---|
| T5-01 | three lab principals, two units, send files/text | authentic E2EE, wrong third party denied, delivery ACK | signed packets, receipt & ciphertext inspection |
| T5-02 | drop/reconnect, retry/duplicate transfer | encrypted outbox safe, exact bytes, no release bypass | impairment traces, queue states |
| T5-03 | revoke while recipient offline | no *newly issued* wrapped key after epoch update | grant/epoch/event/claim order |
| T5-04 | inject synthetic failed logins/replays | event and alert generated without plaintext | log fields/redaction review |
| T5-05 | restart, lock, compromise simulation, loss of token | persisted ciphertext and fail-closed credential handling | vault and device lifecycle |
| T5-06 | synthetic independently operated legacy mock | valid schema accepted, malformed/replayed denied | adapter evidence |
| T5-07 | signed receipt+checkpoint, backup/restore, corrupt DB | tamper detection and rollback limitation documented | detached verifier, restore tests |
| T5-08 | authorised defensive security review | findings tracked, critical issues remediated | scoped test report and retest |

## Test result envelope
test_id, requirement_id, cte_id, source_commit_sha, source_tree_hash, configuration_digest, tool_versions, machine_inventory, TLS policy, topological zones, authority/controller signature, UTC start/end, workload JSON, impairment seed + measured link, expected/actual result, evidence hashes, deviations, reviewer identity and decision (PASS/FAIL/BLOCKED/WAIVED with named authority). Capture physical network taps without private content.

## Non-negotiable security invariants
- Unauthorized actor/device cannot retrieve newly released content keys.
- Trusted sender/context and recipient binding verified before plaintext use.
- Failed/expired MFA, policy epoch mismatch, HSM failure and malformed inputs fail closed.
- Retry cannot issue a different capability under stale authority.
- Audit receipt tampering must be detectable under independently trusted root/checkpoint.
- Revocation cannot recall *previously issued* keys or plaintext; no impossible claim.
- Monitoring is metadata based and cannot decrypt E2EE payloads.

## Exit gate
Each sponsor-selected CTE has an approved relevant environment + independently witnessed repeatable pass + limitations, defects and performance envelope. Critical unresolved defects block advancement unless authorised documented disposition. An engineering test success does not equal official TRL 5 declaration.
