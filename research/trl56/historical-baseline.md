# Historical research baseline — superseded

This is the original assessment at research commit `58e88d86506b686f17c18530b759a869907ec81f`. Its branch heads, failures and test counts are historical. Current status is in `01-repository-and-cte-baseline.md` and `baseline-evidence.json`.

# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Research snapshot: 2026-10-08. Scope: synthetic/authorised environments only. Base: codex/siepmu-hpsc @ f6d75cf6b105319ca0d6942b2bbc196750a0b230. Prepared engineering analysis, not IAF approval, independent assurance or verified procurement quote.

Source hierarchy: official iDEX DISC-14 PS-69, printed pp. 161–162: https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf ; authoritative repository code/evidence; public standards/product documentation. Submitted annexures, sponsor directives, PDS/PRU and agreements are unavailable in this research run and must be reconciled before asserting filed commitments.

## Three-branch forensic ledger

| Ref                           | Frozen SHA                               | What verified by repository inspection                 |
| ----------------------------- | ---------------------------------------- | ------------------------------------------------------ |
| main                          | f0d1db2e8c1415aa99543c96939ae00374ca6c5a | LICENSE + README only                                  |
| feature/repository-foundation | 2df227ef060889ebef67d350a664b9c7e2152e02 | ~153 git tree entries; implemented apps/services/tests |
| codex/siepmu-hpsc             | f6d75cf6b105319ca0d6942b2bbc196750a0b230 | ~157 entries; additional test and validation documents |

Both development heads share ancestor 596b74c4a31091b7312760ef4360bba7eb21dcac; feature and codex have diverged one commit each. Freeze SHA of any merged candidate and compare source and evidence again.

## Engineering implementation baseline

Actual modules: services/control/core.mjs (SQLite serialized authority, identity, policy, grant and transactional release); services/relay/{server,auth}.mjs (authenticated ciphertext relay); services/web/server.mjs (same-origin gateway); packages/crypto/crypto.mjs (endpoint WebCrypto AES-256-GCM, P-256, HKDF and signed context); apps/unit-client/{app,vault-store,sw}.mjs (offline browser client); apps/admin-console; apps/verifier/verify.mjs (detached audit); scripts/validate.mjs; tests/\*.test.mjs; Compose, Dockerfile and pinned GitHub workflows.
Node >=24.19 <25, zero npm runtime application dependencies (OS/OpenSSL/SQLite/Node/browser remain dependencies). Architecture is three services on one host, not HA. Repo findings are file/code inspection, not live system tests in this research run.

## Evidence inspection

Historical native report: docs/testing/native-validation.json, ended 2026-10-07 19:54:20Z, 72 passing native tests; report explicitly references dirty tree and sourceDigest 33f380b76e86566594e2279e72a6c2f6c1e4216ea3b9cf4998548726b9d30492. Browser record docs/testing/browser-results.json: 14 Chromium assertions, historical. Performance 30 sequential 4 KiB loopback objects at 9.86/s; no WAN, fleet capacity or server-side CPU baseline. These records do not prove current HEAD performance.

## Critical technology elements (engineering candidates, to be sponsor-confirmed)

| CTE                                                 | Components                               | Current evidence                     | Additional TRL 5 needed                                                                    |
| --------------------------------------------------- | ---------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------ |
| CTE-01 endpoint E2EE and signed envelope            | packages/crypto; apps/unit-client        | Native, browser historical           | TLS/public-Internet adversarial lab, third-party protocol review, key-directory compromise |
| CTE-02 user/device trust/MFA                        | services/control; apps/unit-client       | Authentication tests; software proof | Device loss/recovery and token/hardware study; sponsor role/PKI mapping                    |
| CTE-03 policy-epoch transactional key release       | services/control/core.mjs                | Race/crash/retry tests               | Multi-endpoint network partition/rejoin, snapshot rollback and policy freshness            |
| CTE-04 ciphertext relay and workload authentication | services/relay                           | HTTP negative tests                  | WAN/replay/failure and service identity tests                                              |
| CTE-05 encrypted offline vault/outbox               | apps/unit-client                         | Browser offline test                 | Loss/reconnect/clock drift/capacity, different browsers/OS                                 |
| CTE-06 audit and detached checkpoint                | apps/verifier; control                   | Signature tests                      | Independently stored checkpoint and restore/red-team validation                            |
| CTE-07 monitoring and operations                    | services/control; admin console          | Counters/events                      | External collector and alert triage in representative isolated environment                 |
| CTE-08 integration boundary                         | /api/integration/validate                | Synthetic schema only                | Independent synthetic mock service across controlled security boundary                     |
| CTE-09 sponsor cryptographic compliance             | crypto provider seam not proven complete | No SAG evidence                      | Formal interface/approval decision; cannot mark approved without sponsor                   |

## Current TRL assessment

No source-backed whole-system TRL rating can be assigned: tests show engineering proof-of-concept behaviors, not independent validation of defined CTEs in a sponsor-accepted relevant environment. CTE readiness = engineering prototype with incomplete environmental/assurance evidence, NOT a certified numerical TRL. Establish reviewer-authorized relevant environment and observe reproducible test runs before seeking a CTE-by-CTE TRL 5 decision.

## Release-blocking forensic findings

HEAD Actions run 37678323924: native/browser/secret-scan succeed. CodeQL extraction/analyze succeed but local SARIF gate fails with “Finding does not resolve to an unambiguous rule”; preserve artifact and fix parser according to actual schema, no blanket ignore. Trivy image scan exit 1: Debian analysis 60 HIGH/CRITICAL (56 HIGH/4 CRITICAL) and Node package analysis 12 (11 HIGH/1 CRITICAL); findings may overlap packages and many are fix-status-dependent. Container build and three-service startup pass. Assign CVE triage, base-image refresh and rescanning; never just lower severity threshold.
