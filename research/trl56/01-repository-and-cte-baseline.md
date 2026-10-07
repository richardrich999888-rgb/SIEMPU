# Frozen implementation and CTE baseline

Reviewed 8 October 2026 (India). The machine-readable authority for this snapshot is [baseline-evidence.json](baseline-evidence.json).

## Code and execution identity

| Record                    | Exact identifier                                                   | Meaning                                                              |
| ------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------- |
| Delivered main            | `49774e2111197412efb31d459317c0df23a838af`                         | Implemented prototype, source/tests/docs                             |
| HPSC development head     | `65a6891a41b57fe9480d1e1df901a1287c66753d`                         | Same implementation tree, merged into main                           |
| Hosted tested PR checkout | `2a8971abc2c2bd8ecaf1119e892864e21943f2bf`                         | GitHub's PR merge checkout, not the later merge commit               |
| Shared tree               | `32a44730eaee4192aa54b5c364ab07e762fc7fac`                         | Verified tree equality between tested checkout and delivered main    |
| Hosted source digest      | `3203523c0e5eb1e03bc5a806a66f0033e155283c318c0e2662ea5ccb80a083a1` | Digest computed by native validation for its configured source scope |
| Research import           | `58e88d86506b686f17c18530b759a869907ec81f`                         | Historical research directory only; not an application-code merge    |

[Hosted run 37683530326](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37683530326) completed all six jobs successfully. Native validation ended at `2026-10-07T20:39:28.585Z`: 87 tests, zero failed/cancelled/skipped; nine successful HTTP demo stages; 14 source-bound claims. Browser acceptance recorded 15 checks. Container acceptance exercised actual encrypted exchange, authentication, policy revocation and evidence. CodeQL's SARIF gate recorded zero findings; the Trivy HIGH/CRITICAL gate and Gitleaks passed. The package job generated archives and verified checksums.

These are separate observed jobs, not conclusions inferred from the native report. A dated scan is not assurance against all vulnerabilities. The image uses the pinned Node 24.19.0 Alpine runtime and patched shared libraries; Node's embedded cryptographic library must still be considered independently of OS-package scanning. Release hashes are unsigned.

## Actual architecture

`services/control/core.mjs` implements a single SQLite authority for identity, policy, wrapped-key issuance and signed evidence. `services/relay/` stores ciphertext behind authenticated interfaces. `services/web/` serves the browser and same-origin API gateway. `packages/crypto/crypto.mjs` uses platform WebCrypto for AES-GCM, P-256 and HKDF; `apps/unit-client/` contains the encrypted offline vault/outbox; `apps/verifier/verify.mjs` verifies detached evidence.

There are no npm runtime application dependencies. Node, browser, OS, SQLite and cryptographic-provider dependencies still exist. The runnable deployment has three services on one host, local HTTP and no HA. The main schema has four generic roles, not the filed six-role/four-priority taxonomy. The integration API is a synthetic schema validator, not a military connector. A complete graded-provider adapter is not implemented.

## Candidate critical technology elements

| CTE                            | Current evidence                         | Relevant-environment gap                                                      |
| ------------------------------ | ---------------------------------------- | ----------------------------------------------------------------------------- |
| CTE01 — endpoint encryption    | Native/WebCrypto and browser tests       | Adversarial transport, directory trust, independent protocol review           |
| CTE02 — identity/device trust  | MFA and software key-possession checks   | Managed endpoint/recovery policy, hardware distinction, approved role mapping |
| CTE03 — transactional release  | Race, crash and retry tests              | WAN partition/rejoin, restore rollback, current-authority continuity          |
| CTE04 — relay/service boundary | Real HTTP/container exchange             | TLS/mTLS, separate nodes, cloud deployment and scale envelope                 |
| CTE05 — offline client         | Browser lock/reload/outbox tests         | Network/clock matrix and bounded local-use policy                             |
| CTE06 — evidence               | Signed receipts/checkpoints and verifier | Independent custody, freshness and rollback quarantine                        |
| CTE07 — monitoring             | Counters, structured events, admin view  | Independent redacted sink and measured triage workflow                        |
| CTE08 — integration            | Synthetic validator                      | Independent authenticated mock, then approved real interface                  |
| CTE09 — graded cryptography    | No approval evidence                     | Sponsor-defined grading path and exact configuration approval                 |

The CTE list itself requires sponsor confirmation. [Readiness records](cte-readiness-matrix.csv) do not award numerical TRLs.

## Historical findings and remaining limits

The earlier CodeQL parser failure and vulnerable final image described by run `37678323924` were resolved for E004. Their original evidence remains in [the historical record](historical-baseline.md); this review does not rewrite archived 72/78-test reports. The older loopback measurement of 30 sequential 4 KiB objects is not evidence of current WAN capacity.

Neither passing CI nor this reconciliation demonstrates SAG approval, real IAF integration, representative DDIL trials, independently protected content keys, classified use, cross-domain release, air-gap peer exchange, PQC, forward secrecy or operational readiness. Revocation can prevent a new issuance when committed first; it cannot recall a previously released key or plaintext.
