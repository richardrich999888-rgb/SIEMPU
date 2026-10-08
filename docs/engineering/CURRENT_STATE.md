# Current engineering state (single authoritative handover file)

**Review date:** 2026-10-08. **Branch:** `claude/siepmu-engineering-recovery-3nwgc8`.
Update this file from executed results whenever major work completes, and before ending a session.
Never copy a result forward to a new SHA.

## Baseline inspected

| Ref                                         | SHA       | Meaning                                          |
| ------------------------------------------- | --------- | ------------------------------------------------ |
| `main`                                      | `ad80210` | Delivered prototype baseline                     |
| PR #15 `codex/siepmu-trl5-trl6-engineering` | `32b4a1c` | Hosted CI green at handover; base of this branch |
| PR #16 `codex/siepmu-q-agile`               | `a4abc80` | Hosted CI red; ported selectively (ADR-006)      |
| This branch, reconciliation commit          | `2fc827e` | —                                                |
| This branch, diagnostics + docs             | `a932cce` | —                                                |

Other open PRs: #13 (filed-application alignment, superseded by PR #15/#16 content), #2
(repository foundation, superseded), Dependabot #3–#12. **#8 bumps the container to Node 26,
which violates `engines` `<25`; do not merge as-is.** #4 (TypeScript 7) and #6 (`@types/node` 26)
need typecheck evaluation.

## Hosted CI results (exact SHAs)

| SHA                | Run                                                                                    | Result                                                                                                                                                |
| ------------------ | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `a4abc80` (PR #16) | CI 37716985109, Security 37716985101                                                   | FAIL: native, regression, CodeQL gate; container skipped. Root cause: five corrupted files                                                            |
| `32b4a1c` (PR #15) | CI 37716389026 (push) / 37716393630 (pull_request)                                     | push: **testbed FAIL**; pull_request: PASS. Same SHA; testbed is runner-dependent                                                                     |
| `2fc827e`          | CI 37727941433                                                                         | native FAIL (`EADDRINUSE` race, fixed in `7655f7b`); pqc-lab, browser PASS                                                                            |
| `a932cce`          | CI 37728343565; Security 37728343538                                                   | native, pqc-lab, browser, container PASS; testbed FAIL 60/75; Security PASS                                                                           |
| `cfdaae1`          | CI 37729846135; Security 37729846172                                                   | native, pqc-lab, browser, container PASS; testbed FAIL 60/75; Security PASS                                                                           |
| `4e422c7`          | CI 37730428069; Security 37730428089                                                   | native (incl. Trust Before Release), pqc-lab, browser PASS; testbed cancelled by next push; **Security FAIL**: CodeQL `js/insufficient-password-hash` |
| `f7b94bd`          | CI 37730762294; Security 37730762398                                                   | **all CI jobs PASS incl. testbed 75/75** (N8 interface fix); Security FAIL (same CodeQL finding)                                                      |
| `d4ff627`          | CI 37731395525; Security 37731395528                                                   | **Security PASS** (CodeQL fixed); browser FAIL: test race fixed in `7d0f568`                                                                          |
| `7d0f568`          | —                                                                                      | runs cancelled by the next push                                                                                                                       |
| `fa3f524`          | CI 37731906364                                                                         | native FAIL: truncated V8 coverage file (SIGKILL raced worker exit), fixed in `17fe1bf`                                                               |
| `17fe1bf`          | CI 37732307142 / 37732310353; Security 37732307170 / 37732310464 (push / pull_request) | **ALL PASS**: native (incl. Trust Before Release), pqc-lab, browser, container, testbed; Security (CodeQL gate, secrets, regression)                  |
| `85e4c7d`          | CI 37754418709; Security 37754418448 (pull_request)                                    | **ALL PASS**: native (incl. Trust Before Release), pqc-lab, browser, container, testbed; Security                                                     |
| `aa1ab91`          | Security 37755304070 / 37755313266                                                     | secret-scan FAIL: gitleaks `generic-api-key` on a public HKDF known-answer constant; exact fingerprint added (documented exception policy)            |
| `ec0ea61`          | CI 37755495149 / 37755500534; Security 37755495108 / 37755500358 (push / pull_request) | **ALL PASS** incl. secret-scan, testbed, Trust Before Release; PR #17 mergeable (clean)                                                               |

Resolved: the testbed failed exactly one netem profile (15 of 75) here and on PR #15's own SHA.
N8 targeted the interface named `eth1`, whose network depends on Docker's attachment order; it
is now selected by address (`f7b94bd`, hosted 75/75).

## Local verification (Node 24.21.0, Linux container)

- `npm run validate` PASS on `aa1ab91` content: 237/237 tests, 97.5 % lines.
- `npm run test:e2e` 3/3; PQC lab 7/7 (incl. X-Wing end-to-end); Chromium shell-upgrade 3/3.
- Trust Before Release 14/14 (`docs/engineering/TRUST_BEFORE_RELEASE.md`).

## Defects found and fixed on this branch

1. PR #16: five files published with invalid UTF-8 (all its CI failures). Gate added: `scripts/text-integrity.mjs`.
2. PR #15 + merge: `crypto.mjs` import graph broke offline start after an interrupted service-worker upgrade (ADR-007).
3. PR #15: `GET /api/objects` returned HTTP 500 for duty-role users when one stored envelope was unreadable (ADR-009).
4. PR #15/#16: FLASH dual control and duty checks keyed on `schemaVersion === 2`; a v3 object would bypass them. Now `hasMissionLabels()`.
5. Lab PQC code and its unaudited npm dependency were copied into `dist/`, the container and signed offline bundles (ADR-008).
6. Migration number collision `004` between the branches (`005-crypto-policy.sql`).
7. PR #16's `Authority` ignored `allowPqcLab`; the registry was never wired (fail-closed: v3 was rejected at submission).
8. **Intermittent `EADDRINUSE`** in multi-process tests: `freePort()` released a port from the ephemeral
   range before a child bound it; outbound sockets could take it. Reproduced 1/12 locally. Fixed by
   `deployment/secure/ports.mjs` (ports below the ephemeral range). This is the most likely cause of
   the `2fc827e` hosted failure, whose log was not retrievable (artefact host blocked); the CI job
   log now prints a failure excerpt so a recurrence will identify the test.
9. PR #16 `CryptoEngine.wrapKey` inlined the context into HKDF `info` (WebCrypto limit 1024 bytes);
   every real object failed. Wrap v2 binds a context digest (ADR-010).
10. Client-chosen initial passwords entered the operation-proof request hash (unsalted SHA-256,
    persisted with the challenge) beside their scrypt hash; CodeQL `js/insufficient-password-hash`.
    The authority now generates them (`d4ff627`).
11. Testbed N8 severed the enclave link on some Docker engines (`f7b94bd`).
12. Browser acceptance race: a stale READY badge could satisfy the wait for a new object (`7d0f568`).
13. Coverage teardown race: SIGKILL of an exiting worker truncated its V8 coverage file (`17fe1bf`).

## Implemented (engineering axis) — see WORK_PACKAGE_REGISTER.md

TLS 1.3/mTLS profiles, 10-zone netem testbed, checkpoint custody and recovery quarantine,
monitoring collector, synthetic adapter, FLASH dual control (provisional policy), duty roles,
signed offline release, classical provider port, provider engine with key lifecycle, PQC lab
providers (ML-KEM-768/1024, ML-DSA-65 via OpenSSL; X-Wing via Noble) with NIST/author vectors.

## Completed on this branch since reconciliation

- Laboratory v3 PQC end-to-end path through the authority release transaction (ADR-010), with
  wrap v2 fixing the HKDF `info` size defect (defect 9 below).
- Trust Before Release scripted demonstration, report and CI step.
- Synthetic adapter negative/restart cases ported from PR #16 (`85e4c7d`).
- Independent review package: `research/cryptographic-standards/V3_COMPOSITION.md` (byte-level
  spec, intended properties P1–P6, assessor questions R1–R7, pinned wrap v2 vector reproduced in
  Python), `HPKE_PQ_EVALUATION.md`, ADR-011 (HPKE base mode reserved as wrap v3, not adopted).

## Incomplete

- `research/defence-comparison/sources.json` D04–D15 must be re-retrieved.
- Live re-verification of the iDEX PS-69 page (not reachable from the build environment).

## Open security findings

None open from hosted CodeQL on `a932cce`. Known design limits: `docs/limitations.md`.

## External approvals (not in scope of engineering completion)

SAG grading, IAF identity/PKI and interface specifications, relevant-environment definition,
independent security assessment, sponsor acceptance, hardware custody procurement, operational
authorisation, formal TRL assignment.

## Open pull request

PR #17 (draft) from this branch to `main`. Not to be merged automatically.

## Next executable tasks

1. Re-retrieve `research/defence-comparison/sources.json` D04-D15 (needs network access to the
   original sources; not reachable from this environment).
2. Re-check `HPKE_PQ_EVALUATION.md` against the published `draft-ietf-hpke-pq` revision (IETF
   hosts blocked here); then prototype wrap v3 behind ADR-011's gates.
3. Engage an independent cryptographic assessor with `V3_COMPOSITION.md` (external).
