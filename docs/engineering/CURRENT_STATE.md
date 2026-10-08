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

| SHA                | Run                                                | Result                                                                                                     |
| ------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `a4abc80` (PR #16) | CI 37716985109, Security 37716985101               | FAIL: native, regression, CodeQL gate; container skipped. Root cause: five corrupted files                 |
| `32b4a1c` (PR #15) | CI 37716389026 (push) / 37716393630 (pull_request) | push: **testbed FAIL**; pull_request: PASS. Same SHA; testbed is runner-dependent                          |
| `2fc827e`          | CI 37727941433                                     | native FAIL (`EADDRINUSE` race, fixed in `7655f7b`); pqc-lab, browser PASS                                 |
| `a932cce`          | CI 37728343565; Security 37728343538               | native, pqc-lab, browser, container PASS; testbed FAIL 60/75; Security PASS                                |
| `cfdaae1`          | CI 37729846135; Security 37729846172               | native, pqc-lab, browser, container PASS; testbed FAIL 60/75; Security PASS                                |
| `4e422c7`          | CI 37730428069; Security 37730428089               | native PASS (incl. Trust Before Release on runner), pqc-lab PASS, browser PASS; testbed/container: see run |

Open: the netem testbed fails exactly one profile (15 of 75 exchanges, all 8 non-exchange
samples pass). The same failure occurs on PR #15's own SHA, so it predates this branch.
`deployment/testbed/run.mjs` now prints failure rows to the job log to identify the profile.

## Local verification (Node 24.21.0, Linux container)

- `npm run validate` PASS on `4e422c7` content: 228/228 tests, about 97 % lines.
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

## Implemented (engineering axis) — see WORK_PACKAGE_REGISTER.md

TLS 1.3/mTLS profiles, 10-zone netem testbed, checkpoint custody and recovery quarantine,
monitoring collector, synthetic adapter, FLASH dual control (provisional policy), duty roles,
signed offline release, classical provider port, provider engine with key lifecycle, PQC lab
providers (ML-KEM-768/1024, ML-DSA-65 via OpenSSL; X-Wing via Noble) with NIST/author vectors.

## Completed on this branch since reconciliation

- Laboratory v3 PQC end-to-end path through the authority release transaction (ADR-010), with
  wrap v2 fixing the HKDF `info` size defect (defect 9 below).
- Trust Before Release scripted demonstration, report and CI step.

## Incomplete

- Testbed one-profile failure (above).
- PR #16 adapter negative tests (freshness, ambiguous restart quarantine, capacity) not ported.
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

1. Root-cause and fix the testbed profile failure using the job-log failure rows.
2. Port PR #16 adapter negative cases onto `services/integration/`.
3. Independent review package for the v3 composition; evaluate RFC 9180 HPKE with PQ KEMs.
4. Re-retrieve `research/defence-comparison/sources.json` D04-D15.
