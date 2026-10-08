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

| SHA                | Workflow / run                       | Result                                                                                                                                                             |
| ------------------ | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `a4abc80` (PR #16) | CI 37716985109, Security 37716985101 | FAIL: native (check, lint, format, coverage), regression (`sarif-gate.test.mjs`), CodeQL gate (`SyntaxError`); container skipped. Root cause: five corrupted files |
| `2fc827e`          | CI 37727941433                       | native FAIL (`test:coverage`, intermittent, see below); pqc-lab PASS; browser PASS; container/testbed skipped                                                      |
| `a932cce`          | CI 37728343565                       | native PASS; pqc-lab PASS; browser PASS; container and testbed: see run                                                                                            |
| `a932cce`          | Security 37728343538                 | PASS (dependency/regression, secret scan, CodeQL gate)                                                                                                             |

## Local verification (Node 24.21.0, Linux container)

- `npm run validate` PASS on `2fc827e`: 208/208 tests, 97.57 % lines, 88.96 % branches.
- `npm run test:e2e` 3/3; PQC lab `npm --prefix packages/pqc-lab test` 6/6.
- Chromium `tests/browser/shell-upgrade.mjs` 3/3 (merged service worker).

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

## Incomplete

- **PQC end-to-end application flow**: authority v3 submission/release path, endpoint v3 envelope
  (`packages/pqc-lab/envelope.mjs` was destroyed in PR #16 and never imported), v3 evidence in
  verifier. In progress on this branch.
- Trust-Before-Release scripted demonstration and evidence report.
- PR #16 adapter negative tests (freshness, ambiguous restart quarantine, capacity) not ported.
- `research/defence-comparison/sources.json` D04–D15 must be re-retrieved.
- Live re-verification of the iDEX PS-69 page (not reachable from the build environment).

## Open security findings

None open from hosted CodeQL on `a932cce`. Known design limits: `docs/limitations.md`.

## External approvals (not in scope of engineering completion)

SAG grading, IAF identity/PKI and interface specifications, relevant-environment definition,
independent security assessment, sponsor acceptance, hardware custody procurement, operational
authorisation, formal TRL assignment.

## Next executable task

Implement the v3 laboratory end-to-end path (endpoint envelope, authority admission/release behind
`SIEPMU_ALLOW_PQC_LAB`, crypto-policy registry wiring, signed crypto evidence, verifier), then the
Trust-Before-Release demonstration script and report.
