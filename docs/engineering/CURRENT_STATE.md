# Current engineering state (single authoritative handover file)

**Review date:** 2026-10-08. **Branch:** `claude/siepmu-trl56-recovery-9o6qet` (stacked on PR #17's
branch `claude/siepmu-engineering-recovery-3nwgc8` at `e3174fe`; not merged into `main`).
Update this file from executed results whenever major work completes, and before ending a session.
Never copy a result forward to a new SHA.

## Current head and hosted evidence

| SHA       | Content                                                    | Hosted result                                                                                                                                                       |
| --------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `4af847b` | Verifier member-set fix; Rust reference verifier + vectors | CI 37756819771 PASS (6/6 jobs incl. rust-native); Security 37756819737 PASS                                                                                         |
| `7ac38e3` | TLA+ model                                                 | CI 37760088995 cancelled by next push; Security 37760089191 PASS                                                                                                    |
| `693327f` | Remove generated TLC traces                                | CI 37760213427 PASS; Security 37760213262 PASS                                                                                                                      |
| `68c8cc2` | Alert-epoch monitoring fix; Core Mission Workflow          | CI 37761417035 PASS; Security 37761417036 PASS                                                                                                                      |
| `7b01d1a` | Decision explanations, capability model (ADR-013)          | **CI 37762135413 PASS, all 7 jobs** (native, rust-native incl. mission workflow, formal, pqc-lab, browser, container, testbed 75/75); **Security 37762135250 PASS** |

Run URLs: `https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/<id>`.

PR #17's branch advanced concurrently to `0e8d1b9` (adapter negative cases ported, HPKE-PQ evaluation
as ADR-011, Rust ADR renumbered to ADR-012, HPSC demos, the same telemetry fix). It is merged into this
branch with a merge commit; the UI ADR is therefore ADR-013. Hosted results for the merge commit are
on PR #18.

## Local verification on `7b01d1a` content (Node 24.21.0, rustc 1.97.0, OpenJDK 21, 4 vCPU)

- `npm run validate` PASS (230+ tests, about 97 % lines); `test:security` 123/123; `test:e2e` 3/3;
  `test:engineering` 16/16; Trust Before Release PASS; `test:browser:isolated` PASS (with
  `SIEPMU_CHROMIUM_PATH` because this container's Playwright browser build differs).
- Rust: `cargo fmt --check`, `clippy -D warnings` (all deny, pedantic warn), 28 tests, `cargo audit
--deny warnings` 0 advisories over 28 crates. `npm run test:native` 3/3 (400 mutations identical).
- `npm run formal:check`: faithful 3,837,180 states / depth 29 no error; `nonatomic` violates
  `IssueRequiresCurrentAuthority`; `unguarded` violates `AckedRevocationHolds`.
- `npm run test:mission`: classical 18/18, pqc-lab 18/18, about 20 s.

## Defects found and fixed in this session

14. Node verifier member-set check joined names with `|`, so one member `keyId|payload` satisfied
    two expected names (`f40bfbc`). Not exploitable (later checks rejected), now unambiguous.
15. **Monitoring silently stopped after the first alert followed by any epoch change**: alert events
    were stamped with the export-time epoch, the collector rejected every later batch with
    `TELEMETRY_CONFLICT` (`32e1585`, migration 006). Present on the hosted-green baseline; found by
    the mission workflow's positive controls. A concurrent session fixed the same defect on the PR #17
    branch (`0e8d1b9`) with an equivalent migration 006; on merging that base into this branch its
    migration text, collector and core changes were kept (one canonical 006 checksum), plus this
    branch's legacy-schema backfill test.

## Implemented in this session (details: ADR-012, ADR-013, formal/README.md, MISSION_WORKFLOW.md)

- Rust reference evidence verifier (general mode) with language-neutral spec and generated vectors.
  Measured: 1.6–5.7x lower peak RSS, 0.54–0.89x Node speed (pure-Rust P-256 verify is ~2x slower).
- TLA+ model of release, revocation, custodian-guarded recovery; mutant configs prove non-vacuity.
- 18-step Core Mission Workflow on the five-process secure stack, classical and lab PQC profiles.
- UI: content-free decision explanations for every authority code; deny-by-default capabilities.

## Not done / incomplete (honest list)

- UI: `app.mjs` decomposition; dedicated security/evaluation view; accessibility audit with
  assistive technology; task-based usability evaluation; Tauri evaluation (no hardware target).
- Rust: strict release mode with replay store; HSM/TPM/PKCS#11 native custody (no hardware).
- Deployment: no Kubernetes/K3s profile executed; PostgreSQL/multi-replica not attempted (would need
  proof of equivalent release/revocation consistency; the TLA+ model is the starting point).
- The v3 composition review package and HPKE-PQ evaluation (ADR-011, on the base branch) still
  await independent cryptographic review.
- Node reference still accepts spec divergences D1–D3 (lone surrogates, invalid UTF-8, duplicate
  members); changing that is a deliberate contract change, not yet made.

## External approvals (unchanged; not engineering deliverables)

SAG grading, IAF identity/PKI and interface specifications, relevant-environment definition,
independent security assessment, sponsor acceptance, hardware procurement, operational
authorisation, formal TRL assignment.

## Next executable tasks

1. Security/evaluation view in the admin console using `capabilities.mjs` (evidence verification,
   crypto inventory, recovery and monitoring health), with browser tests.
2. Extend the TLA+ model to FLASH approval revocation and multi-recipient instances (bigger machine).
3. Decide (ADR) whether the Node verifier should adopt D1–D3 rejection.

## Record of the previous session (PR #17 branch, kept for provenance)

### Baseline inspected

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

### Hosted CI results (exact SHAs)

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
| `ecc5b51`          | CI/Security on PR #17 (merge of Rust verifier `4af847b`)                               | ALL PASS (check suite completed, no failures)                                                                                                         |
| `0e8d1b9`          | CI 37761613000 / 37761620422; Security 37761613051 / 37761620429 (push / pull_request) | **ALL PASS** incl. rust-native, Demos 3 and 4, testbed. **Frozen HPSC demonstration baseline** (`docs/hpsc/FROZEN_BASELINE.md`)                       |

Resolved: the testbed failed exactly one netem profile (15 of 75) here and on PR #15's own SHA.
N8 targeted the interface named `eth1`, whose network depends on Docker's attachment order; it
is now selected by address (`f7b94bd`, hosted 75/75).

### Local verification (Node 24.21.0, Linux container)

- Frozen code `0e8d1b9`: `npm run validate` PASS 249/249 tests, 97.5 % lines; `test:e2e` 3/3; `npm run demo` 9/9;
  Trust Before Release 14/14; Demo 3 10/10; Demo 4 11/11 (Rust verifier ACCEPT genuine / REJECT tampered).
- Rust (cargo 1.97.0) on the merge `ecc5b51`: fmt, clippy `-D warnings`, 26 unit + 2 vector tests, vectors:check,
  differential check 3/3.
- Signed offline bundle built and installed from a clean worktree at `0e8d1b9` (manifest SHA-256 `5fd7b76d…`).

### Defects found and fixed on this branch

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
14. Telemetry stall: re-exported alerts were stamped with the export-time epoch; after any authority change the
    collector rejected every batch as a conflict and monitoring stopped silently (present since PR #15).
    Migration 006 records the epoch at alert time (`0e8d1b9`); regression test reproduces the old failure.

### Implemented (engineering axis) — see WORK_PACKAGE_REGISTER.md

TLS 1.3/mTLS profiles, 10-zone netem testbed, checkpoint custody and recovery quarantine,
monitoring collector, synthetic adapter, FLASH dual control (provisional policy), duty roles,
signed offline release, classical provider port, provider engine with key lifecycle, PQC lab
providers (ML-KEM-768/1024, ML-DSA-65 via OpenSSL; X-Wing via Noble) with NIST/author vectors.

### Completed on this branch since reconciliation

- Laboratory v3 PQC end-to-end path through the authority release transaction (ADR-010), with
  wrap v2 fixing the HKDF `info` size defect (defect 9 below).
- Trust Before Release scripted demonstration, report and CI step.
- Synthetic adapter negative/restart cases ported from PR #16 (`85e4c7d`).
- Independent review package: `research/cryptographic-standards/V3_COMPOSITION.md` (byte-level
  spec, intended properties P1–P6, assessor questions R1–R7, pinned wrap v2 vector reproduced in
  Python), `HPKE_PQ_EVALUATION.md`, ADR-011 (HPKE base mode reserved as wrap v3, not adopted).

### Incomplete

- `research/defence-comparison/sources.json` D04–D15 must be re-retrieved.
- Live re-verification of the iDEX PS-69 page (not reachable from the build environment).

### Open security findings

None open from hosted CodeQL on `a932cce`. Known design limits: `docs/limitations.md`.

### External approvals (not in scope of engineering completion)

SAG grading, IAF identity/PKI and interface specifications, relevant-environment definition,
independent security assessment, sponsor acceptance, hardware custody procurement, operational
authorisation, formal TRL assignment.

### Open pull request

PR #17 (draft) from this branch to `main`. Not to be merged automatically.

### HPSC package (13 October 2026)

Index: `docs/hpsc/EXECUTIVE_SUMMARY.md`. Deck `HPSC_DECK.md`, demos `demo-runbook.md` (Demos 1-4 via
`npm run demo`, `demo:trust-before-release`, `demo:documents`, `demo:monitoring`), Q&A
`evaluator-questions.md`, TRL `docs/trl/` (provisional TRL 4, guarded by `tests/trl-matrix.test.mjs`),
PS-69 matrix `PS69_COMPLIANCE.md`, funding `FUNDING_PLAN.md` (model `scripts/hpsc-budget.mjs`),
external approvals `EXTERNAL_APPROVALS.md`, claims C15-C22 in `CLAIMS_REGISTER.yaml`.
Founder inputs still required: team, traction, IP numbers, matching contribution, quotations,
PDB scope decision (₹1.62 cr estimate vs ₹3.0 cr for the full ₹1.5 cr grant), own release key.

### Next executable tasks

1. Founder: fill the FOUNDER fields, approve budget inputs, rebuild the offline bundle with the
   founder's release key, rehearse the four demonstrations on the presentation laptop.
2. Re-verify the iDEX rules (`research/hpsc/idex-grant-rules.md`) against the live official pages.
3. Re-retrieve `research/defence-comparison/sources.json` D04-D15 (needs network access to the
   original sources; not reachable from this environment).
4. Re-check `HPKE_PQ_EVALUATION.md` against the published `draft-ietf-hpke-pq` revision.
5. Engage an independent cryptographic assessor with `V3_COMPOSITION.md` (external).
6. Gateway readiness does not aggregate relay health (found in Demo 4); decide whether `/health/ready`
   should include it (changes container health semantics; needs an ADR).
