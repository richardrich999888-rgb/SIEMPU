# Current engineering state (single authoritative handover file)

## PS-69 technical review and monitoring build (7 November 2026)

Active branch: `codex/siepmu-ps69-trl5-review`, based on draft PR #31 at
`62291027db51d641b8215925190349501f342301` (tree `feaee50d08dda1e0b7a444ddd810c0b0bd6cc51f`).
Base push CI/Security: runs 42380383700 / 42380383730; PR CI/Security:
42380396989 / 42380397021. All nine CI and three Security jobs passed on both events.
The historical sections below are not this increment's results.

The user requested verified IAF requirements, implementation and assessment of TRL 5 gates.
Official PS-69 body pages 161-162 were retrieved and visually verified on 7 November.
R1-R12 remain valid paraphrases. Government TRL guidance permits realistic controlled
simulations; it does not supply the missing IAF evaluation profile. The status declaration
in docs/trl5/PS69_TECHNICAL_REVIEW.md keeps provisional TRL 4 and explicitly records why
complete-platform TRL 5 is not established. No requirement for new permission is inferred.

Implemented persistent signed threat-signal rules for R6, duplicate/restart suppression,
transactional counters/detections, bounded bucket/incident storage, retention of open or
investigating detections, and operator-pinned mTLS read/disposition endpoints. Eleven new
adverse tests exercise real authority events and transport. Fourteen initial targeted monitoring
tests passed. Database/source/rule binding was then added with an additional regression;
configuration changes or lost metadata refuse startup rather than reuse old counters.
A fixture-clock mismatch was corrected without relaxing production freshness checks.

The adversarial campaign includes the new tests in ADV-09; all nineteen gaps remain open.
The crypto inventory covers fourteen components and sixty reviewed source/test bindings.
The assessment now points to the current review and records D-T5-01 as historically fixed,
with its frozen retest retained. G05 plaintext integration, G18 startup root-cause and
external relevant-environment/identity/crypto/assessment inputs remain outstanding.

Locally tested first code candidate: `75a125f1123c6700ee64aa94b7ddf2aad8de6351`,
tree `3bd1c27a8da1111d3348cd68885fdd52b682ecd8`, Node 24.22.1 / Linux x64.
All ten native gates and 394 tests passed with no failures/skips; coverage was 97.87%
lines, 90.36% branches and 98.89% functions. E2E passed 3/3. The independent campaign
execution passed 204 tests across nine families, retaining 19 open gaps and no assigned
TRL. These observations predate the configuration-binding guard added after review.
The final publication revision must receive fresh validation and hosted evidence.

Next executable task: full validation and E2E on the final clean candidate, then publish
a stacked draft PR targeting codex/siepmu-iaf-adversarial-qualification and observe all
hosted jobs. The final PR description must retain local/published identities, exact run
URLs and artifact identities. No old pass is attributed to a later commit; no PR is merged.

## IAF adversarial qualification preparation (7 November 2026, India)

Active branch: `codex/siepmu-iaf-adversarial-qualification`, based on draft PR #30 at
`3244158f3d1f8fabe1b745b1588392f82884dfcf` (tree `d47db17a2da9e166bda93752c8e126e90e8cf861`).
That base passed all nine CI and three Security jobs on both push and PR runs:
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42376174481 and
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42376174472 (push),
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42376178306 and
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42376178329 (PR).
The sections below are historical snapshots, not current candidate results.

User requested a TRL 8 target, adverse testing and remaining IAF implementation work.
Implemented bounded adapter queueing (default 32), immutable queued requests and
freshness rechecks, authenticated readiness, failed-login local session clearing,
bounded process supervision and safe startup stage/reason diagnostics. Eleven new
adapter regressions cover overload, queue faults/mutation/expiry, readiness, failed
login/binding, actual process failure and expired-session behavior. Three runner tests
verify source/test/gap mapping and real pass/fail/skip handling.

`assurance/iaf/run.mjs` executes nine laboratory families, records exact commit/tree/
source fingerprint and hashed logs, and rejects incomplete or changed-source evidence.
`plan.json` maps all twelve requirements and nineteen open gaps. The qualification
report never self-assigns a TRL. `docs/trl/TRL8_QUALIFICATION.md` records proposed
qualification gates, independent adverse trials, owners and exit evidence. The current
provisional TRL 4 self-assessment and external qualification status remain unchanged.

Confirmed boundary: the synthetic DMS adapter receives plaintext and owns endpoint
keys; the source outbox stores plaintext requests. It cannot be treated as an untrusted
ciphertext-only connector. IAF-G05/Q17/IAF-06 retain the production placement/redesign
decision. The old ADAPTER_EXITED root cause remains open (IAF-G18); improved diagnostics
and later green runs alone do not establish its cause or resolution.

The cryptographic inventory has 14 components and now binds 55 reviewed source/test
files, including the adapter endpoint and its tests. No cryptographic algorithm was
replaced and no approved issuer, provider, hardware or military interface was invented.

Locally tested code candidate: `d8ec42c9c01e677e37288364e50e031aad6fa07f`,
tree `1fe3d704f8581bb7ff96037d6b7117b9f4c7ba7c`, Node 24.22.1 / Linux x64.
Full validation passed all ten gates and 384 tests, with no skips or failures;
coverage: 97.84% lines, 90.24% branches, 98.87% functions. All three E2E tests passed.
The separately executed adversarial campaign passed 194 tests across all nine families
(14, 28, 73, 15, 21, 8, 10, 18, 7), preserving all nineteen open gaps and no assigned TRL.
Actual evaluation packaging and separate verifier execution passed for 602 files,
manifest SHA-256 `9131a068d360c74177c45646b8d85193828c9536f3432991dca09627f2515e6d`.
These identities and digest refer only to the stated code candidate, not later commits.

This documentation follow-up must pass fresh full validation/e2e before publication.
The draft PR description is the final exact-head handover: local tested commit/tree,
published head, hosted run URLs, outcomes and artifacts. No PR is merged and no
operational deployment occurs. The campaign artifact has 30-day CI retention; retain
permitted assessment evidence through the sponsor-agreed process before it expires.

Next executable task: publish the validated candidate as a draft PR based on
`codex/siepmu-sag-evaluation`; observe all hosted jobs and record exact results in that
PR. Then resolve the nineteen gap owners/inputs and execute the sponsor-agreed
independent and operational qualification programme.

## SAG evaluation preparation candidate (2026-11-07)

**Active branch:** `codex/siepmu-sag-evaluation`, based on NEXORA head
`8aef8e4a222a98059761eb26edecb99bc6d8f67e`. Draft PR #29 remains the base;
its exact head passed all 9 CI and 3 Security jobs:
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42359818922 and
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42359818901.
The sections below are historical snapshots.

User requested SAG grading; it remains pending external evaluation. Implemented applicant preparation:
`assurance/sag/` packages a clean committed source, the matching application build,
native-validation report/logs and fresh SBOM. The offline verifier checks an independently
supplied manifest digest, exact file set, source hashes, reconstructed Git tree/commit,
build/source agreement and fixed ungraded status. No production secrets are collected;
ignored runtime files are excluded, known risky paths and links are rejected, and a
content/secret review remains required before controlled handover.

The crypto catalogue covers 14 application/laboratory/optional components and binds
49 implementation/test files; source changes require deliberate inventory review.
Twelve external input requests remain unresolved. References never self-authorise
an approval. `SAG_EVALUATION_DOSSIER.md` records boundaries, test mappings, gaps and
the public Service-sponsored evaluation route. No new cipher, agency interface or
hardware provider is invented. WP11 external grading remains EXTERNAL_BLOCKED.

**Locally tested code candidate:** `b92f0216f33bb0e220e80b98359f938e0c5421a8`,
tree `9d8ad00a056e8c55d8f786a3467e094568153c21`, Node 24.22.1 / Linux x64.
Full `npm run validate`: PASS, all ten gates and 370/370 tests, no skips;
coverage 97.76% lines, 90.11% branches, 99.05% functions. E2E: 3/3 PASS.
The ten package-specific tests pass. Actual packaging and separate CLI verification
pass for 594 payload files with manifest SHA-256
`1cd1deaae2d5e4e4d67f22be21e83d4a3255582c22da3289d31faefef4f014fc`.
All twelve scope inputs remain missing; both external decisions remain NOT_ESTABLISHED.
An initial full run rejected assurance-sensitive wording; pending status was made
explicit without changing the claims audit or suppressing any test. The single earlier
adapter-startup failure remains a separate, unconfirmed investigation item.

[Draft PR #30](https://github.com/richardrich999888-rgb/SIEMPU/pull/30) is based on
PR #29. First published code head `42fc1f2157083fae529390f7f6b36e80e7e59c44`
has the same tree as the local candidate above. Initial hosted observations:
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42375673520 (CI),
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42375673522 (Security).
The secret scanner rejected two source hashes under authentication filenames as
credential-shaped values. Both were verified as exact source-file SHA-256 digests.
The inventory now represents each binding as an explicit `{ sha256: ... }` object;
no scanner ignore, rule exception or reduced gate was added. The candidate commit
must be replaced on this owned branch so the PR range contains the corrected schema.
Fresh complete validation and hosted observations remain required for that revision.

Tracked dotfiles are preserved during CI artifact upload. An intermediate repeat run
exposed test discovery entering the generated source package and was stopped. Both
test commands now use source test globs. The tenth package regression preserves all
tracked `.test.mjs` files and proves copied artifact tests are excluded, with a
positive control showing the original discovery executes them. The 370-test pass
above was obtained with the generated package still present.

The draft PR description is the final hosted-check handover: exact current published
head, run URLs, observed conclusions and `sag-evaluation-candidate` artifact identity.
Local package digests belong only to their stated commit, not later revisions. Push
runs package the branch commit; PR runs may package GitHub's integration merge commit,
which is identified in each manifest. Do not substitute one identity for another.

**Next executable tasks:** verify full validation/e2e on the publication candidate;
observe hosted jobs and artifact creation; record exact results in the draft PR based
on `codex/siepmu-nexora-evidence`. SAG engagement remains pending the IAF sponsor,
agreed scope and proforma, authorised provider/interface, test environment and controlled
submission channel. This repository does not establish SAG grading, TRL advancement
or operational authorisation.

## NEXORA evidence integration candidate (2026-11-07)

**Active branch:** `codex/siepmu-nexora-evidence`, based on readiness head
`20ebb1c81f829520956999be693766652b754c5b`. PR #28 is the separate readiness change;
all 8 CI jobs and all 3 Security jobs passed on that exact head:
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42357753778 and
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42357753696.
The sections below this one are historical.

**Published code candidate:** `0173714f1f8643585586956f25dfd1421e270b74`.
[Draft PR #29](https://github.com/richardrich999888-rgb/SIEMPU/pull/29) targets PR #28's
branch. Its description is the hosted-check handover: exact current head, run URLs,
observed conclusions and remaining investigation items. This documentation follow-up
does not change the tested executable sources.

User authorized continuing the build after asking to wire VANIAN NEXORA for
authentication. Current implementation adds an optional offline operator bridge over
actual pinned `aip-nexora` at AIP revision `4ee39f359430277a48c34b957609104d3cf781f6`.
It verifies existing SIEPMU evidence under an independent authority key and retained
checkpoint, seals canonical source bytes using NEXORA's Merkle and signed-head
code, and verifies both layers offline. It never grants a login session or document
key. Personnel credential federation remains separate work. Snapshot profile and
operator instructions: `integrations/nexora/README.md`.

Local verification: Rust format/clippy PASS, seven bridge negative/conformance
tests PASS, cargo-audit 0.22.0 (`--deny warnings`) PASS for 99 dependencies. Actual
SIEPMU acceptance 5/5 PASS, including authority shutdown, preserved fresh device
challenge, denied NEXORA-as-session and revoked-recipient zero issuance. The pinned
upstream NEXORA suite also passed (185 tests, `cargo test --locked -p aip-nexora --tests`).
Full modified-tree validation PASS (all ten gates, 360/360 tests; 97.76% lines,
90.11% branches, 99.05% functions); e2e 3/3 PASS. Exact source digest and separate
Rust input hashes are recorded in `nexora-integration-validation.json`. No hosted
result on this new branch is yet established. The initial fixture epoch-type error
was corrected without changing authority behavior or reducing any negative assertion.

The first full run failed in the existing document-system test with `ADAPTER_EXITED`.
The isolated five-test file and subsequent full run passed without source changes.
The child error was not retained by that helper, so the root cause remains unconfirmed;
this is recorded as an investigation item, not a resolved defect or a skipped gate.

The optional dependency graph is isolated from the application and native reference
verifier. Upstream AIP crates retain their declared proprietary licence; no upstream
source is copied or relicensed. Docker and offline release exclusion is explicit.

**Next executable tasks:** observe all hosted checks on PR #29 and resolve failures;
retain the exact head and run URLs in that PR. If adapter startup fails again, capture
the child's redacted error and diagnose before accepting a rerun. Personnel credential
federation then needs an explicit enrollment/issuer contract, trust roots, key lifecycle,
fresh challenge binding and revocation rules. No operational deployment or TRL advancement
is claimed.

## PS-69 mission readiness candidate (2026-11-07)

**Active branch:** `codex/siepmu-ps69-readiness`, based on sovereign research head
`09b18103268603b35a9801b2679fa589bf54160c`. Older sections below are historical.
User-confirmed scope: IAF DISC-14 PS-69 secure exchange of sensitive/confidential
information between authorized personnel over the public Internet. Hosting is a
service delivery model; this is not consumer SaaS or public self-registration.

Implemented: protected admin/auditor mission-readiness API and UI, unsigned snapshot
export, configuration observations, crypto policy/inventory, custody state and
pending qualification evidence. Gateway readiness now checks the authority database
and ciphertext relay; actual outage/restart and malformed-response cases are tested.
Immutable browser shell bumped to v8. ADR-015 records the availability semantics.

Local modified-tree verification (Node 24.22.1, Linux x64): `npm run validate` PASS,
360/360 tests, 97.76% lines, 90.13% branches, 99.05% functions; all ten validation
gates PASS. `npm run test:e2e` 3/3 PASS; new readiness tests 6/6 PASS; research record
consistency PASS. Exact tested source digest and runtime/test hashes are recorded in
`docs/engineering/ps69-readiness-validation.json`; do not attribute these runs to the
unchanged historical base SHA. Only handover documentation was added after the run.

Browser run BLOCKED: local Playwright Chromium executable missing; assertions were
not reached. Browser checks for the new view, live dependency check and download
were added to the existing runner. Hosted CI, browser, container and operational
deployment are not established by the local results. No TRL advancement is claimed.

**Hosted observation on candidate `188be1612b1b955910f805771f4a3668bbf664aa`:**
[CI run 42355976435](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42355976435)
passed the browser and PQC jobs; [Security run 42355976393](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42355976393)
passed CodeQL, secret scanning and dependency/security regression. Native CI found
one ambiguous qualification-plan line in the tracked-file claims audit; it now
explicitly says the SAG process is pending. The initial local claims scan did not
include that then-untracked document; tracked-file checks were rerun after correction.
Formal CI stopped before model execution because the current upstream v1.8.0 JAR
published on 6 November does not match the recorded checksum. The strict SHA-256 pin
is updated to the independently downloaded asset's hash, which matches both the
official GitHub asset digest and the release's SHA-1. The checks are not disabled. Local formal validation with the verified JAR passed:
3,837,180 states for the faithful model; both deliberately broken models produced
their expected invariant violations.
Official asset: `https://api.github.com/repos/tlaplus/tlaplus/releases/assets/718777374`;
SHA-256: `e1f11b75c4b5bc4478ba0ac5cb6ae28e40a01b0016bc33e0aa97da22dfdbcd7f`.
PR: https://github.com/richardrich999888-rgb/SIEMPU/pull/28 (draft).

**Dependency follow-up after `76fb20e348b9f9b66ecad16e17729f2f8bd6691b`:**
CI run 42356230201 passed native, browser, PQC, formal, relevant-env and testbed.
Security run 42356230189 passed all three jobs. Two release gates failed:
RustSec RUSTSEC-2026-0387 in crypto-bigint 0.5.5, and image HIGH findings in musl/zlib.
The next candidate upgrades p256/sha2 and their locked dependencies, adapts only the
upstream point-parser API names, and pins the refreshed official Node/Alpine image.
Rust 1.97.0 local results on the modified tree: format/clippy PASS, 26 unit + 3 vector
suites PASS, Node/Rust differential 3/3 PASS including 400 mutations, both 18-step
mission profiles PASS, cargo-audit 0.22.0 with `--deny warnings` PASS.
Full modified-tree validation also PASS (360/360), acceptance 3/3 PASS, engineering PASS,
network/independent-services 3/3 PASS. Exact digest/hashes and environment are in
`ps69-dependency-validation.json`. Container execution remains hosted-only. No scanner
exceptions were introduced.

Hosted `b2e1785154547d05a70bfea4419e4ad5613517f5` caught a Clippy rule newly
applicable at the raised Rust minimum (1.87): the CLI's odd argument-count check.
The equivalent standard `is_multiple_of` predicate replaces manual modulo. The
initial local lint preceded the minimum-version change. Follow-up local format,
Clippy, 26 Rust unit tests and 3 vector suites PASS with the final manifest;
full validation 360/360 and acceptance 3/3 PASS on modified source digest
`604326cff0bbc3452e3da15edd59cc7f7f2870aa57adc1a225b74b86c6355b14`.
Rust CLI SHA-256: `433d79fb2b938129052c513d2bd61117efa73255e7ff270f4fc5e129bcdcd623`.
The native-validation source digest covers the JavaScript source; the CLI hash binds
the separate Rust checks. Only this handover update followed that run. No lint
suppression is used.
Hosted container job 128358817829 on `b2e1785` passed build, actual exchange,
HIGH/CRITICAL scan and SBOM generation; Security run 42357429642 passed all jobs.
The final CLI-fix candidate still requires its own hosted run; consult PR #28 for
exact candidate SHA and run results rather than carrying older passes forward.

**NEXORA clarification:** user asked why VANIAN NEXORA cannot provide authentication.
Source inspected at AIP `4ee39f359430277a48c34b957609104d3cf781f6` establishes a portable
commitment/proof verifier. The proposed SIEPMU integration and authentication boundary
are recorded in `docs/decisions/NEXORA_INTEGRATION_BOUNDARY.md`; no NEXORA login or
cross-format compatibility is implemented or claimed by this candidate.

**Next executable tasks:** finish validation and hosted checks for the dependency
candidate, then execute sponsor-agreed qualification work in
`docs/trl/PS69_QUALIFICATION_PLAN.md`. Keep the draft unmerged for review. No approved
IAF deployment target, PKI/provider interface or external qualification evidence was
supplied. Provisional TRL 4 remains unchanged.

**Review date:** 2026-10-10. **Active branch:** `claude/siepmu-sovereign-research-w886dv` (see first section). Previous active branch: `claude/siepmu-trl5-24h-validation`, created from PR #18's head
`4190797`, which contains PR #17's head `12989fb`. Not merged into `main`. The sections below this sprint's section
describe earlier branches and are kept for provenance.
Update this file from executed results whenever major work completes, and before ending a session.
Never copy a result forward to a new SHA.

## Sovereign research branch `claude/siepmu-sovereign-research-w886dv` (2026-10-10)

Based on `assurance/kat-and-gap-2026-10` `86744a8` (pushed; it contains PR #19 `2b3f9ab`). Index:
`docs/research/sovereign/README.md`. Evidence: `docs/research/sovereign/10-EVIDENCE.md`.

- **D-T5-01 fixed in code** (`d879b4a`, ADR-014): incremental custody protocol v2. Per-authorisation cost
  3.4–4.1 ms flat to 250,000 records (full chain: 18.2 s at 100,000). Three-namespace matrix re-run at
  `1a0218d`: 33/33; T8.1 1.56 → 5.93 exchanges/s; custodian CPU 72.3 % → 17.1 %. TRL decision unchanged (TRL 4).
- **CodeQL `js/file-system-race`** that failed hosted Security run 38046629878 on `86744a8`: fixed on the base by `f62fd04` (merged here; this branch's equivalent `50303b5` superseded, its regression tests kept). Hosted CI on PR #20 head `81b64e0`: all 12 checks green incl. CodeQL.
- Rust range verifier + SIEPMU-EVIDENCE-RANGE-v1 (25 vectors). Sovereignty matrix with guard test.
- Local results on `4975a61`: `npm run validate` PASS (353/353, 97.68 % lines), `test:security` 140/140,
  `test:engineering` 39/39, `test:e2e` 3/3, `test:native` 3/3, Rust 26 + 3, pqc-lab 7/7, `test:mission` PASS,
  `demo:hpsc` PASS. `formal:check` PASS (model unchanged). Not run: browser, container, hosted CI.
- The repository is **public**: candidate patent claims are not committed (see `IP_AND_ORIGINALITY.md`).

**Open:** hosted CI/Security on this branch; control authority is now the bottleneck (85 % CPU in T8.1):
incremental authorization-state digest (L-1), one authorisation per request (needs TLA+ change), TLS reuse.

**Next executable task:** confirm hosted CI and Security green on this branch's PR, then implement the
incremental authorization-state digest with negative tests and re-run `trl5:validate`.

## Crypto-assurance branch `assurance/kat-and-gap-2026-10` (pushed; head `86744a8`)

Branched from `2b3f9ab` (PR #19 head). Commits `f6bd66d`..`e7a0a1f`. Not pushed: pushing awaits
the owner's explicit approval.

- KAT harness `assurance/kat/` (`npm run kat`): 9/9 vendored vector cases and 21/21 failure-mode
  checks pass; SHA-256, AES-256-GCM, HKDF and ECDSA are NOT-RUN until NIST files are placed under
  `./vectors/`; report `docs/assurance/kat-conformance.md` (generated at `f6bd66d`).
- Gap analysis `docs/assurance/fips-sag-gap-analysis.md` (planned tasks A-01..A-15).
- Claims audit `docs/assurance/claims-audit.md` (generated at `deb6f0f`, 587 hits, 5 proposed
  corrections not applied) and CI gate `scripts/check-claims.sh` (wired into the native job).
- D-T5-01 baseline `docs/assurance/d-t5-01-baseline.md` (generated at `edfc92d`).
- Local results on `e7a0a1f`: `npm test` 315/315 (289 before), `npm run validate` PASS,
  `test:security` 124/124, `cargo test --locked --release` (native/) 28/28 before and after.

**Next executable task on this branch:** place NIST CAVP SHA-256, GCM and ECDSA SigVer files and
RFC 5869 HKDF cases under `./vectors/`, re-run `npm run kat`, and regenerate the report.

## TRL 5 advancement sprint (branch `claude/siepmu-trl5-24h-validation`)

| SHA       | Content                                                                             | Result                                                                                                                                                     |
| --------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `4190797` | Phase A baseline (PR #18 head)                                                      | Local: validate PASS, `test:security` 123/123, `test:e2e` 3/3, `test:native` 3/3, `test:mission` PASS, `demo:hpsc` PASS                                    |
| `8dda0a1` | Acceptance matrix declared **before** execution                                     | CI 37795100462 PASS; Security 37795100418 PASS                                                                                                             |
| `1bdd79e` | Three-namespace harness (`deployment/relevant-env/`, `scripts/trl5-validation.mjs`) | Local 33/33 (first clean run)                                                                                                                              |
| `e05e1c8` | Relay-down 503 fix (P-1); harness assertions tightened                              | Local 33/33 clean                                                                                                                                          |
| `1348b86` | CI `relevant-env` job (kernel netem); scaling measurements                          | **Local 33/33 clean** (evidence frozen in `docs/trl5/evidence/1348b86/`); **CI 37800666173 PASS, all 8 jobs**, `relevant-env` 35/35 incl. 1 % and 3 % loss |

Further local checks on the current tree: `npm run validate` PASS (289 tests, 97.54 % lines); `test:security` 124/124;
`formal:check` faithful 3,837,180 states, no error, both mutants violate; `test:browser:isolated` PASS.

**Decision:** TRL 4 retained, with the TRL 5 advancement tests completed and gates outstanding
(`docs/trl5/READINESS_DECISION.md`). The guard `tests/trl-matrix.test.mjs` is unchanged, and it now
also verifies the frozen evidence byte for byte.

**Open defects:**

- **D-T5-01, custody scaling.** The recovery guard ships and re-verifies the full evidence chain
  twice per request, serialised: 0.144 ms per record per authorisation. Throughput is about
  1.6 exchanges/s. The fix (incremental checkpoints) needs an ADR and negative tests for rollback,
  fork, gap, reorder and stale anchor.
- **E-1.** Profiles are provisioned by the conductor, not by per-device enrolment.
- **E-2.** The hosts share one kernel.

**Next executable task:** write the ADR for incremental custody checkpoints, then implement it in
`services/evidence/custody.mjs`, `services/control/core.mjs dispatch` and `apps/verifier` (partial
chain from an anchored head). Then re-run `node scripts/custody-scaling.mjs` and
`sudo npm run trl5:validate`, and require a flat per-request cost.

**Environment notes for this container:**

- No KVM or Docker daemon. iproute2 was installed with apt.
- Local kernel has no `sch_netem`; TBF is available.
- `/trl5-dbg` and `/run.log` at the file-system root are leftovers from a debug run (an empty
  shell variable). They are outside the repository and safe to delete.

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
