# Current engineering state (single authoritative handover file)

## P0 044 control/relay recovery bounds (11 November 2026 IST)

Branch `codex/p0-044-recovery-bounds`, base PR #43 `07ab59762f5a086152835709ea5df60d07890e74`.
Baseline push/PR CI and Security runs 42785812150/42786747805 and
42785812191/42786747888 were inspected as successful. Baseline recovery was freshly rerun:
4 passed. New negative tests reproduced six inconsistent control/relay snapshots being published.
These are baseline observations, not final-candidate results.

Restore now verifies staged relay ciphertext and control references before publication, using
existing envelope integrity checks. The maintenance archive has explicit input/decoded/metadata
limits. No deletion, authority cache, changed crypto, startup activation or dependency is added.
See `docs/qualification/P0-044_RECOVERY_STORES.md` for the finding, compatibility constraints,
reproduction commands and retained failed attempts. A clean-source growth drill records
control/relay backup and restore costs and recipient integrity at 0/20/60 objects.

Freeze and execute the full native/E2E/adversarial gates; bind results and hosted checks to the
final published SHA in the generated report and PR. Do not transfer earlier counts.
Next: a reviewed streaming backup format, bounded retention design and all-service recovery
with independent current custody and representative hosts. All 19 gaps remain open/partial.
Provisional TRL 4 remains unchanged. No production merge or deployment.

SAG grading is not established.

TRL 5 qualification and IAF operational approval are not established.

## P0 043 checkpoint signing cost (10 November 2026 IST)

Base: PR #42 `92353e1224e3eedb35db9d7420b6820a2574632a`; its four observed
push/PR CI/Security runs succeeded. The unchanged migration suite was freshly rerun:
113 passed. These are baseline observations, not validation of this increment.

Branch `codex/p0-043-authority-assurance` removes discarded checkpoint signatures from
local state/seal/lease comparisons through a fresh SQLite head lookup. Exported
checkpoints, seals and custody exchanges remain signed. No cache, migration, threshold
or dependency change. Four new rollback/custody/signature regressions and a source-bound
matched comparison accompany the change. See `docs/qualification/P0-043_CHECKPOINT_COST.md`
for the measurement protocol, retained first-run fixture failure and trust boundary.

Freeze and validate the exact revision before publishing results. The generated report
and PR bind final test counts, benchmark samples and hosted checks; do not transfer
PR #42's results to this source. Follow-on priorities remain full-state growth/retention,
full-system recovery and representative independent-host evaluation. All 19 gaps remain
open or partial. Provisional TRL 4 is unchanged. No merge, activation or deployment.

SAG grading is not established.

TRL 5 qualification and IAF operational approval are not established.

## Candidate verification follow-up (10 November 2026 IST)

Active draft PR: https://github.com/richardrich999888-rgb/SIEMPU/pull/42.
Branch `codex/guarded-legacy-migration`, still based on unmerged PR #41. No comments
or inline review threads were present when this follow-up started. Starting published
head `bad91af7c7ebec490719331ca375673cdc2ef651`, tree
`0e254aade52d399acd6dc5f7e842f4c50cb8fbfa`, matches local validation commit
`c0beb0424268f569c16cddbf9d66a3e315f5c6a3` exactly. That predecessor passed all ten
native gates/571 tests, 3 E2E, 359 adversarial tests and all nine CI/three Security jobs:
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42689294181
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42689294135
These are predecessor results, not proof of the follow-up source.

The procedure's independent candidate check is now executable with
`node scripts/legacy-migration.mjs verify REQUEST RETAINED_PLAN_SHA256`. It requires
original independent evidence and a separately retained reviewed plan pin, uses public
signing keys only, and validates the receipt, approval, exact successor event/seal,
all preserved logical rows and the precise writer handover request. Source and candidate
remain untouched; only private temporary copies are opened. Success means
`VERIFIED_QUARANTINED`, never live custody validation or activation. Expired review,
missing evidence, extra files/sidecars and changed state are refused. The builder also
checks unchanged non-authorization rows before publication. Core runtime/custody code
and SQL migrations remain unchanged; deployment package exclusions still apply.

New adversarial tests grant a synthetic attacker the authority signing key but retain
independent review/snapshot pins, inject metadata/session/schema/event changes and
handover substitution, and exercise uncertain publication after parent fsync failure.
The real verifier CLI runs without the authority private-key file. Development failures
(106/107 then 111/113) were error-precedence/message assertions; both are documented in
the procedure, with no negative test removed. Freeze the new source and execute all
native/E2E/adversarial gates before publication; the final PR body and generated reports
bind the tested source/tree and observed hosted run IDs. Run `npm run test:legacy-migration`
for focused reproduction. Do not reuse the predecessor's results for changed source.

Next boundary: a separately authorized operational recovery/activation design still
requires independently current policy/custody, complete service recovery and a defined
relevant environment. No production migration, merge or deployment is performed.
Provisional TRL 4 remains unchanged. SAG grading is not established.
TRL 5 qualification and IAF operational approval are not established.

## Guarded legacy migration prototype (10 November 2026 IST)

Branch `codex/guarded-legacy-migration`, stacked on PR #41 head
`64cce099f1729b899c6da702c85d438c22162a06`; PR #40 inspected at `62b8e6634cc6ba2a634b3170654fc21a34c8c0b4`.
The old limited custody digest cannot establish full authorization state. The explicit
synthetic-only builder requires the exact independently retained original backup manifest/pin,
matching checkpoint and old custody receipt, policy agreement, and a separate reviewer-signed
approval. It creates a new candidate directory and signed migration event/seal; it never writes
source databases, advances custody, activates services or deploys a migration. Existing default
restore/quarantine remains strict. Fresh writer handover is a separate exact-anchor/generation CAS.

Eligibility, private input schemas, operator steps, failure semantics and impossible cases:
`docs/qualification/GUARDED_LEGACY_MIGRATION.md`. Execute `npm run test:legacy-migration`.
Source is excluded from application/offline release packages. No new dependency or applied SQL
migration changed. Supported inputs are exact schema 001–006 snapshots or schema 007 with empty
seal table, classical policy only; more general legacy formats remain refused.

Development focused regression passed 85/85 before expanded rollback cases.
Frozen implementation `0793fb1108f59f7cf0c4d4630289ef88fbbd475d` ran 571 tests (569 pass,
2 fail): exact crypto-inventory expectations and line-scoped qualification wording needed
updates. All 68 migration tests and the other nine gates passed. The follow-up changes only
that exact inventory assertion and documentation; no runtime behavior or gate is weakened. The initial harness
failures and their causes are retained in the procedure document. Freeze the final source and
run all local gates/E2E/adversarial tests before publication. The new draft PR records final
commit, observed counts and hosted CI/Security URLs. Do not treat PR #41's older 503/291 results
as validation of this branch. The generated report binds the exact tested SHA/tree/source digest.
Next executable task: review/reproduce this prototype and its independent-evidence assumptions;
do not apply it to production or bypass missing evidence. Provisional TRL 4 remains unchanged.
SAG grading, TRL 5 qualification and IAF operational approval are not established.

## PR #39 public-interface assurance iteration (8 November 2026)

Active draft PR: https://github.com/richardrich999888-rgb/SIEMPU/pull/39,
branch `codex/india-dpi-iudx-contract-tests`, stacked on unmerged PR #38.
Inspected starting SHA: `8ba056e4b00eea5696c2b5880dd8e2ba26c7782c`.
Its eight IUDX tests passed; formatting of its three new files was the reproducible blocker.
Push/PR CI 42483937839 / 42483941780 failed native formatting and skipped dependent jobs;
both Security workflows and both relevant-env jobs passed. No latest-head claims failure found.

The predecessor entry below predates the completed T8.1 correction. Final continuity base
`5f8c6848f6ba0bcf7ba81eb4be90c3e9c9dcc92a` passed 457 local tests/all ten gates,
3 E2E and 248 adversarial cases. Final push/PR CI 42483369153 / 42483374555 passed
all nine jobs; both 35-case matrices passed, with 188 sent/delivered and zero refusals in T8.1.
The 650 ms offered-load profile retains the 500-request/session limiter and zero-refusal oracle.
This resolves that specific load-profile failure, not maximum capacity or sponsor scale.

This iteration fixes formatting, bounds/validates the DX proxy response, removes the text fallback,
adds deadlines/cancellation and an opt-in TLS 1.3 literal-loopback reader. External claims remain
untrusted and cannot grant local identity/authority. No production import route or live government
transaction exists. New adversarial cases and a synthetic policy-release comparison feed a
clean-tree evidence runner, CI artifact, reviewed crypto inventory and updated requirements mapping.
No runtime dependencies added. Open PR metadata/ancestry inventory covers 31 PRs; no merge.

Current candidate identity must be read from Git and the generated report, not inferred from this
pre-freeze prose: `node scripts/interop-assurance.mjs artifacts/NEW_DIRECTORY` binds the commit,
tree, whole-source index, test output and raw measurements, and rejects source drift. Full
`npm run validate` and `npm run test:e2e` are required on the clean commit before ref publication.
Final observed run URLs, exact source identity, counts and any unresolved CI failures are recorded
in PR #39's body; hosted PR merge checkouts must be matched by tree as well as head SHA.

Report and reproduction: `docs/interop/GOVERNMENT_INTEROPERABILITY_AND_DEFENCE_ASSURANCE.md`
and `docs/interop/INDIA_DPI_TESTBED.md`. Both current and earlier failures retain their revision.
All nineteen qualification gaps remain open, including G18's historical undiagnosed adapter exit.
System self-assessment stays provisional TRL 4. No SAG grading is established.
Operational authorization is not established. Public interfaces need owner-permitted test credentials/contracts and a relevant
use case; military identity, crypto module, representative environment and grading need sponsor input.

Next executable handover: verify the exact PR #39 head and latest CI/Security results, retrieve
`government-interop-assurance` and the separate evaluation/native/network artifacts for that head,
then independently reproduce. Remaining design work includes single-writer failover/fencing,
complete DR, managed fleet/browser controls and agreed communication/scale requirements. Do not
merge, deploy, infer government access, or mark TRL advancement from software tests.

## Continuity acceptance and load-profile follow-up (8 November 2026)

Active draft PR #38: https://github.com/richardrich999888-rgb/SIEMPU/pull/38,
branch `codex/siepmu-continuity-mechanisms`, stacked on unmerged PR #37.
Last fully passing local source: `421863693183aac90a302cfb3f2ad93efdaf35d2`, tree
`e47056cdcc0bcb45e3fe976da3814449dc8e6a98`: all ten gates, 455 tests, 3 E2E,
247 adversarial cases across nine families, and five standalone offline tests.

That source passed all nine push CI jobs and both Security and token workflows.
Push CI: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42481838396.
The combined native run passed one real isolation probe, three ClamAV smoke cases and
all eight managed-companion scenarios (nine TAP tests including the parent):
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42481838366.
Downloaded native artifacts were SHA-256 checked; the hosted and local 27-file packages
share manifest digest `7f8281bcb66655e1404c7cb8ca66a84b378ed31a745655bda91352855bb99ecb`.
Exact reports and artifact identities: `docs/testing/continuity-acceptance-2026-11-08.json`.

PR CI run https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42481879771
passed eight jobs but failed relevant-env T8.1: all 496 accepted objects were delivered
without mismatch; all 287 refused requests were HTTP 429 RATE_LIMITED in control.log.
Unpaced workers exceeded the existing 500 protected requests/session/fixed-minute limit.
The push run crossing a different minute boundary passed; it does not erase this failure.

The follow-up declares one exchange start per 650 ms/session, shared by sender workers,
and paces recipients too. It records refusal codes, retains explicit unpaced investigation
mode and leaves the authority limit and zero-refusal acceptance criterion unchanged.
A direct protected-route regression covers the 500-request ceiling, per-session isolation,
window reset and revocation. This is an offered-load reliability measurement; sponsor scale
and maximum-throughput requirements remain open. Runtime continuity mechanisms and native
integrations are unchanged by this follow-up; the test/deployment source digest changes.

Next: freeze this follow-up, run full validation/E2E/adversarial checks before updating the
branch, then observe fresh hosted CI/Security/token results. Record the final SHA and run URLs
in PR #38. Do not attribute the initial hosted result to the follow-up without its identity.
All nineteen qualification gaps remain open; G09 is PARTIAL_LAB. Provisional TRL4 is unchanged.
SAG grading is not established. Operational authorization is not established. No merge or deployment.

## Continuity mechanisms candidate (8 November 2026)

Active branch: `codex/siepmu-continuity-mechanisms`, based on PR #37 head
`fee0ffd52e15fa9a175944a3c599d05e8ec7e8a0`. Base passed 440 tests/all ten gates,
3 E2E, 233 adversarial cases, all nine CI jobs and three Security jobs on both events.
Base exact push CI: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42472021719.
Base combined native run attempt 2 passed the extracted companion (six scenarios/7 TAP tests),
plus isolation and ClamAV smoke: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42472021718.
Those results resolve the download-only blockers in the historical entries below.

This candidate implements ADR-016: live-session rotation, an optional encrypted managed
outbox, checkpoint-aware restore CLI and signed durable monitoring cursors/pending batches.
Fresh MFA and device proof are required for renewal; revoked/expired/ambiguous sessions
never trigger automatic login. The v2 connector has no personnel credentials. Outbox
submission still uses current authority admission; stale objects are held, never resealed.
Monitoring never skips rejected, missing or expired source records to claim delivery.

The initial frozen candidate `6c941d56783fdd4e6054e2b6ccbbdf331b146a70` ran 455 tests;
one claims-wording guard failed, and the separate formatting gate also failed. Behavioral
tests and the remaining eight gates passed. Follow-up changes clarify the status wording,
correct formatting and document the new exporter; no test or gate is weakened.
Complete exact-candidate validation and native acceptance still need to be recorded
in the candidate PR. Freeze the source, refresh crypto inventory bindings, validate all gates,
E2E and the adversarial suite, then rebuild and independently verify the companion and
observe hosted CI/Security/token/combined native runs. No previous result proves this head.

G09 advances to PARTIAL_LAB only. All nineteen qualification gaps remain open. Source retention,
complete multi-service backup, failover/fencing, hardware/fleet identity, token lifecycle,
legacy-store migration, browser enforcement and large-file transport remain follow-on work.
G18's historical startup failure remains unresolved. Provisional TRL4 is unchanged.
SAG grading is not established. Operational authorization is not established. No merge or deployment.

## Companion validation follow-up (8 November 2026)

Draft PR #37: https://github.com/richardrich999888-rgb/SIEMPU/pull/37. Initial candidate
`7f4ba06b303637ab465379054bd5d9013084d88c` passed all ten local gates (440 tests),
3 HTTP E2E and five extracted-package offline tests. Its 25-payload-file companion verified
against manifest `6279f66afbc1e3f1e6634033c6184ccebaaaa38304239f235b540ce4ba20e42f`.
Hosted CI's native job also passed, but CodeQL flagged an unanchored expression in the package
test's filename exclusion assertion. The follow-up uses explicit substring/suffix checks
with the same rejection behavior; it does not suppress the finding or alter a security gate.

The combined native run stopped before testing because the pinned engine download returned
HTTP 504. Both token jobs ran native tests but were blocked installing the dependency scanner.
The native engine/source downloads now have bounded retries; their exact hashes and all
isolation/database checks remain mandatory. FreshClam's single update attempt is unchanged.
Base run: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42471223555.
Record the follow-up's exact validation, package identity and hosted outcomes in PR #37.
No combined native PASS is established by the initial candidate's offline results.
SAG grading is not established. Provisional TRL4; all nineteen qualification gaps remain open.

## Separate managed endpoint package (8 November 2026)

Active branch: `codex/siepmu-managed-endpoint-pack`, based on PR #36 head
`d77440ce36456fa4cfc1c6fb5dd1edb865e39ae0`. The base passed all ten local gates,
432 tests, 3 E2E and 233 adversarial cases. Its final PR CI, Security and token jobs passed;
its separate push formal download remained blocked by HTTP 504. Base evidence and exact
run references: https://github.com/richardrich999888-rgb/SIEMPU/pull/36.

The new optional package under `integrations/managed-endpoint/` composes the existing token,
isolated file inspection and TLS SDK interfaces into one frozen endpoint facade. Public
configuration is separate from credentials/PIN input. It requires isolated scanner preflight
and existing pinned token objects; send/receive enforce file inspection. It exposes no raw
client or uninspected-submit method. Local closure invalidates handles, not persistent token
objects or server sessions. A persistent offline outbox is not included in this compact API.

The source-only builder produces a standalone package with an explicit import/dependency
allowlist, notices and an independently runnable integrity verifier. Native tools, credentials
and host policy are separately provisioned. Root npm runtime dependencies remain zero.
The combined native workflow tests the extracted package against actual SoftHSM, isolated
ClamAV and TLS 1.3 with an in-process synthetic authority and test relay. A shared local action
prepares the existing pinned SoftHSM/Python environment for both native workflows.

Freeze and validate the exact candidate before publishing. The companion PR must record
local validation/E2E, package digest, extracted-package tests, combined native outcome and
hosted CI/Security results. Planned tests are not passing evidence. The base's results do not
prove the new package. No merge or deployment is performed here.
SAG grading is not established. Provisional TRL4; all nineteen qualification gaps remain open.

## CI tool acquisition follow-up (8 November 2026)

Draft PR #36 remains the active candidate. Evidence head
`c65fa4ccffe72ae3b34d5e29b199ed51b35a6da4` passed all ten local gates (432 tests),
3 E2E, 233 adversarial cases across nine families, both hosted Security/token workflows,
and the browser, Rust, PQC, Nexora, relevant-environment and testbed jobs. The PR formal
model check passed on its matching merge tree. Repeated push formal downloads returned
HTTP 504; container jobs stopped in the upstream Trivy installer before its scanner ran.
Run references: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42464566040
and https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42464568928.

This follow-up changes CI tool acquisition only: bounded curl retries for the existing
TLA+ pin and a direct, SHA-256-pinned Trivy 0.69.3 Linux x64 archive, installed once per
job. The archive digest was verified against the upstream release API asset metadata.
Both container scans and the optional Python scan use that binary; no mutable installer
is fetched. Hash mismatches and vulnerability findings still fail the gates. Runtime,
provider and scanner code are unchanged, but the validation source digest changes because
it includes workflows. Freeze and validate this exact follow-up, run E2E and the adversarial
suite, rebuild/verify the candidate bundle, then record final hosted outcomes in PR #36.

The prior hosted 653-file candidate was downloaded and independently verified against
manifest `109c0aada96b1ab51539376bad804c02749720751fd8a2eac149ed4c8eece81a` and artifact
ZIP `e433359096ca3c3b2be5ee378ec5259fffb455df8011647a43a9f8e2c860c121`; it belongs only
to `c65fa4c`. The final follow-up requires a new bundle. Native parser evidence remains
bound to `f9eac4d` below; exact runtime-source equivalence must be retained when citing it.
SAG grading is not established. Provisional TRL4; all nineteen qualification gaps remain open.

## Native endpoint integrations accepted in the lab (8 November 2026)

Active draft: https://github.com/richardrich999888-rgb/SIEMPU/pull/36,
`codex/siepmu-evaluation-integrations`, stacked on unmerged PR #35. Executed native code
commit `f9eac4d6b6a8726795e46660dcc15496da00eb48`, tree
`e058810eb2562a000991a5b23a6f96e6c97bf1b2`, passed local all-ten-gate validation
(432 tests) and 3 E2E tests on Node 24.22.1/Linux x64.

Hosted native results on that exact code:

- PKCS11: 9/9 tests plus a complete two-package high/critical dependency scan passed;
  https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42463858775.
- Isolated ClamAV: 1/1 real namespace probe plus 3/3 actual engine smoke tests passed;
  https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42463858700.
- Both native artifact ZIPs were downloaded and SHA-256 verified. Exact reports,
  inventories, hashes, counts and dependency-scan data are preserved in
  `docs/testing/endpoint-native-acceptance-2026-11-08.json`.

The host exception is limited to one root-owned launcher. The recorded global Ubuntu
userns restriction remained 1; the parser could not create further user namespaces.
The probe correction tests creating a new file on a read-only mount instead of opening
the running executable, which confounds the check with executable text protection.

This evidence/documentation follow-up leaves executable source unchanged. Validate its
final exact commit and E2E before publishing. Final push/PR CI, Security, token acceptance,
adversarial result and final bundle identity are recorded in PR #36. Native scanner evidence
belongs to the code commit above; preserve that identity and verify code equivalence.
The candidate remains ungraded, provisional TRL4; all nineteen qualification gaps are open.
Hardware custody, managed/browser enforcement, production failover, service-identity
lifecycle, representative corpus and sponsor/evaluator acceptance are not established.

## Native integration host follow-up (8 November 2026)

Draft PR #36: https://github.com/richardrich999888-rgb/SIEMPU/pull/36. Initial head
`a2eaeefcb68cc594b0fc369270915d334c577af4` passed all ten local gates / 432 tests,
3 E2E, 9 token tests, 7 separate PQC tests and 233 adversarial cases. An ungraded
source-bound evaluation bundle was built and independently verified offline. Its digest
was `eca7804f1c5c8f5235c38d258c63f120fb2fa78bfd97425adb1710d75e950c43`.

Head `2fb909e9ae3d785ebd9c320015368198bbe70650` also passed 432 local tests, 3 E2E
and 9 token tests. Native PKCS11 CI passed after fixing the SoftHSM configuration/state
install directories to stay within the private runner workspace:
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42462812497.
The native scanner probe still refused isolation: Ubuntu blocked network-namespace
setup capabilities (`RTM_NEWADDR`). The follow-up grants only the dedicated root-owned
launcher an AppArmor userns exception and explicitly prevents nested user namespaces
inside the parser. It does not disable the global host restriction or remove parser
isolation. Final exact-head local/hosted results and bundle identity belong in PR #36;
prior passes must not be attributed to the follow-up. No merge or deployment occurred.

## Endpoint integration evaluation candidate (8 November 2026)

Active branch: `codex/siepmu-evaluation-integrations`, based on PR #35 exact head
`48ecd4bc2268fbe4e759782e7e685ba367946a9d`. New optional integrations: real PKCS11
signing/ECDH through pinned python-pkcs11/asn1crypto and a SoftHSM 2.7.0 laboratory gate;
Bubblewrap 0.13.1/prlimit scanner isolation with strict runtime inventory and a native
boundary probe. Outbound ephemeral ECDH keys are no longer exported as private JWK.
Details and limits: `docs/engineering/INTEGRATION_STATUS.md` and `integrations/*/README.md`.

Development execution: nine native token tests passed, including managed endpoint device
enrollment/proof and policy-authorized object release; eighteen targeted core/scanner
regressions passed. These are development results, not the final candidate release gate.
Freeze and validate the exact commit before publishing its branch ref. Record final local
validation/E2E, both push/PR CI and Security, PKCS11 and isolated ClamAV workflow outcomes
in the candidate PR. Never report native isolation PASS from contract doubles. The local
container cannot create the required namespace; hosted real isolation must be observed.

Root npm runtime dependencies remain zero. Optional Python/native tools stay outside
application bundles. CodeQL includes Python. Hash-pinned wheels and upstream license
notices accompany the optional package. The crypto inventory now has sixteen components.
No merge/deployment, TRL increase or grading is performed; all nineteen gaps remain open.
External sponsor, scope, module, issuer and relevant-environment inputs remain required.

## Native ClamAV smoke acceptance passed (8 November 2026)

Active branch/PR: `codex/siepmu-clamav-acceptance`, draft
https://github.com/richardrich999888-rgb/SIEMPU/pull/35, stacked on PR #34. The executed
code commit is `db782b64d66b5cb0af2533c27f5ac839d79b5d66`, tree
`1050dcff7c594d39e6052b8bfe40525c29dc3e3d`. It passed all ten local validation gates,
429 tests and 3/3 E2E on a clean Linux x64 checkout / Node 24.22.1. Six added regressions
cover evidence completeness, version selection, database snapshots/sidecars, temporary
storage and blocked-report behavior.

Real native [run 42458112330](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42458112330)
passed all three benign/EICAR/expanded-limit cases using ClamAV 1.5.4 and official daily
28177/main 63/bytecode 339 on Node 24.21.0. Source and inputs remained unchanged. The
exact report and selected inventory are preserved under `docs/testing/clamav-native-*2026-11-08.json`;
the downloaded artifact matched its published SHA-256. The initial versioned-sidecar
preflight defect was fixed without relaxing official-database, freshness or scan limits.

This evidence-only follow-up retains the same executable-source digest
`69dfdf62ca5bff8f6322276a55dbeab931add359bdf80f75dd60189b3ede0f2e`. It updates the gap
and dependency descriptions without changing executable code or the native workflow.
Fresh native signature downloads are not triggered by this documentation change. Validate
its final exact commit and E2E, then record all hosted CI/Security outcomes and artifact
links in PR #35. Do not attribute a result from a different commit without its identity
and source-equivalence qualification. No branch is merged or deployed.

Next engineering work: representative file corpus and native parser/resource isolation,
then managed endpoint/browser enforcement. The initial native smoke gate is now passed;
all nineteen broader qualification gaps remain open, IAF-G11 is PARTIAL_LAB, and the
provisional TRL4 assessment and external authorization/grading status are unchanged.

## Native scanner acceptance continuation (8 November 2026)

Draft PR #35 is open at https://github.com/richardrich999888-rgb/SIEMPU/pull/35.
Initial head `6f6c9647d6207ee237d22a49e852f08213a66b9b` passed all ten local gates
(428 tests) and 3/3 E2E on a clean tree. Hosted native run 42457612734 successfully
obtained and verified official daily 28177, main 63 and bytecode 339 databases, then
reported BLOCKED / ACCEPTANCE_DATABASE_UNEXPECTED_FILE before running the three cases.
Pinned upstream source confirmed versioned sidecars such as `main-63.cvd.sign`; the
preflight originally expected unversioned names. This follow-up supports the upstream
format, binds sidecars to the database header version, preserves unknown-file rejection,
and adds a regression. The workflow excludes patch signatures from the snapshot.
Revalidate and publish this fix as a fast-forward; final exact-head local and hosted
results, including the actual native acceptance outcome, are recorded in PR #35.

Active branch: `codex/siepmu-clamav-acceptance`, based on PR #34 head
`560eb080eac3125533034efaa9d23caf3c827a1f` (tree `9dd352564a3267d798aa096219938a415912e520`).
PR #34 remains open/draft and unmerged. Its final local result was 423 native tests plus
3 E2E tests; its 233 adversarial cases overlap that native suite. Its push CI
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42454008250 and Security
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42454008218 passed, as did
PR CI 42454012784 and Security 42454012724. PR checkout `aa4d057be02d4053716b6d526c3fee069d9e0f7f`
had the same tree as the head. These results belong to the base, not this continuation.

The new explicit `npm run test:clamav -- <config> <new-output-directory>` command binds
native acceptance to a source commit/digest and pinned engine/database inputs, checks a
private Linux tmpfs root, rejects unreviewed versions and incomplete test summaries,
and distinguishes blocked prerequisites from executed failures. Five focused regressions
passed during development; they exercise the evidence gate, not native malware detection.
The runtime SDK adapter and its scan/freshness flags are unchanged. No npm runtime or
production scanner dependency is added. This is a stacked draft candidate; exact final
validation identity, local/hosted outcomes and run links belong in this branch's PR.

ClamAV 1.5.3 has upstream security fixes in 1.5.4. The official 1.5.4 Linux package digest
matched release metadata; its actual process started and refused the missing database
with `FILE_INSPECTION_INCOMPLETE`. CVDUpdate 1.2.0 failed its system DNS TXT lookup before
signature download. The new gate therefore reports `BLOCKED` / `ACCEPTANCE_DATABASE_MISSING`;
all three native positive/detection cases remain unexecuted. The earlier curl HTTP 403
was an unsupported download method, not proof that a supported updater was refused.
See `docs/testing/endpoint-inspection-engine-probe-1.5.4.json` and the endpoint guide.

A separate synthetic hosted workflow now provides a bounded FreshClam attempt on an
unprivileged GitHub runner, with the native package/hash pinned and CVD certificates
configured. It records blocked prerequisites instead of skipping the acceptance gate.
It runs once when its workflow file is pushed on this branch, without a duplicate PR
trigger. The preceding candidate `87fae9db1dce89cbe895b53770f6349fd528746a` passed all
ten local validation gates (428 tests); those results precede this workflow addition.
Validate the final candidate and E2E before branch publication; observe its hosted
CI, Security and Native ClamAV acceptance outcomes and record them in the draft PR.

Next executable task: inspect the hosted native result; if still blocked, provision official signatures through FreshClam/CVDUpdate on a
managed host with permitted DNS/HTTPS; freeze a database snapshot and run the explicit
gate on a clean checkout. Do not disable official-database or freshness controls. Then
extend real-engine coverage to the representative corpus and endpoint isolation before
browser/helper integration. All nineteen qualification gaps remain open, including
IAF-G11 (PARTIAL_LAB); provisional TRL4 and external authorization axes are unchanged.

## Managed endpoint inspection continuation (8 November 2026)

Active branch: `codex/siepmu-endpoint-file-inspection`, based on PR #33 head
`c7bf7c913cff88d2ebd0d2e08fe2539c7121830e`. This is a separate stacked draft change;
no branch has been merged. Historical PR #33 validation is not this candidate's evidence.

Implemented an optional local ClamAV process adapter and source/recipient SDK hooks.
Plaintext inspection stays at the managed endpoint. Byte snapshots bind scanning to
subsequent encryption/return, and failed recipient scans produce no delivery ACK.
The adapter bounds input, output, time and concurrent work, pins the executable entry
point, and requests official/current signatures plus encrypted-container/scan-limit
alerts. No npm runtime dependency or scanner binary is added. Default SDK and browser
clients remain explicitly unscanned. See `docs/integration/endpoint-file-inspection.md`.

Candidate `71a279684678445e0b16672218ce2848962e3ac2` (tree
`ea45fab702389e654673c09246ac2d12a0fc6e45`) passed all ten native validation gates
and 423/423 tests, plus 3/3 E2E tests, with zero failures/cancellations/skips, on
Node 24.22.1 / Linux x64 with a clean tree. Coverage was 97.93% lines, 90.77%
branches and 98.45% functions. Research-register self-tests and claims checks passed.
The local report is `artifacts/validation/report.json`; later runs identify their own
exact commit and source digest and must not be attributed to this historical candidate.

The new tests use labelled scanner-process doubles and real authority/crypto over an
in-process transport; this is not real-engine positive-path qualification. A real locally
extracted ClamAV 1.5.3 process refused a missing official database. Downloading current
official signatures returned HTTP 403. `tests/file-inspection/clamav.check.mjs` is ready,
but its benign/EICAR/expanded-file cases remain unexecuted. Do not remove freshness,
official-signature or scan-completeness gates to make the laboratory run pass.

The preliminary adversarial run invalidated by a simultaneous documentation edit was
superseded by a clean run at `ebd46bb9e3a82ec6093b44e604ae5fee2ee9cff0`: all ten
native gates / 423 tests, 3 E2E tests, and 233 adversarial tests across nine families
passed. The campaign's sourceUnchanged check passed; its tests overlap the native suite.
The reviewed tree is `f33761f6c42cdec76713747269f5d72dde761d84`.

The user authorized publication of the reviewed patch to the public repository and a
draft PR on 8 November 2026, resolving the earlier automatic-approval block. Command-line
Git had no write credentials; the connected GitHub API published initial commit
`72386146b006b6ca57850b9e77bdd1dee320d145` with exactly the reviewed tree above.
Draft PR #34 is open: https://github.com/richardrich999888-rgb/SIEMPU/pull/34,
targeting `codex/siepmu-sealed-integration-trl5` (PR #33, unchanged at the inspected
base). No branch is merged or deployed. The local publication checkout is
`codex/siepmu-endpoint-file-inspection-publication`; the remote branch remains
`codex/siepmu-endpoint-file-inspection`.

Initial published-head runs, observed queued/in progress at this documentation edit:

- Push CI: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42453597596
- Push Security: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42453597974
- PR CI: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42453648372
- PR Security: https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42453648323

This handover follow-up changes documentation only. Validate its exact published commit,
run E2E locally, then observe every hosted CI/Security job for that same commit. The
final commit, run outcomes and artifact links are recorded in PR #34; initial run results
must not be attributed to a later candidate. Next engineering work is the outstanding
real-engine acceptance and managed endpoint/browser boundary described below.

IAF-G11 is PARTIAL_LAB; all nineteen gaps remain open. Native-engine acceptance, a
representative corpus, browser/helper integration, endpoint sandboxing and memory-backed
temporary storage verification are pending. Neither the provisional TRL4 assessment
nor any external authorization axis changes. No operational or confidential information
was used. Hosted validation is not substituted by the local checks. Final local candidate
identity and results are in the generated validation report and the review patch handover.

## Source-sealed integration and dependency review (7 November 2026)

Publication follow-up: draft PR #33 is open at
https://github.com/richardrich999888-rgb/SIEMPU/pull/33, targeting draft PR #32's branch.
Initial published head `c8cf3bcac15dd26e0546fb77b9822c0453a32f05` has the same complete
tree `07c69bca43980d9ca4384b12f789aa26f07a5344` as locally validated candidate
`11f0768f31f00679066faa6122c4ee463f0369eb`. On Node 24.22.1 / Linux x64 with a clean
tree, all ten native gates passed: 410 tests, zero failures/cancellations/skips;
coverage 97.96% lines, 90.67% branches and 98.75% functions. E2E passed 3/3.
The separate adversarial execution passed 220 tests across nine families, retained
all nineteen gaps and assigned no readiness level. Source remained unchanged.

Initial hosted runs were launched on that published head (not yet observed complete
at this handover edit): push CI
https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42392946845,
push Security https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42392946841,
PR CI https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42392997177,
PR Security https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42392997154.
This documentation follow-up requires fresh final-candidate checks. Exact final
published identity, completed run outcomes and artifact links are retained in PR #33.
Next continuation: inspect that PR's current head/runs before attributing any result;
finish its hosted gates if pending, then address the remaining gap register. No merge.

Active branch: `codex/siepmu-sealed-integration-trl5`, based on draft PR #32 at
`5c465d290a002a551a83ef74b235cd5a97990da8`, tree `48cb1f7293d78c55992d886b03ff3043a051f90d`.
That base passed all 9 CI and 3 Security jobs on both events: push CI 42384141258,
push Security 42384141375, PR CI 42384144786 and PR Security 42384144785. The base
has 395 native tests, 3 E2E and a 205-test adversarial campaign; these are historical
results, not this candidate's evidence. No branch has been merged.

The user requested advancement toward the next readiness assessment and dependency research.
`INTEGRATION_DEPENDENCY_REVIEW.md` records primary-source options: Keycloak/OIDC,
WebAuthn, vendor PKCS#11, optional OpenBao/OTel and ZAP/k6. It records a concrete
cryptoki advisory and distinguishes external specifications from optional packages.
No third-party dependency was installed.

Implemented a separate v2 ciphertext-staging connector and source-side sealed outbox.
Neither plaintext, endpoint keys, bearer sessions nor the wrapped content key is sent
to the connector. Source admission and recipient release use the unchanged authority
policy path. Staging cannot award admission. Row HMACs protect outbox storage; the
independent source HMAC key is never persisted there. Configuration changes fail closed.
See ADR-015 for bounds, current duplicate relay PUT, metadata exposure and trust limits.
Legacy v1 startup now requires explicit enablement in its historical lab harnesses.
The new service never falls back to v1; legacy stores are not migrated or erased.

Initial new tests passed 14/14; combined integration/boundary/package preflight passed
46/46, no failures or skips. A lint check found two unused test imports; they were removed.
The inventory now covers 15 components and 66 source/test bindings. ADV-05 includes
the new tests; all 19 gaps stay open. G05 is PARTIAL_LAB for the new path, with legacy
migration, representative host isolation and IAF interface/placement still unresolved.
G18 remains ROOT_CAUSE_OPEN. No external status axis or TRL has been raised.

First complete local candidate `edaac8b93b068c303d20d7c18a6291025ca1e482` failed three
of 409 native tests: a handover wording hit in the claims audit, independent-adapter
startup (503 at AUTHENTICATE), and a network test's first login (RECOVERY_QUARANTINED).
The new sealed-path tests passed. The wording is corrected without an audit exception.
Twenty-five instrumented ordinary startup probes and eight coverage repetitions of the
three affected process/network tests did not reproduce the startup failures. Temporary
diagnostic code was removed; these passes alone do not establish their historical cause.

A deterministic delayed-custodian regression did reproduce a separate readiness defect:
the launcher returned READY while the gateway/relay were available and custody was blocked.
The lab launcher now verifies a fresh, nonce-bound, signed anchor over pinned mTLS before
returning ready. This probe is read-only and never bypasses the recovery guard. The new
regression failed before the change and passed after it. Corrected preflight: 33/33 tests,
no failures or skips. G18 remains open; the original failures are not conclusively attributed.

Next: commit this correction, run full validation, E2E and the adversarial campaign,
publish a draft PR based on `codex/siepmu-ps69-trl5-review`, and observe every hosted
CI/Security job. Retain exact local/published identities and
run/artifact links in the draft PR. The network matrices still exercise the legacy
integration path; new v2 process/restart tests are same-host laboratory evidence.

## PS-69 technical review and monitoring build (7 November 2026)

Publication follow-up: draft PR #32 is open at
https://github.com/richardrich999888-rgb/SIEMPU/pull/32, targeting PR #31's branch.
Initial published head `97b7c687f3bf7b43b7eabde429d31fee63c22ddb` has the same complete
tree `e70d8f68f5dc1573e72afc87d1d93f1f6660031a` as locally validated candidate
`1434c9507d5168c0258da4869498c5e6fa4e7cf5`: all ten gates / 395 tests and 3 E2E
passed, with no failures or skips (97.88% lines, 90.38% branches, 98.89% functions).
Hosted push CI run 42383303729 failed ADV-01 while PR run 42383320981 passed that
campaign. Push/PR Security runs 42383303743 / 42383321059 passed all three jobs.

The failed artifact 13578531556 identifies `concurrent recovery writers reserve one
output and rotate identity exactly once`: one losing child's stderr was empty at
assertion time. The single successful writer assertion passed. The harness exited
children immediately after an asynchronous stderr write and collected output at
`exit`, before the stream-close guarantee. This follow-up flushes the child write
and waits for `close`; all outcome, diagnostic and state-change assertions remain.
The crypto source binding is refreshed for the reviewed test change. Fresh full
validation, E2E and hosted execution are required for this follow-up; earlier passes
do not qualify it. Exact final candidate/run identities are retained in PR #32.
The corrected concurrent-writer test passed twenty local executions (six children
each), followed by 21/21 recovery-boundary and evaluation-package tests, no skips.

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
