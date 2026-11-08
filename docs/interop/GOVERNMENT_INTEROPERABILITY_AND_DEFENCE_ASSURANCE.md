# AIRON–SIEPMU Government Interoperability and Defence Assurance Report

Review date: **8 November 2026**. Organisation: SYNTRIASS Labs Pvt. Ltd.
Scope: DISC-14 PS-69; PR #39, `codex/india-dpi-iudx-contract-tests`, stacked on PR #38.
This applicant engineering record establishes no SAG grading or operational authorization.
Independent assessment and a system-level TRL 5 decision are **not established**.

The current iteration fixes the reproducible formatting failure and hardens the isolated DX
reader. It adds a real loopback TLS transport, authority-separation regressions, a measured
policy-release comparison and a source-bound observer package. No government API transaction,
production deployment, restricted-system access or new runtime dependency is introduced.

Execution results belong to `artifacts/interop-assurance/report.json` and its manifest, which
record the exact commit/tree. They are produced **after** source freeze. This document does not
predict a CI outcome. Final hosted run links and outstanding gates are recorded in PR #39.

## 1. Government technologies: verified facts and selection

Primary sources below were reviewed on 8 November. Availability of documentation or source is
not compatibility with an operational government deployment. Proposed uses are our engineering
inferences, not requirements or endorsements from those projects. We reviewed the named public
projects, not every community or all non-public government interfaces.

| Candidate                  | Ownership / status evidence                                                                                                                                               | Source, licence and observed maintenance                                                                                                                                                                                                                                                           | Interface / authentication / test access                                                                                                                                                                                                                                                                                                         | Decision and PS-69 relevance                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IUDX / DataKaveri DX proxy | [IUDX developer page](https://iudx.org.in/developers/) describes a MoHUA Smart Cities initiative implemented by IISc. Public reference code; not an IAF deployment.       | [DX proxy](https://github.com/datakaveri/dx-rs-proxy), Apache-2.0, not archived; latest main commit observed `a6d2bbb2199f1db65aa67e7b807c5241aea2895c`, 12 Sep 2025. [Pinned OpenAPI](https://github.com/datakaveri/dx-rs-proxy/blob/a6d2bbb2199f1db65aa67e7b807c5241aea2895c/docs/openapi.yaml). | Proxy GET `/ngsi-ld/v1/entities?id=UUID`, provider `token` header. [Consumer guide](https://docs.iudx.org.in/docs/consumer/consumer_data_access_apis/) requires resource/token access and describes a different general resource-server API. Public sandbox is documented; no scoped account/resource supplied here.                             | **LOCAL_CONTRACT_SELECTED** for a proposed endpoint read of unclassified external data. Proxy subset only; live service compatibility remains untested. No data publication or personnel federation.  |
| API Setu                   | MeitY/NeGD/DIC platform, identified in [official documentation](https://docs.apisetu.gov.in/document-central/explore-apisetu/Sandbox.html).                               | No single reusable platform source licence established in reviewed sources. Publisher API/data terms must be checked separately; no stack imported.                                                                                                                                                | [Public sample sandbox](https://sandbox.api-setu.in/) is documented as signup-free; landing page retrieved, API transactions not executed. [SOP](https://cdn.apisetu.gov.in/portal/assets/SOP-APISETU.pdf) describes organisational signup, use-case review, subscriptions, publisher permission and scoped key/token.                           | **HOLD_USE_CASE_AND_CONTRACT**. A selected logistics/document metadata API could help; no specific publisher endpoint and relevant PS-69 workflow selected. Do not build a generic credential bridge. |
| OpenForge                  | [Government of India collaboration platform](https://openforge.gov.in/openforge/about.php); a source-hosting service rather than an exchange gateway.                     | [FAQ](https://openforge.gov.in/openforge/faq.php) permits reuse under each project's own licence. Public and restricted projects differ; project provenance and maintenance require per-repository review.                                                                                         | Public source discovery is available. Restricted G2G projects require access approval. No relevant data-exchange API contract selected.                                                                                                                                                                                                          | **SOURCE_DISCOVERY_ONLY**. Useful for finding reusable modules; hosting there does not establish agency qualification. No adapter or dependency justified.                                            |
| MOSIP / eSignet            | [IIIT-B owns and maintains MOSIP code](https://www.mosip.io/ip_policy). Identity public-good software, not an IAF personnel issuer.                                       | [mosip/esignet](https://github.com/mosip/esignet), MPL-2.0; not archived, push activity observed 6 Nov 2026. Per-module dependency/licence review still needed before adoption.                                                                                                                    | [Collab and Synergy documentation](https://docs.mosip.io/1.2.0/readme/technology/sandbox-details) describes partner onboarding; [eSignet/IDA integration](https://docs.mosip.io/1.2.0/interoperability/integrations/e-signet/ida) describes authentication interfaces. No tenant, relying-party registration or trust mapping supplied.          | **HOLD_NOMINATED_ISSUER**. Research OIDC/identity binding only after IAF selects an issuer. External authentication cannot grant local mission authority. No live login attempted.                    |
| DIGIT                      | [eGov Foundation reference platform](https://github.com/egovernments/DIGIT-OSS); nongovernmental project used for public services.                                        | [Digit-Core](https://github.com/egovernments/Digit-Core), MIT; not archived, push activity observed 4 Nov 2026. No complete dependency or vulnerability assessment performed.                                                                                                                      | [Sandbox](https://docs.digit.org/sandbox) supports product exploration. [Workflow documentation](https://docs.digit.org/local-governance/v2.8/products/modules/hrms/hrms-ui-configuration/auto-escalation-ui-flow) shows POST `/egov-workflow-v2/egov-wf/process/_search`; tenant roles and authentication apply. No authorized tenant supplied. | **HOLD_WORKFLOW_SCOPE**. Potential administrative workflow metadata only. Do not forward plaintext documents or inherit DIGIT roles into SIEPMU. No integration executed.                             |
| NIC Sandes                 | [NIC service description](https://www.nic.gov.in/service/sandes/) and [government portal](https://www.sandes.gov.in/) document government messaging and eGov integration. | Open-source-based is NIC's description; a complete redistributable source repository/licence was not established. Public service pages are maintained; no code/security maintenance assessment made.                                                                                               | Service integration and organisation administration are documented; no public integration wire contract and permitted test credentials were found in the reviewed sources. [FAQ](https://www.sandes.gov.in/resources/um/faq.pdf) describes organisation verification/onboarding.                                                                 | **OWNER_INTERFACE_REQUIRED**. Potential notification interoperability or feature baseline only. No reverse engineering, app automation, live messaging or interoperability claim.                     |
| C-DOT SAMVAD               | [C-DOT product page](https://www.cdot.in/cdotweb/web/product_page.php?catId=4&lang=en&pId=23) documents an indigenous communication product.                              | [SAMVAD site](https://signupsamvad.cdot.in/) supplies vendor feature claims, not a public source licence or independent result for AIRON. No repository/API release pin established.                                                                                                               | Public product information exists; no reviewed public integration schema, SDK licence or owner-approved test tenant supplied.                                                                                                                                                                                                                    | **OWNER_INTERFACE_REQUIRED**. Potential comparative evaluation after owner access and agreed protocol. Vendor capabilities or qualifications cannot be inherited by SIEPMU.                           |

The selected IUDX profile is documented in [INDIA_DPI_TESTBED.md](INDIA_DPI_TESTBED.md).
It needs only existing Node built-ins and the repository TLS component. Deploying the whole DX
server would add Vert.x/PostgreSQL/RabbitMQ and supporting infrastructure described by its
README; that stack is neither required nor imported for a read-only endpoint adapter.
Maintenance timestamps are activity observations, not proof of security or supported versions.

## 2. Implemented integrations and trust boundaries

The new `SIEPMU_DX_READ_V1` profile binds HTTPS origin, UUID query and provider header to a pinned
specification. A strict application subset validates successful responses; streamed byte limits,
UTF-8 decoding, nesting/entry limits, a request deadline and fixed error codes constrain hostile
responses. Rejected streams are canceled. The concrete interface uses TLS 1.3 and literal
loopback addresses only, requires explicit opt-in and a private CA, and refuses redirects.
Production public-network access remains unavailable.

The receiver labels content `RECEIVED_UNTRUSTED`; a raw-byte hash records provenance, not truth
or authority. Embedded roles and verification labels are inert content. Tests attempt an external
token against actual local authority routes and receive denial. An explicit synthetic endpoint
import encrypts this content and uses normal admission/release; the wrong local recipient is
refused. There is no automatic forwarding, rendering, URL fetching or identity conversion.

End-to-end encryption, device-bound authentication, transactional current-policy key release,
provider failure behaviour and revocation boundaries remain unchanged. Prior optional NEXORA
integration verifies evidence offline; it does not authenticate IAF personnel. Government
connectors and the synthetic military adapter remain separate and excluded from production
runtime imports. Classified content, all-file-type safety, a military gateway and production
PKI compatibility are not established by this work.

## 3. Adversarial evidence and remediation

Starting commit: `8ba056e4b00eea5696c2b5880dd8e2ba26c7782c`.
[Push CI 42483937839](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42483937839)
and [PR CI 42483941780](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42483941780)
failed the formatting gate on the three new files. The exact starting revision passed its eight
IUDX tests locally. Its claims gate and Security jobs passed; a new claims violation was not
reproduced. Native-job failure skipped dependent container/testbed jobs. Both relevant-env jobs
passed, so the older T8.1 load issue is not an unresolved defect in this base.

| Finding                        | Reproduction / prior behaviour                                             | Remediation and regression oracle                                                                   |
| ------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| INT-01 formatting              | Pinned Prettier check on PR #39's three files fails                        | Format with committed Prettier; full gate required on final SHA                                     |
| INT-02 unbounded mock fallback | `text()` allocates entire response before checking length                  | Remove fallback; stream-only transport; oversize must cancel before complete body consumption       |
| INT-03 untrusted schema        | Arbitrary JSON object accepted, no resource binding                        | Narrow versioned schema, requested ID, immutable untrusted output, complexity/prototype tests       |
| INT-04 absent deadline         | Stalled headers/body can wait indefinitely                                 | Whole-request timer/abort and cancellation; stalled header/body tests                               |
| INT-05 weak transport evidence | Request builder sets redirect policy but only fake transport was exercised | Opt-in literal-loopback TLS transport; real CA/hostname rejection, redirect sink gets zero requests |
| INT-06 authority confusion     | No explicit regression for external claims at local authority              | Foreign token denied; embedded admin claims do not elevate operator; normal encrypted import only   |

No claim is made that these source findings prove exploitation of a live deployment: the initial
reader was not connected to production. Development testing also exposed an incorrect comparison
harness expectation (403); the authority correctly returns 409 with `POLICY_DENIED` and `HELD`.
The harness now asserts that exact reason/state and zero new issuances; runtime code was not altered.

[`assurance/iaf/plan.json`](../../assurance/iaf/plan.json) maps nine families to R1–R12. The new
contract tests are included in ADV-05; the policy comparison is included in ADV-02. Existing
families cover identity/session/device attacks, cross-unit/mission boundaries, ciphertext and
key tampering, provider selection/downgrade, grant expiry, custody/rollback, duplicate submissions,
crashes, encrypted outbox, malformed files, transport disruption and monitoring recovery.
Passing synthetic cases do not close representative fleet, parser/corpus or independent assessment gaps.

Failures remain attributable to their original SHA/run. The local observer runner retains TAP,
raw measurements and failure details, refuses skipped/missing tests, and checks the whole source
tree before and after execution. Fresh CI supplies container, browser, Rust, PQC, NEXORA, formal,
three-namespace impairment and ten-zone testbed results for the candidate. A later green run does
not erase an earlier failure. See final PR evidence for actual counts and unfinished jobs.

## 4. Technical contribution and measured comparison

The repository's contribution is its combined implementation of current-policy transactional
release, policy-epoch/object binding and independently verifiable signed decision evidence.
No novelty, patentability, government preference or superior overall performance is concluded.

`scripts/policy-release-comparison.mjs` compares the same encrypted/signed 4 KiB object under two
explicit assumptions: (a) a reference that gives the recipient the wrapped key in advance and
(b) SIEPMU's current-policy release. After revocation, the reference remains decryptable while
SIEPMU denies new issuance. A previously issued SIEPMU key also remains usable. This isolates the
release boundary; it is not a model of every secure messenger or a Sandes/SAMVAD benchmark.

Twenty sequential in-process iterations report encryption/signing, admission/preparation,
release and both decrypt timings; five audit-verification samples record chain size and cost.
CPU, memory, raw samples, environment and percentile method are retained. These measure local
cost rather than maximum throughput or field performance. Existing relevant-env T8.1 tests use
an explicit 650 ms exchange interval per session and retain the 500 protected requests/session/
fixed-minute limiter. Zero-refusal acceptance was not weakened. Recovery times and impairment
measurements belong to `artifacts/trl5/` and `artifacts/testbed/` from the named CI revision;
they must not be substituted with local microbenchmark numbers.

## 5. TRL assessment and requirements traceability

System self-assessment remains **provisional TRL 4**. Automated success, a local TLS simulation
and GitHub network namespaces are not sufficient to declare TRL 5. Sponsor-defined relevant
hardware, deployment boundaries, operating conditions, complete-system evidence and independent
observation/acceptance remain necessary. Namespaces share a host kernel and administration.

The [official PS-69 compendium](https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf),
printed pp.161–162, was re-retrieved. It calls for secure inter-unit exchange over public Internet,
cloud microservices, E2EE/MFA, monitoring/threat detection, granular access control, existing
military interfaces and an encryption algorithm with SAG grading, which remains pending here. Testing scope
is set by the certifying/QA agencies. It does not supply personnel PKI, classification permission,
message modes, load/SLA targets or authority to use a government sandbox. Those are still missing.

| Requirement                                    | This iteration's evidence                                                            | Remaining boundary                                                  |
| ---------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| R1/R5/R7 identity, E2EE and local authority    | External-token/role denial; synthetic endpoint sealing and correct-recipient release | Nominated issuer, managed devices, approved operating scope         |
| R2/R6 integrity, secure protocols and evidence | Response limits/deadlines/TLS checks; source-bound report and policy experiment      | Live owner contract, independent observers and deployment controls  |
| R3/R11 latency and scale                       | Raw local release measurements; fresh CI load/impairment evidence required           | Agreed communication modes, workload and SLA                        |
| R4 service boundaries                          | Isolated endpoint reader; no production route or extra service stack                 | Representative hosting and operational isolation                    |
| R8 military interoperability                   | Public DX contract plus separate synthetic adapter tests                             | Public DPI compatibility does not satisfy a real military interface |
| R9 cryptographic assurance                     | Updated reviewed crypto inventory and exact-source evaluation package                | Pending SAG scope, permitted module and formal decision             |
| R10 storage/recovery                           | Existing adversarial custody, corruption and restore tests rerun                     | Independent backup custody, full DR and accepted retention          |
| R12 qualification                              | Traceable sources/tests, reproducible observer package                               | Agency-directed testing and documentary decisions                   |

## 6. Pending SAG evaluation requirements

[DRDO's industry-support document](https://drdo.gov.in/drdo/sites/default/files/inline-files/Support-to-Indian-Industry_1.pdf)
describes SAG testing support on a Service request; no such request for AIRON is established. The official
search-index excerpt was retrieved; the full PDF timed out in this session. This is a route to
seek direction, not evidence of sponsorship, fees, acceptance or a scheduled evaluation.
The source-specific public PS-69 grading requirement was verified directly in the compendium.

The complete gap register remains [IAF-G01–G19](../../assurance/iaf/plan.json). None is closed by
this iteration. These are exact outstanding work items, not additional invented IAF specifications:

| Gap | Outstanding work / owner input                                                                               |
| --- | ------------------------------------------------------------------------------------------------------------ |
| G01 | Freeze sponsor requirements, classifications and Internet boundary                                           |
| G02 | Integrate nominated issuer/PKI and personnel lifecycle/recovery                                              |
| G03 | Obtain permitted crypto module/SDK/version and scoped evaluation direction                                   |
| G04 | Qualify hardware key custody, rotation, loss recovery and destruction                                        |
| G05 | Validate endpoint placement; retire/migrate legacy plaintext document paths; receive real interface contract |
| G06 | Implement single-writer fencing and failover across independently administered hosts                         |
| G07 | Qualify perimeter isolation, connection budgets and load shedding                                            |
| G08 | Complete accepted retention/deletion, backup custody and recurring restore drills                            |
| G09 | Qualify renewal/reauthentication against nominated identity and long-duration policy                         |
| G10 | Agree scale, communication modes and SLA; complete missing modes and capacity controls                       |
| G11 | Qualify scan engine/signatures/corpus, safe viewers and browser/managed endpoint enforcement                 |
| G12 | Integrate accepted monitoring schema, alert handling, availability and retention                             |
| G13 | Integrate selected MDM, posture/attestation and device-loss controls                                         |
| G14 | Complete role-based manuals, training and accessibility/user trials                                          |
| G15 | Freeze final hardware/runtime/supplier inventory and protected release-signing ceremonies                    |
| G16 | Independent penetration, protocol and cryptographic assessment with agreed rules                             |
| G17 | Reconcile filed/contract scope, support and licensing commitments                                            |
| G18 | Preserve unresolved historical `ADAPTER_EXITED`; obtain root cause or assessor-accepted disposition          |
| G19 | Run authorized representative/operational trials; obtain separate qualification and operational decisions    |

The existing evaluation package includes reviewed algorithms, key locations, provider boundaries,
software/lab limitations, source bindings and SBOM. This iteration adds the optional reader's
TLS/hash inventory. Software PKCS#11 emulation is not physical key protection; generic primitives,
NEXORA evidence, known-answer tests and standards references are not agency-qualified modules.
SAG-01–06 in `assurance/sag/requests.json` remain pending. A public government API token or
another product's grading cannot satisfy them.

## 7. Testbed access and independent demonstration

The no-cost local path is a clean checkout, pinned tools, synthetic identities, private laboratory
CA and the observer commands in [INDIA_DPI_TESTBED.md](INDIA_DPI_TESTBED.md). An observer can
recompute hashes, run the contract tests and policy experiment, inspect signed evidence and
verify the separate source/evaluation package. Container/netem trials add deployment separation
but do not establish sponsor representativeness or independent administration.

External steps: IUDX owner supplies permitted origin/resource/token and proxy version; API Setu
requires a concrete sample product/use case before integration and publisher onboarding for live
access; MOSIP needs partner/relying-party registration and a nominated issuer; DIGIT needs a
permitted tenant/workflow. NIC/C-DOT must supply their interface, licence and test-access terms.
Pending IAF/SAG inputs: Service sponsor, test environment, permitted module/hardware and
submission/evaluation procedure. No account was registered, restricted endpoint probed or message
sent to these organisations during this work.

## 8. Remaining budget and resources

This change adds **zero runtime npm packages and no software licence purchase**. It uses existing
workspace/CI capacity; no new paid service or purchase was initiated. That is not a promise that
GitHub execution, staff time or formal evaluation is universally free.

| Work                                          | Resource plan under the ₹0 constraint                                                                 | Cost status                                                                       |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Reproduce this iteration                      | Existing Node host; temporary local TLS; current development lockfile                                 | No incremental purchase initiated                                                 |
| Container/network/formal/native gates         | Existing Linux CI with Docker/netem, Rust, Java                                                       | Existing capacity; actual account billing not assessed                            |
| Representative evaluation                     | Borrow/reuse managed endpoints, separately administered service/evidence hosts and impairment network | Availability and adequacy require sponsor/lab confirmation                        |
| Personnel PKI, HSM/token/MDM and supplier SDK | Request a permitted test integration or loan only after scope selection                               | Price/lead time unknown; no procurement authorization or quote                    |
| Independent audit, lab access and witness     | Agree scope and request sponsorship or applicable support                                             | Fees/waivers unknown; no zero-cost grading claim                                  |
| HA, DR, fleet controls and remaining modes    | Engineering effort depends on accepted architecture and workload                                      | No defensible fixed total before requirements; itemized estimate remains required |

Use the existing [quote-required BOM](../../research/trl56/13-bill-of-materials-and-budget.md).
Do not advertise a full readiness cost from free dependency licences. Dependency PRs were not
blindly adopted: Node 26 conflicts with the declared Node 24 profile, and dev-tool updates need
separate compatibility/security evidence. Root runtime dependencies remain zero. Refer to
`packages/pqc-lab/THIRD-PARTY-NOTICES.txt`, optional integration notices, committed lockfiles and the generated CycloneDX SBOM for existing software.
Upstream licence observations above do not import those full dependency graphs into this build.

## 9. Source, PRs, delivery gates and blockers

- Starting PR: [#39](https://github.com/richardrich999888-rgb/SIEMPU/pull/39), head
  `8ba056e4b00eea5696c2b5880dd8e2ba26c7782c`.
- Inherited continuity base: [#38](https://github.com/richardrich999888-rgb/SIEMPU/pull/38),
  `5f8c6848f6ba0bcf7ba81eb4be90c3e9c9dcc92a`. Its final push/PR CI runs
  [42483369153](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42483369153) and
  [42483374555](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/42483374555)
  passed all nine jobs, including T8.1. This is historical base evidence, not a new candidate result.
- [31 open-PR inventory](open-pr-inventory-2026-11-08.json) captures heads, bases and draft state.
  Architecture/ancestry inspection confirms the existing #39→#38→#37 stack; unrelated divergent
  or dependency PRs were not merged. This inventory is not a fresh security audit of every old diff.
- Final candidate commit/tree, measured results and artifact digests are generated by the clean-tree
  observer runner. The PR body records fresh hosted CI/security runs. Never attribute base results
  to a new source hash, or a PR merge checkout to its head without verifying tree equivalence.

Before branch publication: full local `validate` and E2E on the frozen commit. Before any future
merge: required hosted CI and Security checks on that candidate, review of the complete stacked
change and resolution of release blockers. Branch publication is for review, not production
approval. All nineteen qualification gaps and unestablished live-government interfaces remain
visible. The next engineering work can continue with HA/fencing and complete DR design under
explicit single-writer assumptions, while sponsor-dependent identity/crypto/interfaces await input.
