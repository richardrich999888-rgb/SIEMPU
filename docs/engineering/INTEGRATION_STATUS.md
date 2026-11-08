# Integration and SAG evaluation candidate — 8 November 2026

Candidate branch: `codex/siepmu-evaluation-integrations`, based on PR #35 head
`48ecd4bc2268fbe4e759782e7e685ba367946a9d`. Final exact-commit execution results and artifact
links belong in the candidate PR; a planned workflow is not a passing result.

| Integration                                      | Implemented boundary                                                                                              | Remaining qualification                                                                                                                                                         |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ClamAV 1.5.4                                     | endpoint inspection before encryption and after decryption; byte-bound verdict; official database/freshness gates | original native three-case smoke evidence exists; isolated profile now has a passing native probe and three smoke tests; broader corpus and managed/browser rollout remain open |
| Bubblewrap 0.13.1 + prlimit                      | optional fail-closed Linux parser isolation, runtime inventory and resource limits                                | native probe/scan workflow passed on the code commit recorded below; no aggregate cgroup/seccomp or host attestation claim                                                      |
| python-pkcs11 0.10.1 + asn1crypto 1.5.1          | optional managed endpoint signing/ECDH, opaque handles, existing enrollment/device proof/object flow              | SoftHSM 2.7.0 emulator evidence only; actual token/module, custody procedures and approved algorithms required                                                                  |
| NEXORA/AIP                                       | historical evidence sealing and verification                                                                      | not personnel login, authorization or fresh session proof                                                                                                                       |
| OpenSSL/Noble PQC                                | isolated laboratory providers and interoperability tests                                                          | not enabled in production policy or shipped in runtime releases                                                                                                                 |
| CodeQL, Gitleaks, Trivy, Playwright, TLA+, netem | existing repository assurance/CI; CodeQL extended to Python                                                       | exact candidate workflow outcomes required; no independent assessment substitute                                                                                                |
| WebAuthn/FIDO2; IAF PKI or federated issuer      | no new login claim                                                                                                | sponsor authentication profile and managed-device integration still required                                                                                                    |
| Keycloak, SPIRE, OPA, OpenTelemetry, Cosign      | research candidates; not installed merely to increase dependency count                                            | explicit architecture/use-case decision and acceptance tests before adoption                                                                                                    |

The root application retains zero npm runtime dependencies. Optional Python packages have
exact wheel pins, transitive coverage and license notices. They and their native test token
are outside the production build roots. The cryptographic inventory binds the optional
provider and scanner to source/tests. The source-bound SAG candidate bundle includes the
reviewed inventory, gap register and validation evidence without assigning approval.

## Inputs required for a real evaluation

The existing `assurance/sag/requests.json` records the outstanding requests. The immediate
items are: IAF sponsor and evaluation authority; authorized data classifications and handling
channel and deployment/relevant environment. SAG module/SDK/token selection remains pending.
IAF personnel issuer/enrollment rules, acceptance tests and independent assessment
arrangements are also outstanding. No classified inputs should be placed in this public repository.

DRDO's public [industry support document](https://www.drdo.gov.in/drdo/sites/default/files/inline-files/Support-to-Indian-Industry_1.pdf)
describes SAG support on a Services request; no evaluation request is submitted here.
The applicant can prepare evidence and interfaces, but cannot confer SAG grading. Contacting
or submitting to an agency is not performed by this engineering change.

Provisional TRL4 and all nineteen qualification gaps remain open. A relevant-environment
TRL5 demonstration and its acceptance evidence are still needed. Neither this integration
nor a passing CI run authorizes operational classified-data use or establishes TRL8.

## Executed native evidence

Code commit `f9eac4d6b6a8726795e46660dcc15496da00eb48` passed 432 local regression tests
and 3 E2E tests. Hosted token run 42463858775 passed all nine tests and the Python dependency
scan. Hosted isolated scanner run 42463858700 passed one namespace probe and three actual
ClamAV cases. The global Ubuntu userns restriction remained enabled. Exact source identity,
artifact hashes, native inventories and reports are retained in
`docs/testing/endpoint-native-acceptance-2026-11-08.json`. Broader file-type and hardware
qualification remain open; final candidate CI and bundle references are in PR #36.
