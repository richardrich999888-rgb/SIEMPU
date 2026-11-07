# AIRON–SIEPMU: applicant evaluation dossier

Date: 7 November 2026. Status: preparation candidate; agency grading, operational
authorisation and final qualification are not established. This document proposes
review work; it is not SAG's submission proforma or an IAF-approved test specification.

## Public basis and responsible route

SAG grading remains pending; the public PS-69 statement requires encryption-algorithm grading.
DRDO's policy provides a Service-requested SAG evaluation route, not automatic approval.
Request the IAF programme owner, through iDEX/DIO as relevant,
to sponsor a scoping discussion. Ask for the current proforma, exact required grade,
evaluation scope, target devices, permitted implementation and approved transfer channel.

Public sources inspected 7 November 2026:

| Source                                                                                                                                             | What it establishes                                                                  | Limit                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| [Official PS-69 page](https://idex.gov.in/challenges-cpt/2507)                                                                                     | Stated requirement for encryption algorithm grading                                  | Search-retrieved official text; direct page fetch unavailable. It supplies no detailed test profile. |
| [DRDO support to Indian industry, section 6](https://drdo.gov.in/drdo/sites/default/files/schemes_services/Support-to-Indian-Industry_1_0.pdf)     | SAG support on a Service request                                                     | Not a product-specific approval or fee quote                                                         |
| [DRDO cluster directory](https://drdo.gov.in/drdo/en/organisation/technology-cluster/micro-electronic-devices-computational-systems-cyber-systems) | SAG Delhi: director.sag@gov.in; 011-23819828 / 23812695. CAIR: director.cair@gov.in  | Contact listing, not acceptance of this project                                                      |
| [MoD announcement, 7 October 2026](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2320195)                                                      | Testing-charge waiver announced for iDEX/TDF/Make and other MoD development projects | Obtain written applicability to this project and assessment; no assumed free evaluation or schedule  |

Generic lab access, a vulnerability report, an algorithm standard, hardware marketing
or our own test pass does not establish the required cryptographic decision.

## Candidate and boundaries

The generated package identifies its actual Git commit, tree, full source fingerprint,
build files, runtime and validation report. Public research under `research/trl56` and
older engineering records retain their original scope and dates. The current package
does not inherit their results merely by copying them as source documentation.

| Boundary          | Current implementation                                                        | Evidence / remaining issue                                                                                         |
| ----------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Sender/recipient  | Endpoint encryption, signatures and encrypted local vault                     | `crypto-inventory.json` CR-01/02; software private keys and endpoint compromise remain risks                       |
| Control authority | MFA, fresh device proof, current policy and transactional wrapped-key release | CR-03/04/05; real IAF enrollment/PKI and recovery policy not integrated                                            |
| Ciphertext relay  | Ciphertext storage and integrity checks                                       | Does not receive endpoint plaintext or recipient private keys; metadata still visible                              |
| Custodian         | Independently retained checkpoint and recovery guard                          | Separate-host administrative independence requires representative deployment evidence                              |
| Transport         | TLS 1.3/mTLS and configured trust/pins                                        | Capture actual negotiated parameters, certificate chain, revocation/rotation and target configuration              |
| Crypto provider   | Explicit suite selection and no silent fallback                               | No supplied approved module/SDK, no hardware custody; fixed AES-GCM content operation is an integration constraint |
| Native verifier   | Rust reference verifier                                                       | Optional tool with separate lockfile, vectors and differential tests                                               |
| NEXORA            | Offline evidence snapshot commitment and verification                         | Optional software signer; no live personnel-login authority or continuity-log claim                                |
| Laboratory PQC    | Opt-in Node-only candidate providers                                          | Excluded from application releases; composition and implementation need independent review                         |

Authority compromise can cause premature wrapped-key release. An already disclosed
key/plaintext cannot be recalled. Static recipient encryption keys do not provide
forward secrecy. Current software erasure and opaque handles do not prove physical
key protection. TLS settings and local KAT results do not validate an entropy source
or the deployed cryptographic module.

## Proposed laboratory review matrix

The evaluator must accept or replace these tests and thresholds. The listed files
are implementation mappings, not claims that SAG has accepted or witnessed them.

| Review area                           | Existing executable evidence                                                         | Additional evaluation needed                                                                       |
| ------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| Correct encryption and authentication | `tests/crypto.test.mjs`; `assurance/kat/`                                            | Required authoritative vectors, algorithms and exact module/firmware profile                       |
| Context tampering and downgrade       | `tests/crypto-agility/wrap-derivation.test.mjs`; `tests/versioned-envelope.test.mjs` | Independent composition/protocol review; permitted transition rules                                |
| Enrollment, fresh proof and replay    | `tests/authority.test.mjs`; `tests/auth-routing.test.mjs`                            | Actual personnel issuer, phishing resistance, recovery and device custody                          |
| Revocation and release race           | `tests/authority.test.mjs`; `tests/acceptance/revocation/`                           | Representative concurrency, time limits and sponsor policy                                         |
| Storage and rollback                  | `tests/recovery.test.mjs`; `tests/checkpoint-custody.test.mjs`                       | Separate administration, backup/restore, retention, witnessed recovery                             |
| Transport identity                    | `tests/transport/tls.test.mjs`; `tests/transport/secure-stack.test.mjs`              | Approved PKI, real endpoint fleet, certificate operations and network perimeter                    |
| Provider/key lifecycle                | `tests/crypto-agility/providers.test.mjs`                                            | Supplied SDK, hardware removal, export resistance, attestation, zeroisation and side-channel scope |
| Supply chain and update               | `tests/offline-release.test.mjs`; hosted dependency/secret/CodeQL/container jobs     | Exact OS/browser/module inventory, supplier review, offline installation and authorised updates    |
| Network disruption and scale          | `deployment/testbed/`; `docs/trl5/ACCEPTANCE_MATRIX.md`                              | Agreed independent hosts, WAN, load, acceptance limits and witnessed trials                        |
| Evidence interchange                  | `tests/native/`; `tests/nexora/`                                                     | Independent trust provisioning, handling rules and evaluator acceptance                            |

## External inputs and immediate priorities

The machine-readable [request register](../../assurance/sag/requests.json) retains
SAG-01 through SAG-06 and relevant IAF question IDs. All are pending at creation.
Do not infer an authorised classification, approved cipher, prescribed HSM, lab profile,
fee, timeline, endorsement or mandatory SAG test from this proposed dossier.

1. Obtain the IAF sponsoring officer and written scope, including public-Internet use.
2. Establish whether an existing authorised graded implementation can be integrated,
   and its scope/conditions, or a new implementation must undergo evaluation.
3. Obtain the module/SDK/interface and authoritative vectors through the agreed channel.
4. Freeze the representative hardware/OS/browser/PKI/configuration and operator model.
5. Integrate and test the supplied implementation, preserving fail-closed routing and
   current-policy release. Do not invent an algorithm/provider while inputs are absent.
6. Resolve open defects, conduct independent/witnessed evaluation, remediate and retest.
7. Record the competent authority's actual decision, version, scope and conditions in
   controlled records. Determine re-evaluation after changes before operational use.

The previously observed single local document-adapter startup failure remains an
investigation item in CURRENT_STATE; later local and hosted runs passed. If repeated,
retain a redacted child-process diagnostic and diagnose it before accepting a rerun.

## Submission and change control

Build and verify using [the operator commands](../../assurance/sag/README.md). Review
the generated package before handover; transmit it and the independently pinned digest
using the agreed method. No material is sent automatically. Synthetic test credentials
and vectors in source must be identified as such; never introduce operational secrets.

Keep a controlled evaluation record with candidate hash, device/module firmware,
operating environment, test authority, witnessed procedures, observations, defects,
retest evidence and explicit decision limitations. Changes to cryptographic code,
provider/SDK, firmware, OS/browser, key lifecycle or deployment require impact review.
The repository's source-binding check detects edits; it cannot decide whether an
agency's previous decision continues to apply. SAG grading is not established. TRL assignment,
sponsor acceptance and operational authorisation remain separate external decisions.
