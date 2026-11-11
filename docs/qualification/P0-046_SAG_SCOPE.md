# P0-046 proposed SAG evaluation scoping dossier

SYNTRIASS Labs Pvt. Ltd. submits an inspectable software candidate for scoping, not a certificate.
The proposed evaluation object is the frozen AIRON–SIEPMU source/tree, build inventory, runtime
configuration, cryptographic providers, endpoint keys, policy authority, custody protocol and
independent verifiers recorded in the package manifest.
Government approval and SAG grading are not established. Do not describe this as a formally accepted evaluation submission.

## Mechanisms and implementation boundary

The machine-readable, source-bound inventory is `assurance/sag/catalogue.json` (20 components).
It names every reviewed application mechanism plus separately scoped lab/optional tools and
hashes its cited source/tests. Runtime versions, OpenSSL configuration, build hashes, dependency
SBOM and licensing are generated per candidate. Review drift fails the package gate.

| Mechanism group        | Current implementation and custody                                                                      | External assessment needed                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Object encryption      | P-256 ECDH, HKDF-SHA256, AES-256-GCM; 96-bit nonce/128-bit tag; endpoint software keys                  | Allowed suite, module/build, nonce/entropy assurance, endpoint lifecycle                     |
| Signatures and history | ECDSA P-256 SHA-256 P1363; SHA-256 chained evidence; independently keyed custody                        | Key separation, canonical encoding, module failure, signature/checkpoint trust model         |
| Authentication         | scrypt password hashes; six-digit TOTP HMAC-SHA1; signed device operation proofs; hashed session tokens | Nominated personnel issuer, MFA policy, phishing resistance, recovery and attestation        |
| Storage                | AES-256-GCM MFA protection; PBKDF2-SHA256 endpoint vault; encrypted scrypt/AES-GCM maintenance archive  | Approved storage module, master/passphrase custody, backups, destruction and recovery        |
| Transport              | TLS/mTLS through Node/OpenSSL, pinned service identities, local lab CA                                  | Exact cipher/protocol configuration, issuer, certificate issuance/expiry/revocation/rotation |
| Release authority      | Transactional policy checks, complete state digest and signed commit seal, writer generation/floors     | Provider/key custody, crash behavior, manual failover, independent state retention           |
| Optional providers     | Provider registry with explicit selection; managed endpoint PKCS11 boundary                             | Authorised SDK, module/firmware, hardware removal and mechanism validation                   |
| Lab-only PQC           | Separately gated ML-KEM/ML-DSA/X-Wing candidates                                                        | No inferred approval; allowed algorithms, module and deployment decision required            |

Randomness depends on Node/OpenSSL and operating-system CSPRNGs; laboratory PKI and software key
files are not approved entropy or hardware custody evidence. TLS certificate expiry/peer-name
tests do not establish an operational IAF certificate lifecycle. Recipient key revocation prevents
new releases at defined boundaries; it cannot erase previously delivered keys or plaintext.

The existing provider-neutral registry rejects unknown/unavailable providers, mismatched suites,
invalid key descriptors and forbidden policies. It does not dynamically map a government API token
to a personnel identity or substitute an unapproved algorithm when a provider fails. An authorised
SDK can be integrated only after its public/formally supplied interface, licence, key semantics,
error behavior and evaluation scope are provided. No restricted interface is reverse-engineered.

## Included laboratory material

The candidate package contains source/index, runtime/build inventory, CycloneDX dependencies,
source-bound validation, declarations and open external requests. The associated CI artifacts
retain known-answer tests, provider/interoperability and downgrade tests, replay/tampering,
key lifecycle/removal, encrypted restore, custody partitions, state seals and handover regressions.
Optional native token/container/Rust results are separately identified; no absent suite becomes
passed. Failing attempts and the two-stage AUTH-STATE-01 correction are retained in the assurance
archive. No new npm/Rust/Python dependency is introduced by P0-046.

## Decisions and documents still required

| Decision                          | Owner                                | Required evidence and next action                                                                           |
| --------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| Service sponsorship and evaluator | IAF sponsoring authority             | Nominate technical point of contact; SAG scope determination is pending                                     |
| Product/module/algorithm scope    | SAG with IAF crypto authority        | Pending written scope, required grading/profile, exact module/firmware/SDK and applicability conditions     |
| Test methods and acceptance       | Nominated evaluator                  | Submission proforma, authoritative vectors, procedures, independence requirements and thresholds            |
| Hardware keys and lifecycle       | IAF crypto/endpoint owners           | Selected module, provisioning, rotation, loss, revocation, destruction and recovery policy                  |
| Fees and possible waiver          | Sponsoring authority and laboratory  | Written quotation or zero-fee applicability decision covering this exact activity; amount currently unknown |
| Access and handling               | Laboratory and IAF information owner | Approved hosts, personnel, data classification, NDA/IP terms and source-transfer channel                    |
| Findings and final disposition    | Evaluator                            | Signed report referencing exact candidate and outstanding conditions; no applicant substitution             |

Public DRDO material describes a service-requested SAG route; applicant sponsorship remains pending.
The MoD announcement of 7 October 2026 describes testing-charge waivers for qualifying iDEX,
TDF, Make and other MoD development projects. SAG fee-waiver eligibility is not presumed.
Obtain written confirmation; neither announcement establishes free certification or sponsorship.

Sources checked 9 November 2026:

- [DRDO industry support, official PIB release](https://www.pib.gov.in/PressReleasePage.aspx?PRID=1786640&lang=2&reg=48).
- [MoD testing-charge waiver announcement](https://www.pib.gov.in/PressReleseDetailm.aspx?PRID=2320195&lang=1&reg=3).
- [Official PS-69 compendium, printed pages 161–162](https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf).

The 12 external inputs in `assurance/sag/requests.json` and all 19 qualification gaps remain
authoritative tracking records. This dossier is complete only to the extent possible without
those inputs; formal laboratory submission readiness is not yet established.

## Unified recovery scope and review delta

CR-19 now includes both PRs: bounded authenticated archive decoding, signed envelope/relay
consistency, exact schemas, independent monitor pins, reviewer approval, pre-serving logical row
checks and writer handover reconciliation. The source catalogue hashes the combined implementation
and all original/new regression files. CR-20 writer authority and the provider-neutral boundaries
remain unchanged. No SAG approval is inferred from use of published standard primitives.

The evaluator should review composition across snapshot publication, independent custody history,
review expiry, authorization seal, generation transfer, fresh lease and protected release. Partial
write, parent-fsync and SQLite capacity failures are software fault evidence only. Current keys
remain software-held; the encrypted archive contains authority/relay secrets and must receive an
approved custody and recovery procedure. The verifier never grants activation.

Exact commit/tree, Node/OpenSSL runtime report, module inventory, KATs and application digests,
SBOMs, licences, dependencies, final tests and failures are in the frozen candidate manifest and
hosted artifacts. The twenty-component catalogue is the exact machine-readable inventory; the
summary above does not claim a complete independent cryptographic discovery.

SAG grading is not established. Formal submission acceptance, agreed scope, laboratory access,
approved module/algorithm configuration, fees and any applicable waiver remain external inputs.
Public DRDO industry-support guidance and the 7 October 2026 MoD testing SOP announcement were
rechecked on 11 November 2026; see P0-046_ASSURANCE.md. No external request was sent.
