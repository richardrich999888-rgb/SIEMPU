# Anticipated HPSC questions and evidence-backed answers

Answers apply to the frozen build `0e8d1b9`. Each points to where the evidence is. If a question
goes beyond the evidence, say so; do not improvise a capability.

## Security

| Question                                      | Answer                                                                                                                                                                                                                   | Evidence                          |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------- |
| Can the server read messages?                 | No. Content keys are wrapped to the recipient endpoint. The relay stores only ciphertext. The authority holds opaque wrapped keys and no recipient private key. A compromised endpoint can still disclose what it reads. | C01, C06; `docs/threat-model.md`  |
| Can an administrator decrypt?                 | The admin role does not bypass recipient checks and holds no recipient keys. Compromise of the host or authority is a separate trust boundary that we document.                                                          | `docs/security.md`                |
| What if a device is lost while offline?       | Revoke it. Its next request is refused, and no new key is released to it. Keys issued before revocation cannot be recalled.                                                                                              | Demo 4 step 9; C15                |
| What happens in a revoke-versus-release race? | Both serialise in one authority transaction, and commit order decides. Both orders are tested, including crashes.                                                                                                        | C04; `tests/authority.test.mjs`   |
| How is replay prevented?                      | Nonces, durable idempotency keys, a TOTP replay floor and a replay store in the verifier.                                                                                                                                | C05, C06; Demo 3 replay step      |
| What does a receipt prove?                    | That the authority committed this decision for these bound inputs. It does not prove endpoint truth or complete history without an independently held checkpoint.                                                        | C05; `spec/SIEPMU-EVIDENCE-v1.md` |
| Have you had an independent security test?    | No. It is budgeted (₹12 L VAPT and code review; ₹6 L crypto review). CodeQL, secret scanning, dependency audit and image scanning run on every commit.                                                                   | X09, X10                          |

## Cryptography

| Question                       | Answer                                                                                                                                                                                                                                    | Evidence                                                  |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Is it SAG graded?              | **No.** The classical suite uses standard primitives, and standard primitives do not satisfy SAG grading. The provider port is ready for an approved provider; the grading route needs the sponsor.                                       | C12; Q04, Q15                                             |
| Is it quantum-proof?           | We do not use that term. We have a **post-quantum research implementation**: ML-KEM and ML-DSA through the same release transaction, disabled by default, awaiting independent review.                                                    | C19; `research/cryptographic-standards/V3_COMPOSITION.md` |
| Why not HPKE?                  | We evaluated the HPKE post-quantum draft and reserved it as the next wrap format, once a reviewed implementation passes the draft's test vectors.                                                                                         | ADR-011                                                   |
| Which Indian crypto providers? | We surveyed the public record. One product holds an IC3S EAL3 certificate, and one module a FIPS 140-3 Level 1 certificate. None publicly documents an integration interface or a held SAG grade. Qualification is a funded work package. | `research/hpsc/indian-crypto-providers.md`                |

## TRL

| Question                                     | Answer                                                                                                                                                                                  | Evidence                          |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| What TRL are you?                            | **Provisional TRL 4**, self-assessed. Four elements are TRL 5 validation candidates.                                                                                                    | C20; `docs/trl/TRL_ASSESSMENT.md` |
| Why not TRL 5?                               | No relevant environment is defined, and all tests run on a single host or a simulated network. TRL 5 needs the sponsor's definition and a witnessed multi-host test (milestones M1–M2). | X02                               |
| Is the netem testbed a relevant environment? | No. It is a laboratory simulation of impairment with 10 zones on one runner (75/75).                                                                                                    | CTE-03                            |

## Sovereignty and deployment

| Question                                  | Answer                                                                                                                                                                                                                                 | Evidence                           |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| Does it depend on a foreign cloud?        | No. The runtime has zero npm dependencies and no external control plane. Operators hold the roots, and installation is offline and signed. Third-party components (Node.js, OpenSSL, SQLite) remain; we do not claim 100 % indigenous. | `docs/deployment/PROFILES.md`; C11 |
| Can it run air-gapped?                    | It has an isolated profile with signed offline bundles and rollback protection. The physical transfer procedure between enclaves needs authorisation.                                                                                  | `docs/secure-airgap-profile.md`    |
| Kubernetes?                               | Not needed for the current single-authority design. It would be evaluated in M3 if multi-host operation calls for it.                                                                                                                  | `docs/deployment/PROFILES.md`      |
| Does it integrate with AFNET or e-Office? | No. It integrates through an authenticated adapter, demonstrated with a synthetic document system. A real interface needs the sponsor's specification.                                                                                 | C16; X05                           |

## Funding and commercialisation

| Question                            | Answer                                                                                                                                                                        | Evidence                       |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| What will the grant buy?            | Validation, not invention: a relevant-environment test, a multi-host representative deployment, hardware-trust trials, Indian provider qualification and independent reviews. | `docs/hpsc/FUNDING_PLAN.md`    |
| How much, and on what basis?        | An engineering estimate of PDB ≈ ₹1.62 cr; the grant is capped at 50 % of PDB (≈ ₹0.81 cr). A third of the cost needs quotations. Founder-approved figures supersede these.   | `docs/hpsc/budget-inputs.json` |
| What is your matching contribution? | ⟨FOUNDER: sources and evidence⟩                                                                                                                                               | X15                            |
| Path to adoption?                   | Grant-validated evidence leads to sponsor-directed trials and then qualification. A grant is not a procurement commitment, and we do not represent it as one.                 | C22                            |
| Why trust a startup?                | The evidence is inspectable, the scope is bounded, the gaps are disclosed, and an independent validation plan is in place.                                                    | This package                   |
