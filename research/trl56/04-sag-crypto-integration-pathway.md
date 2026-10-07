# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Review date: 2026-10-08 (India). Frozen implementation: `main` at `49774e2111197412efb31d459317c0df23a838af`.
Engineering plan for synthetic, authorised tests; not SAG/IAF approval or a TRL award.
Source hierarchy: official PS-69, filed-proposal copies, frozen code and execution evidence, then candidate documentation.
See [source register](source-evidence-register.json) and [proposal reconciliation](17-proposal-reconciliation.md).

## Mandatory sponsor-dependent requirement

Official PS-69: the encryption algorithm should be SAG graded. DRDO public research lists SAG cryptography, formal assurance and security-evaluation work: https://drdo.gov.in/drdo/en/offerings/technology-foresight/cyber-information-communication-security . Public material does not specify a SIEPMU grading test procedure, approved suite list, cryptographic module, classified algorithm or procurement path. Do not invent any.

## Provider contract (engineering proposal)

CryptoProvider v1 should provide: suiteDescriptor(algorithmIDs, security policy hash, key provenance); generate/import public identity; sign/verify detached envelope context; encrypt/decrypt content AEAD; wrap/unwrap content-key; monotonic anti-downgrade check; key renew/decommission; conformance vectors and error taxonomy. Keep private key handles opaque; forbid export if policy marks nonexportable; fail closed if suite unsupported. Every envelope includes suite/version/key IDs authenticated as context and exactly one approved algorithm path.

## Cryptographic custody architecture

- Endpoint boundary: plaintext and data-encryption-key generated at sender; recipient receives only after authorised release; server must not acquire recipient private keys.
- Control boundary: controls _when_ the opaque wrapped key is released via current policy epoch transaction.
- Relay: ciphertext and routing metadata only.
- Provider: can be native WebCrypto (LAB-ONLY) or sponsor-approved native SDK/HSM adapter; never silently fall back on provider load failure.
- Logs: never output secret keys, plaintext or MFA seeds. KDF salts are normally public parameters; minimise correlatable metadata without claiming salts are secret.

## Migration programme

A: freeze existing native suite semantics and cross-implementation known-answer tests. B: version/feature negotiate signed suite constraints and deny downgrade. C: develop PKCS#11/SDK proof-of-concept behind adapter using lab emulator and a security token. D: request authorised interface and permitted grading route. E: conformance tests with approved provider; end-to-end interoperability, loss of token, restart, rotation, expiry, compromise and recovery. F: record SAG/IAF decision for exact deployed build/configuration. None of C–F implies agency approval.

## Clarification register

| ID     | Question                                                                   | Decision owner                                   | Blocked evidence           |
| ------ | -------------------------------------------------------------------------- | ------------------------------------------------ | -------------------------- |
| SAG-01 | Which grading/authorisation path and permitted algorithms apply?           | IAF sponsor + authorised cryptographic authority | Compliance claim           |
| SAG-02 | Which software/hardware implementation, interface and SDK may be supplied? | Sponsor/approved supplier                        | Product provider selection |
| SAG-03 | Which endpoints may retain content keys? Is escrow mandatory?              | Security owner                                   | Key-custody policy         |
| SAG-04 | What formal KAT/conformance and graded evaluation dossier are required?    | Authorised evaluator                             | Approved provider evidence |
| SAG-05 | Rules for key provisioning, handling, destruction, repair and audit?       | Information owner                                | Lifecycle acceptance       |
| SAG-06 | What suite transition, rollback and dual-provider migration is allowed?    | Cryptographic authority                          | Legacy interoperability    |

**Approval is external.** Synthetic WebCrypto tests can validate protocol logic only; they cannot prove graded cryptographic acceptance.
