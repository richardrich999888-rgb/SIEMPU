# AIRON–SIEPMU Defence Research | 2026-10-08

Review date: 2026-10-08 (India). Frozen implementation: `main` at `49774e2111197412efb31d459317c0df23a838af`.
Engineering plan for synthetic, authorised tests; not SAG/IAF approval or a TRL award.
Source hierarchy: official PS-69, filed-proposal copies, frozen code and execution evidence, then candidate documentation.
See [source register](source-evidence-register.json) and [proposal reconciliation](17-proposal-reconciliation.md).

## Build versus buy decisions

| Need                                      | Preferred                                                  | Why                                                            | Gate                                         |
| ----------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------- |
| Policy-epoch issuing transaction          | KEEP INTERNAL                                              | Custom invariant already exercised; central to differentiation | model & regression tests                     |
| Envelope/authenticated context format     | KEEP INTERNAL but external review                          | protocol compatibility tightly coupled                         | cryptographer assessment                     |
| Endpoint crypto primitive implementations | USE vetted platform providers                              | never implement AES/ECDSA by hand                              | cross-provider conformance, SAG later        |
| Cryptographic device integration          | ADAPTER to standard interface                              | HSM vendor lock-in avoidance                                   | PKCS#11 mechanism and key-custody test       |
| Browser identity                          | FIDO2/WebAuthn as additive                                 | resists phishing better than TOTP                              | browser support and recovery design          |
| Policy engine                             | KEEP integrated short-term                                 | OPA add-on adds failure and consistency boundaries             | consider when complexity needs it            |
| TLS/PKI                                   | STANDARD LIBRARY + controlled issuer                       | mature transport infrastructure                                | authenticated ingress certificate tests      |
| Audit storage                             | BUILD external checkpoint integration                      | gap is trust custody not blockchain                            | tamper/snapshot recovery tests               |
| EDR/NDR/SIEM                              | USE separate defensive product                             | no need to write detection engine                              | redaction/privacy and CPU budget             |
| Network simulation                        | tc/netem first; Toxiproxy only for a demonstrated gap      | deterministic, simple reproducible                             | repeatability and log hash                   |
| Vulnerability/SBOM                        | KEEP existing CodeQL+Trivy                                 | frozen release blockers resolved; continuous revalidation      | all candidate gates PASS with source binding |
| Military adaptor                          | BUILD synthetic neutral shell; sponsor interfaces external | unknown classified interface unavailable                       | authorised IAF interface owner               |

## Hard requirements for adoption

Permit/restrictions of licenses including AGPL and non-commercial research licenses; export/import controls; no copyleft leakage into proprietary linking unless legally approved; vendor provenance; vulnerability advisory; supported OS/CPU; signed binary; secure offline mirror; key ownership; sponsor cryptographic acceptance. No weighted score overrides a failed hard gate.

## Supply chain flow

Pinned source and reproducible build recipe -> SBOM (app + image) -> SCA/CVE triage -> static/secret scans -> permission-minimal CI -> signed manifest/images (proposed) -> offline trust roots -> acceptance verification + rollback path. Exclude private annexures, .env, secrets and operational materials from public repo.
