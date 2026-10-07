# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Review date: 2026-10-08 (India). Frozen implementation: `main` at `49774e2111197412efb31d459317c0df23a838af`.
Engineering plan for synthetic, authorised tests; not SAG/IAF approval or a TRL award.
Source hierarchy: official PS-69, filed-proposal copies, frozen code and execution evidence, then candidate documentation.
See [source register](source-evidence-register.json) and [proposal reconciliation](17-proposal-reconciliation.md).

## Additive, evidence-first decisions

| Domain                 | Present capability                              | Candidate                                                     | Decision / validation                                                                               |
| ---------------------- | ----------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Application crypto     | native WebCrypto; zero npm runtime dependencies | keep native provider; define versioned adapter                | KEEP EXISTING provider; PROTOTYPE adapter; compare sign, encrypt, unwrap, key lifecycle conformance |
| HSM PKCS#11            | no hardware key provider                        | SoftHSM2 for CI + compatible production PKCS#11               | PROTOTYPE in isolated test; vendor-specific mapping and policy required                             |
| Strong login           | password/TOTP + software signed device proof    | FIDO2/WebAuthn hardware authenticators                        | PROTOTYPE; browser origins/recovery/accessibility and phishing resistance                           |
| Service TLS / identity | authenticated service HMAC on one host          | native TLS/mTLS; SPIFFE/SPIRE if multi-host growth justifies  | PROTOTYPE mTLS baseline; DEFER SPIRE until host attestation design                                  |
| Auth/PKI federation    | internal authority                              | Keycloak / sponsor IdP protocol adapter                       | DEFER until confirmed sponsor identity source; never replace epoch claim enforcement                |
| Central policy         | embedded transactional checks                   | OPA offline sidecar or policy bundle                          | DEFER unless complex policy size warrants; final transactional recheck stays in control             |
| Telemetry              | logs/metrics/alerts                             | OpenTelemetry collector                                       | PROTOTYPE for redacted traces and security events, no message plaintext                             |
| Host threat telemetry  | no external SOC                                 | Wazuh agent/manager, Suricata/Zeek                            | DEFER product selection; first prove redacted events to an independent sink                         |
| Network impairment     | local loopback tests                            | tc/netem first; Toxiproxy deferred                            | PROTOTYPE LAB; deterministic profiles, frozen kernel/package versions and cleanup                   |
| Security tests         | native/tests, CodeQL, Trivy, Gitleaks           | current tools first; Syft/Grype cross-check, cosign           | KEEP passed frozen gates; add tooling only for a measured gap                                       |
| Integrity updates      | unsigned hashes                                 | Cosign signing with offline verifiable root, provenance       | PROTOTYPE for TRL6 release candidate                                                                |
| API                    | OpenAPI partial, synthetic validator            | OpenAPI schema conformance, strict canonical envelope adapter | PROTOTYPE schema coverage, parser rejects unknown/dangerous fields                                  |
| Formal assurance       | race tests; informal threat model               | TLA+/PlusCal model for release order or Alloy                 | PROTOTYPE CTE-03 safety invariant, model-check counterexamples                                      |

## Integration seams

1. Define CryptoProvider v1: supported_suites, create_identity, encrypt_object, sign_envelope, verify_envelope, wrap_for_recipient, unwrap_for_recipient, import/export public material, rotate/revoke; reject unknown suites and downgrades. No provider may receive unapproved plaintext or unwrapped key context.
2. Define IdentityProofProvider with strong-auth assertion, binding to user/device/request/epoch, anti-replay and freshness. Keep provider independent of IAF directory semantics.
3. Define PolicyEvaluationPort with decision + reason + policy-version digest; keep final authority transaction check in core.mjs, not remote eventual-consistency cache.
4. Define ObservationPort with redaction allowlist; emit event type, trace ID, epoch, pseudonymized actor and disposition only.

## Selection protocol

Obtain released version, license/SPDX, SBOM, security advisories, public CVEs, maintained branch/tag, upstream signed release, platform support and India procurement evidence for each pinned product BEFORE adoption. Candidate documentation is not a vetted dependency pin. No package enters production just because listed here.

References: https://nodejs.org/api/crypto.html ; https://spiffe.io/docs/latest/spire-about/ ; https://www.openpolicyagent.org/docs ; https://www.keycloak.org/documentation ; https://opentelemetry.io/docs/collector/ ; https://github.com/softhsm/SoftHSMv2
