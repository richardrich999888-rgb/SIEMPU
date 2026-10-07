# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Research snapshot: 2026-10-08. Scope: synthetic/authorised environments only. Base: codex/siepmu-hpsc @ f6d75cf6b105319ca0d6942b2bbc196750a0b230. Prepared engineering analysis, not IAF approval, independent assurance or verified procurement quote.

Source hierarchy: official iDEX DISC-14 PS-69, printed pp. 161–162: https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf ; authoritative repository code/evidence; public standards/product documentation. Submitted annexures, sponsor directives, PDS/PRU and agreements are unavailable in this research run and must be reconciled before asserting filed commitments.

## Additive, evidence-first decisions
| Domain | Present capability | Candidate | Decision / validation |
|---|---|---|---|
| Application crypto | native WebCrypto; zero npm runtime dependencies | keep native provider; define versioned adapter | ADOPT design work; compare sign, encrypt, unwrap, key lifecycle conformance |
| HSM PKCS#11 | no hardware key provider | SoftHSM2 for CI + compatible production PKCS#11 | PROTOTYPE in isolated test; vendor-specific mapping and policy required |
| Strong login | password/TOTP + software signed device proof | FIDO2/WebAuthn hardware authenticators | PROTOTYPE; browser origins/recovery/accessibility and phishing resistance |
| Service TLS / identity | authenticated service HMAC on one host | native TLS/mTLS; SPIFFE/SPIRE if multi-host growth justifies | ADOPT mTLS baseline; DEFER SPIRE until host attestation design |
| Auth/PKI federation | internal authority | Keycloak / sponsor IdP protocol adapter | PROTOTYPE only after confirmed sponsor identity source; never replace epoch claim enforcement |
| Central policy | embedded transactional checks | OPA offline sidecar or policy bundle | DEFER unless complex policy size warrants; final transactional recheck stays in control |
| Telemetry | logs/metrics/alerts | OpenTelemetry collector | PROTOTYPE for redacted traces and security events, no message plaintext |
| Host threat telemetry | no external SOC | Wazuh agent/manager, Suricata/Zeek | PROTOTYPE in testbed; measure resource/privacy; E2EE content stays opaque |
| Network impairment | local loopback tests | tc/netem + Toxiproxy | ADOPT LAB; deterministic profiles and rollback |
| Security tests | native/tests, CodeQL, Trivy, Gitleaks | current tools first; Syft/Grype cross-check, cosign | FIX current gates; add extra tooling only if useful difference measured |
| Integrity updates | unsigned hashes | Cosign signing with offline verifiable root, provenance | PROTOTYPE for TRL6 release candidate |
| API | OpenAPI partial, synthetic validator | OpenAPI schema conformance, strict canonical envelope adapter | ADOPT schema coverage, parser rejects unknown/dangerous fields |
| Formal assurance | race tests; informal threat model | TLA+/PlusCal model for release order or Alloy | PROTOTYPE CTE-03 safety invariant, model-check counterexamples |

## Integration seams
1. Define CryptoProvider v1: supported_suites, create_identity, encrypt_object, sign_envelope, verify_envelope, wrap_for_recipient, unwrap_for_recipient, import/export public material, rotate/revoke; reject unknown suites and downgrades. No provider may receive unapproved plaintext or unwrapped key context.
2. Define IdentityProofProvider with strong-auth assertion, binding to user/device/request/epoch, anti-replay and freshness. Keep provider independent of IAF directory semantics.
3. Define PolicyEvaluationPort with decision + reason + policy-version digest; keep final authority transaction check in core.mjs, not remote eventual-consistency cache.
4. Define ObservationPort with redaction allowlist; emit event type, trace ID, epoch, pseudonymized actor and disposition only.

## Selection protocol
Obtain released version, license/SPDX, SBOM, security advisories, public CVEs, maintained branch/tag, upstream signed release, platform support and India procurement evidence for each pinned product BEFORE adoption. Candidate documentation is not a vetted dependency pin. No package enters production just because listed here.

References: https://nodejs.org/api/crypto.html ; https://spiffe.io/docs/latest/spire-about/ ; https://www.openpolicyagent.org/docs ; https://www.keycloak.org/documentation ; https://opentelemetry.io/docs/collector/ ; https://github.com/softhsm/SoftHSMv2
