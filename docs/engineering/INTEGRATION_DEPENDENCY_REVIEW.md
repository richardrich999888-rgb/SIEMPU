# Integration dependency review — 7 November 2026

Inspected baseline: PR #32, `5c465d290a002a551a83ef74b235cd5a97990da8`.
The application currently has no npm runtime dependencies; six exact-pinned development
packages are in package.json. Rust verification, optional NEXORA and laboratory PQC
have separate dependency boundaries. This review is a proposed integration shortlist,
not an installation record or an IAF selection. No new third-party dependency is installed
by the sealed-transport change.

## Decisions

| Gap                                   | Candidate                                                                                  | Wiring decision and acceptance evidence                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G02 personnel identity                | Self-hosted Keycloak and `openid-client`                                                   | First identity integration candidate. Use OIDC authorization-code flow with PKCE, pinned issuer/client/audience, nonce/state and bounded expiry. Map issuer+subject to a locally enrolled identity; issuer roles must not bypass current authority policy, duty roles or device proof. Test revoked user/device, disabled account, issuer/key rollover, wrong issuer/audience, replay and issuer outage. IAF must nominate the real issuer/PKI and lifecycle policy. |
| G02 stronger login                    | Keycloak WebAuthn, or `@simplewebauthn/server` plus browser client if login remains native | Choose one registration/login owner. Require appropriate user verification and an agreed authenticator/recovery policy. A WebAuthn login key is not automatically a document encryption key. Test origin/RP binding, challenge reuse, lost tokens and account recovery.                                                                                                                                                                                              |
| G03/G04 crypto module and key custody | Vendor PKCS#11 library or supplied SDK; Rust `cryptoki` is a possible wrapper              | First obtain the hardware/module API and mechanism list. Build a separate provider adapter, exercise sign/derive/wrap operations actually required by SIEPMU, and fail closed on removal/error. SoftHSM2 is a software lab fixture only; it does not validate physical protection. No module selection or SAG outcome is established by PKCS#11 compatibility.                                                                                                       |
| G04 infrastructure secrets            | OpenBao, optionally its `kms-pkcs11` plugin                                                | Optional for infrastructure credentials. The PKCS#11 seal protects OpenBao auto-unseal; it does not establish that every application operation happens inside an HSM. Do not route document plaintext to a central Transit service: endpoint-only encryption remains the product boundary.                                                                                                                                                                           |
| G12 SOC export                        | Self-hosted OpenTelemetry Collector                                                        | Optional adapter for explicitly allowed, already-redacted operational events/metrics. Preserve original signed evidence separately. Use mTLS and approved destinations; test data canaries, loss/backpressure, duplicate/reordered delivery, retry bounds and receiver outage. Telemetry export does not prove completeness or replace evidence verification.                                                                                                        |
| G07/G10/G16 validation                | ZAP baseline and k6                                                                        | Assessment tooling, outside runtime. ZAP baseline crawls and passively scans; it is not a complete penetration test. k6 thresholds can make agreed latency/error/load limits fail a job. Existing browser, network impairment, CodeQL and adversarial tests remain required. Full authentication/device-proof workloads need a real client driver, not unauthenticated health checks.                                                                                |
| G05 plaintext integration             | Existing endpoint cryptography and native Node/SQLite                                      | No external plugin is necessary. Seal/sign at source; give the connector ciphertext only; keep the wrapped key, grants, bearer session and admission proof on the source-to-authority control path. The new v2 staging path implements this separation.                                                                                                                                                                                                              |
| G06 authority availability            | Design work before package selection                                                       | Keycloak clustering, a database swap or Kafka does not establish single-writer fencing, custody continuity or safe release during partitions. Define failure domains and RPO/RTO, then implement and test the chosen design.                                                                                                                                                                                                                                         |

NEXORA remains optional offline evidence verification. It is not currently the personnel
identity provider. OPA, Kafka, MongoDB or a service mesh are not prerequisites for this
increment; introducing them needs a concrete unmet requirement and measured benefit.

The root runtime dependency guard remains in force. An OIDC or hardware SDK integration
needs a separately defined adapter boundary (or a reviewed architecture change) before
adding packages; the table is not an instruction to bypass the existing dependency gate.

## Version and supply-chain decision

Do not install moving `latest` tags or an entire suggested stack. Select supported releases,
resolve exact package versions/container digests, record transitive dependencies and licenses,
run npm/Rust/container advisory checks, and retain offline artifacts before adoption.
This is deliberately not a claim that the shortlisted projects are vulnerability-free.

One concrete finding: RustSec RUSTSEC-2026-0286 reports an out-of-bounds read in `cryptoki`
when decoding CKA_ALLOWED_MECHANISMS. Its published patched ranges are >=0.10.1 <0.11.0,

> =0.11.1 <0.12.0, and >=0.12.1. A new wrapper must select a supported patched release and
> pass a fresh audit; fixing this advisory alone is not a complete dependency assessment.

The actual remaining external dependencies are the IAF identity/interface specification,
the permitted cryptographic module/profile and the relevant-environment acceptance criteria.
Open-source services do not supply those decisions. Complete-platform TRL 5 remains pending
validation against the declared assessment gates; no dependency creates a grading or TRL decision.

## Primary sources checked

- Keycloak administration (OIDC, federation, WebAuthn): https://www.keycloak.org/docs/latest/server_admin/index.html
- Keycloak production requirements: https://www.keycloak.org/server/configuration-production
- OIDC client: https://github.com/panva/openid-client
- Native WebAuthn alternative: https://simplewebauthn.dev/docs/packages/server
- PKCS#11 Rust wrapper: https://github.com/parallaxsecond/rust-cryptoki
- Concrete advisory: https://rustsec.org/advisories/RUSTSEC-2026-0286.html
- Software token fixture: https://github.com/softhsm/SoftHSMv2
- OpenBao PKCS#11 seal: https://openbao.org/docs/configuration/seal/pkcs11/
- OpenBao Transit boundary: https://openbao.org/docs/secrets/transit/
- OpenTelemetry sensitive-data handling: https://opentelemetry.io/docs/security/handling-sensitive-data/
- ZAP baseline scope: https://www.zaproxy.org/docs/docker/baseline-scan/
- k6 pass/fail thresholds: https://grafana.com/docs/k6/latest/using-k6/thresholds/
