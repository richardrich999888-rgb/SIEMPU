# PS-69 gap and compliance matrix

**Revision:** `0e8d1b9`. Hosted CI and Security are green on push and pull_request runs (CI
37761613000/37761620422, Security 37761613051/37761620429).

**Requirement source:** the DISC-14 compendium, PS-69, as recorded in
`docs/requirements/README.md`. The live challenge page could not be fetched from the build
environment.

**Status vocabulary** (the deck uses the same terms):

| Status                   | Meaning                                                  |
| ------------------------ | -------------------------------------------------------- |
| **Tested**               | Implemented and passing automated or scripted tests here |
| **Implemented**          | Code exists; not tested end to end                       |
| **Under development**    | Partial                                                  |
| **Proposed**             | Planned; no code yet                                     |
| **Externally dependent** | Requires a sponsor or third-party decision               |

## The eight published capability requirements

| #   | PS-69 requirement                                       | Status                                          | What exists                                                                                                                               | Evidence                                                                                          | Gap to close                                                                                |
| --- | ------------------------------------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| 1   | Cloud-based microservices architecture                  | **Tested** (lab)                                | Independently running gateway, authority, relay, checkpoint custodian, collector and adapter. Each has its own identity, storage and mTLS | Container and testbed CI jobs; `tests/transport/secure-stack.test.mjs`                            | No multi-host or approved cloud hosting. Authority is deliberately one transaction boundary |
| 2   | End-to-end encryption                                   | **Tested**                                      | Endpoint-held keys; ciphertext-only relay; authority holds opaque wrapped keys                                                            | `tests/crypto.test.mjs`, browser job, plaintext-canary checks                                     | Trusted-endpoint boundary; no hardware key custody                                          |
| 3   | Multi-factor authentication                             | **Tested**                                      | Password (scrypt) + TOTP with replay floor + device proof per operation                                                                   | `tests/authority.test.mjs`, Demo 4 step 2                                                         | No hardware tokens or IAF identity federation                                               |
| 4   | Secure communication protocols                          | **Tested** (lab PKI)                            | TLS 1.3 at the gateway; mTLS with pins and CRLs between services; HMAC-authenticated relay                                                | `tests/transport/tls.test.mjs`, testbed 75/75                                                     | No production PKI or OCSP                                                                   |
| 5   | Real-time threat monitoring and detection               | **Under development**                           | Rule alerts, independent signed-telemetry collector, operator acknowledgement; telemetry-stall defect fixed in `0e8d1b9`                  | Demo 4; `tests/monitoring.test.mjs`                                                               | Rule-based only; no analytics or SIEM/SOC interface (Q-sponsor)                             |
| 6   | Granular role-based access control                      | **Tested**                                      | Role, duty role, unit, mission, destination and FLASH dual control checked at release                                                     | `tests/filed-mission-*.test.mjs`, `tests/flash-approval.test.mjs`, `tests/access-alerts.test.mjs` | Six-duty-role and priority policy is **provisional applicant policy**                       |
| 7   | Integration with existing military systems and networks | **Externally dependent** (synthetic **tested**) | Authenticated adapter plus a synthetic document system (Demo 3)                                                                           | `tests/document-system.test.mjs`, Demo 3                                                          | Needs a sponsor interface specification and test endpoint (Q06)                             |
| 8   | SAG-graded encryption                                   | **Externally dependent**                        | Provider-neutral crypto port with policy gate and downgrade rejection                                                                     | `tests/crypto-agility/*`                                                                          | SAG process and approved provider not defined (Q04, Q15, Q16). **Not satisfied today**      |

## Further published expectations (requirement ledger R1–R12)

| ID  | Expectation                          | Status                    | Note                                                                                                  |
| --- | ------------------------------------ | ------------------------- | ----------------------------------------------------------------------------------------------------- |
| R2  | Reliability, integrity, authenticity | **Tested** (lab)          | Durable pending state; idempotent retry; signed evidence; restart tests                               |
| R3  | Real-time collaboration              | **Under development**     | Text and file exchange with delivery state; no chat or presence                                       |
| R10 | Secure storage                       | **Tested** (stated scope) | Ciphertext relay, encrypted vault, plaintext-canary checks; secrets are host files, not HSM-protected |
| R11 | Scalability and flexibility          | **Under development**     | Bounded queues and measured single-host timings; no sponsor scale target (Q07)                        |
| R12 | QA / certification testing           | **Externally dependent**  | Reproducible evidence and traceability; agency gates undefined (Q11)                                  |

## Applicant-proposed capabilities (not PS-69 mandates)

| Capability                                          | Status                        | Note                                                                                                |
| --------------------------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------- |
| Policy-epoch-bound release (Trust Before Release)   | **Tested**                    | Core differentiator; issuance committed before revocation cannot be recalled                        |
| Post-quantum cryptography                           | **Tested** (laboratory only)  | ML-KEM/ML-DSA lab suites, disabled by default and unreviewed                                        |
| Air-gap-native / isolated operation                 | **Implemented** (lab profile) | Isolated profile and signed offline bundles; transfer procedure unauthorised                        |
| Six duty roles, four priorities, FLASH dual control | **Tested**                    | Provisional applicant policy, pending sponsor confirmation                                          |
| Sovereign operator control                          | **Implemented**               | Operator-held roots, offline install and no external control plane. Third-party dependencies remain |
