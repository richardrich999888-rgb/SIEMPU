# Cryptographic standards and implementation decision

Source check: 2026-10-08. This is public-source engineering research; no restricted interface or operational data is used.

| Primary source                                                                                                | Current observed status                                                                          | SIEPMU decision                                                                                     |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)                                                    | Final 13 August 2024; potential errata noted 17 November 2025                                    | ML-KEM-768 and ML-KEM-1024 native endpoint experiments; track errata                                |
| [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)                                                    | Final 13 August 2024; potential errata noted 31 July 2026                                        | ML-DSA-65 experiment; no module-validation claim                                                    |
| [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)                                                    | Final 13 August 2024                                                                             | SLH-DSA investigated as hash-based diversity; not enabled without a justified size/latency use case |
| [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final)                                                | Final 18 September 2025                                                                          | KEM usage, authentication and key-establishment review reference                                    |
| [NIST CSWP 39upd1](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final) | Original 19 December 2025, updated 29 June 2026; supersedes withdrawn CSWP 39                    | Explicit provider policy, inventory, lifecycle, transition and fail-closed behavior                 |
| [RFC 10024](https://datatracker.ietf.org/doc/rfc10024/)                                                       | Proposed Standard, August 2026                                                                   | TLS hybrid groups are transport protection; never substitute them for endpoint E2EE                 |
| [X-Wing draft-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)                            | Individual draft dated 23 September 2026; not IETF-endorsed                                      | Published ML-KEM-768+X25519 composition, laboratory only, external integration review required      |
| [Node 24.19 crypto API](https://nodejs.org/download/release/v24.19.0/docs/api/crypto.html)                    | Native ML-KEM, ML-DSA, SLH-DSA APIs available                                                    | Reuse bundled OpenSSL primitives; do not implement lattice arithmetic                               |
| [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum/tree/0.7.1)                              | Version 0.7.1, 27 August 2026, MIT; upstream says no independent audit or constant-time JS claim | Isolated pinned dependency; exact author-vector tests and independent implementation interop        |
| [WICG modern WebCrypto](https://wicg.github.io/webcrypto-modern-algos/)                                       | Explicit unofficial proposal, not a W3C Standard                                                 | Probe exact selected browser versions; no blanket browser PQ capability claim                       |

## Decision: native endpoint reference plus isolated hybrid candidate

The native provider retains existing AES-256-GCM content encryption while changing endpoint KEM/signature operations behind the versioned provider boundary. Installed Node 24.19.0 used OpenSSL 3.5.7 during the initial experiments; the system `openssl` executable was separately 3.0.13. Version evidence must come from the runtime actually executing the operation.

X-Wing is implemented by the upstream `ml_kem768_x25519` preset, not by an invented combiner. Its domain separation and exact composition remain upstream-controlled. The engine's HKDF/AES-GCM wrapping binds the provider, suite, recipient key and object context separately. This application composition still requires independent review. TLS-specific secret concatenation cannot be lifted into a standalone KEM while assuming TLS transcript protections remain present.

Conformance experiments are limited to the precise cases documented in `packages/pqc-lab/README.md`. Native OpenSSL and Noble provide two implementations for interoperability; agreement alone cannot prove either implementation or the integrated protocol secure. Classical browser operation remains available under explicit policy. A PQ profile must fail when its selected endpoint provider is unavailable; server-side plaintext encryption and automatic classical fallback are forbidden.

Native X-Wing alternatives for subsequent qualification include [BoringSSL](https://github.com/google/boringssl/blob/main/include/openssl/xwing.h), [Cloudflare CIRCL](https://pkg.go.dev/github.com/cloudflare/circl/kem/xwing) and [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit/xwingmlkem768x25519), listed by the X-Wing authors. Selection requires version-specific provenance, licensing, side-channel analysis and deployment tests. Listing in a draft is not a certification.

## Messaging lessons

[Signal PQXDH](https://signal.org/docs/specifications/pqxdh/), revision 3 updated 23 January 2024, combines asynchronous key establishment with PQ forward secrecy but retains discrete-log-based authentication in that revision. [Double Ratchet revision 4](https://signal.org/docs/specifications/doubleratchet/), 4 November 2025, documents Sparse Post-Quantum Ratchet and Triple Ratchet. Sparse key agreement reduces bandwidth demands, while lost messages can delay post-compromise healing.

These designs provide useful state-management and deletion lessons. SIEPMU's one-shot object KEM is not a ratchet and does not inherit Signal's security analysis. A session-ratchet redesign is deferred until sponsor scope and long-lived session requirements justify its additional state, replay, crash-recovery and key-retention risks.

## Claims boundary

Algorithm standards, test-vector agreement and green CI do not establish module validation, independently reviewed composition, hardware key custody, SAG grading, IAF integration or TRL 5/6. Historical captured classical ciphertext is not retroactively protected by key migration. Revocation can deny new release; it cannot recall a key or plaintext already disclosed.
