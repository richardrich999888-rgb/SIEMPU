# 01 — Repository, architecture and dependency audit

Inspected revision: `86744a8` (`assurance/kat-and-gap-2026-10`, which contains PR #19 `2b3f9ab` ⊃ PR #18
`4190797` ⊃ PR #17 `12989fb` ⊃ `main` `ad80210`). Date 2026-10-10. Every statement below was checked
against the tree at that revision unless marked otherwise.

## 1. Branch and pull-request state

| Ref                                        | Head      | Relation                                                                       |
| ------------------------------------------ | --------- | ------------------------------------------------------------------------------ |
| `main`                                     | `ad80210` | Delivered prototype baseline                                                   |
| PR #17 `claude/siepmu-engineering-…`       | `12989fb` | Integrated platform; base of #18                                               |
| PR #18 `claude/siepmu-trl56-recovery-…`    | `4190797` | Rust verifier, TLA+ model, mission workflow; base of #19                       |
| PR #19 `claude/siepmu-trl5-24h-validation` | `2b3f9ab` | Advancement tests (TRL 4 kept, not TRL 5); found D-T5-01                       |
| `assurance/kat-and-gap-2026-10` (no PR)    | `86744a8` | KAT harness, gap analysis, claims gate, D-T5-01 baseline; **this work's base** |
| PR #15, #16 (`codex/…`)                    | —         | Superseded; selectively ported into #17 (ADR-006)                              |
| PR #13, #2                                 | —         | Superseded                                                                     |
| PR #3–#12 Dependabot                       | —         | #8 (Node 26) violates `engines <25`; #4/#6 need typecheck evaluation           |

Hosted results on the base: CI run 38046629830 **PASS**; Security run 38046629878 **FAIL** (CodeQL gate:
`js/file-system-race`, severity 7.7, `assurance/kat/io/sources.mjs:22`). Fixed on this branch (§9).

## 2. SYNTRIASS-developed components (source in this repository)

| Component                         | Path                                | Language | Notes                                             |
| --------------------------------- | ----------------------------------- | -------- | ------------------------------------------------- |
| Control authority                 | `services/control/`                 | Node     | Identity, policy, transactional release, evidence |
| Ciphertext relay                  | `services/relay/`                   | Node     | Ciphertext only, workload auth                    |
| Web gateway                       | `services/web/`                     | Node     | TLS ingress, same-origin proxy                    |
| Evidence custodian + guard        | `services/evidence/`                | Node     | Changed here (ADR-014)                            |
| Monitoring collector              | `services/monitoring/`              | Node     | Signed redacted telemetry                         |
| Synthetic integration adapter     | `services/integration/`             | Node     | Not an IAF interface                              |
| Endpoint crypto + vault           | `packages/crypto/`                  | Browser  | WebCrypto composition, no custom primitive        |
| Provider engine / suite policy    | `packages/crypto-provider/`         | Node     | Provider-neutral seam, lifecycle, downgrade guard |
| Canonical JSON                    | `packages/protocol/canonical.mjs`   | JS       | SIEPMU-CJSON-v1 (not RFC 8785)                    |
| TLS/mTLS profile                  | `packages/transport/`               | Node     | On `node:tls`                                     |
| Signed offline bundles            | `packages/release/`                 | Node     |                                                   |
| Independent verifier              | `apps/verifier/`                    | Node     | General + strict release modes                    |
| Rust reference verifier           | `native/evidence-verify/`           | Rust     | Own JSON parser and canonicaliser (ADR-012)       |
| TLA+ release/revocation model     | `formal/`                           | TLA+     | Faithful + mutant configurations                  |
| Lab PQC providers                 | `packages/pqc-lab/`                 | Node     | Excluded from every release artefact (ADR-008)    |
| Test, testbed, relevant-env tools | `tests/`, `deployment/`, `scripts/` | Node/sh  |                                                   |

"Developed here" means the source was written for this project. It does not make the algorithms, runtime or
libraries underneath indigenous (see `02-SOVEREIGNTY_MATRIX.md`).

## 3. Third-party software

| Item                                                           | Version / pin                                                               | Where it runs         | Role                                                 |
| -------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------- | ---------------------------------------------------- |
| Node.js (V8, libuv, OpenSSL, SQLite)                           | 24.21.0; container digest-pinned                                            | All services, runtime | Runtime, crypto, TLS, storage                        |
| OpenSSL (bundled in Node)                                      | 3.5.x (3.5.8 measured)                                                      | Runtime               | All server-side primitives, TLS, ML-KEM/ML-DSA (lab) |
| SQLite (bundled `node:sqlite`)                                 | Node 24 bundled                                                             | Runtime               | All persistent state                                 |
| Browser WebCrypto                                              | Browser vendor                                                              | Endpoint              | Endpoint primitives                                  |
| Alpine Linux base image                                        | `node:24.21.0-alpine3.24@sha256:ebfe…`                                      | Container             | OS userland                                          |
| `@noble/post-quantum`                                          | 0.7.1 (exact)                                                               | Lab only              | X-Wing hybrid KEM                                    |
| RustCrypto `p256`, `sha2`                                      | =0.13.2, =0.10.8 (+25 transitive; 28 crates in Cargo.lock incl. this crate) | Rust verifier         | ECDSA verify, SHA-256                                |
| ESLint, Prettier, TypeScript, Playwright, globals, @types/node | exact pins                                                                  | Development only      | Quality gates, browser tests                         |
| GitHub Actions, CodeQL, gitleaks, Trivy                        | action SHAs pinned                                                          | CI only               | Build, SAST, secret scan, image scan                 |
| TLA+ tools (TLC)                                               | operator-supplied jar                                                       | Verification only     | Model checking                                       |

Runtime npm dependency count: **0** (`package.json` has only `devDependencies`).

## 4. Cryptographic algorithms and implementations

| Use                               | Algorithm                                        | Implementation                                |
| --------------------------------- | ------------------------------------------------ | --------------------------------------------- |
| Payload encryption                | AES-256-GCM                                      | WebCrypto / OpenSSL                           |
| Recipient key wrapping            | Ephemeral P-256 ECDH + HKDF-SHA256 + AES-256-GCM | WebCrypto / OpenSSL                           |
| Envelope, evidence, lease signing | ECDSA P-256 / SHA-256, P1363                     | WebCrypto / OpenSSL; RustCrypto (verify only) |
| Hash chain, digests               | SHA-256                                          | OpenSSL; RustCrypto                           |
| Password storage                  | scrypt (N=2^14, r=8, p=1)                        | OpenSSL                                       |
| Local vault                       | PBKDF2-SHA256 600,000 iterations + AES-GCM       | WebCrypto                                     |
| MFA                               | TOTP (RFC 6238, HMAC-SHA1)                       | OpenSSL                                       |
| Transport                         | TLS 1.3, mTLS                                    | OpenSSL via `node:tls`                        |
| Lab PQC                           | ML-KEM-768/1024, ML-DSA-65; X-Wing               | OpenSSL 3.5 (Node); Noble                     |

No custom primitive exists. Every algorithm is a public international standard (NIST FIPS 197/180-4/186-5/
203/204, SP 800-38D/108, RFC 5869/6238/7914/8446) of foreign origin.
No algorithm, implementation or module here is SAG-graded or FIPS 140-validated by this project.

## 5. Database and storage

SQLite via `node:sqlite` for: authority (`control.sqlite`, versioned migrations 001–006), relay ciphertext
store, custodian anchor (`checkpoints.sqlite`), collector, verifier replay store. WAL journal,
`synchronous=FULL`, `BEGIN IMMEDIATE` for every security transaction. Single host; no replication.

## 6. Operating-system dependencies

Linux (Alpine in the container; any glibc/musl Linux for native runs). Testbeds: Linux network namespaces,
`tc` netem/TBF, Docker/Compose. No Windows/macOS server profile. Secure BOSS Linux not tested.

## 7. Network and transport

HTTP/1.1 over TLS 1.3 with mTLS between services (`packages/transport/tls.mjs`); QUIC disabled and asserted
at container build. A new TLS connection per client request (no reuse; measured ≈4× one-way delay per
request in `docs/trl5/PERFORMANCE_REPORT.md`).

## 8. Deployment dependencies

Native: Node 24 only. Container: digest-pinned base, npm removed from the runtime image, non-root UID.
Testbeds: Docker engine, kernel netem. Offline install: signed bundles (`packages/release/offline.mjs`).
CI: GitHub-hosted runners (foreign SaaS; build-time only, not runtime).

## 9. Security defects (found or open)

| ID       | Defect                                                                      | Status on this branch                 |
| -------- | --------------------------------------------------------------------------- | ------------------------------------- |
| CQ-1     | `js/file-system-race`: KAT vector reader stat-then-read (TOCTOU)            | **Fixed** `50303b5`, regression tests |
| D-T5-01a | Custody cost O(chain) per authorisation, twice per serialised request       | **Fixed** `d879b4a` (ADR-014)         |
| D-T5-01b | Availability cliff: >100k records (verifier) / >16 MiB body ⇒ permanent 503 | **Fixed** by bounded ranges (ADR-014) |
| E-1/E-2  | Conductor-provisioned profiles; shared-kernel test hosts                    | Open (environment, not code)          |
| L-1      | Authorization digest reads all identities per authorisation (O(identities)) | Open; next scaling item               |
| L-2      | Static recipient keys: no forward secrecy                                   | Open by design (documented)           |
| L-3      | Database snapshot rollback only detected with custody enabled               | Unchanged                             |

## 10. Hardware integration gaps

No PKCS#11, TPM 2.0, HSM, WebAuthn/FIDO2 or smart-card code exists. All keys are software keys. The provider
engine has the seam (`packages/crypto-provider/engine.mjs`), but no hardware provider has been implemented or
tested. See `08-INDIAN_CRYPTO_PROVIDER_PLAN.md`.

## 11. Performance bottlenecks (ordered by measured impact)

1. Custody full-chain re-verification — fixed (see `docs/assurance/d-t5-01-incremental.md`).
2. Serialised dispatch with two custodian round trips per request — remains; next candidate is to
   authorise once per request when no evidence was written before routing (needs a TLA+ check).
3. New TLS connection per client request — connection reuse not implemented.
4. Authorization digest over all identities per authorisation (L-1) — incremental state digest needed.
