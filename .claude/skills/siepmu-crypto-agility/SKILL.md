---
name: siepmu-crypto-agility
description: Cryptographic provider interfaces, supported suites, classical compatibility, the post-quantum laboratory providers (ML-KEM, ML-DSA, X-Wing), envelope schema versions, suite policy, downgrade prevention and key lifecycle in SIEPMU. Use before touching packages/crypto, packages/crypto-provider, packages/pqc-lab, services/crypto-policy, envelope schemas, or any statement about quantum resistance or SAG.
---

# SIEPMU crypto-agility

## Layers (do not collapse them)

| Layer                            | Module                                                                                                                                | Runs where               | Notes                                                                                                                                                                             |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Classical endpoint object crypto | `packages/crypto/crypto.mjs` (`createObjectCryptography(provider)`)                                                                   | browser + Node endpoints | Suite `P256-HKDF-SHA256-AES256GCM`: P-256 ECDH, HKDF-SHA256, AES-256-GCM, ECDSA P-256. Schema v1/v2 only. Imports only `canonical.mjs` (ADR-007)                                  |
| Classical provider port          | `crypto.mjs` `createWebCryptoProvider`, `negotiateSuite`; `packages/crypto/providers/node-classic.mjs`                                | endpoints                | Opaque software handles; no fallback provider. Tests: `tests/crypto-provider.test.mjs`                                                                                            |
| Provider engine                  | `packages/crypto-provider/engine.mjs` (`CryptoEngine`), `registry.mjs`, `policy.mjs`, `primitives.mjs`, `classical.mjs`, `legacy.mjs` | endpoints only           | Key generation/import, lifecycle (active/retired/revoked, rotate, migrate), hash-chained config evidence, `wrapKey`/`unwrapKey`. Tests: `tests/crypto-agility/providers.test.mjs` |
| PQC wire identifiers             | `packages/crypto-provider/pqc-identifiers.mjs`                                                                                        | services and endpoints   | Suite IDs, byte sizes, strict decoders. The only PQC module services may import (ADR-008)                                                                                         |
| PQC lab providers                | `packages/pqc-lab/native-provider.mjs` (OpenSSL ML-KEM-768/1024 + ML-DSA-65), `xwing-provider.mjs` (Noble X-Wing, unaudited)          | **lab endpoints only**   | Never in `dist/`, container or offline bundle                                                                                                                                     |
| Authority crypto policy          | `services/crypto-policy/registry.mjs` (`CryptoPolicyRegistry`), `database/migrations/005-crypto-policy.sql`                           | authority                | Public keys only; policy revisions advance by one; `reason(e, creation)` gates suites and key status                                                                              |

## Suites

| Provider ID                | Suite ID                               | KEM                                                         | Signature            | Status                    |
| -------------------------- | -------------------------------------- | ----------------------------------------------------------- | -------------------- | ------------------------- |
| `siepmu-webcrypto-p256-v1` | `P256-HKDF-SHA256-AES256GCM`           | P-256 ECDH                                                  | ECDSA P-256          | default production policy |
| `node-openssl-pqc-lab`     | `ML-KEM-768-ML-DSA-65-AES-256-GCM-v1`  | ML-KEM-768 (FIPS 203)                                       | ML-DSA-65 (FIPS 204) | laboratory                |
| `node-openssl-pqc-lab`     | `ML-KEM-1024-ML-DSA-65-AES-256-GCM-v1` | ML-KEM-1024                                                 | ML-DSA-65            | laboratory                |
| `noble-xwing-lab`          | `X-WING-ML-DSA-65-AES-256-GCM-v1`      | X-Wing (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem) | ML-DSA-65            | laboratory, hybrid KEM    |

Key wrapping in the engine: KEM shared secret -> HKDF-SHA256 (32-byte salt, domain-separated
info binding provider, suite, recipient key ID and context) -> AES-256-GCM over the 32-byte
content key with canonical AAD. This is a KEM/DEM composition, not a new combiner. No custom
hybrid combiner exists; the hybrid property comes only from X-Wing's published construction.
HPKE (RFC 9180) with PQ KEMs is the standards-track alternative for independent review.

## Versions are separate

Envelope **schema** version (1, 2, 3) is not the **suite** version (`suiteVersion`) and not the
crypto **policy** revision (`suitePolicyRevision`). Never change an encoding under an existing version.

## Enforcement points (fail closed)

- Lab gate: authority reads `SIEPMU_ALLOW_PQC_LAB` (only omitted or exactly `1`).
- Policy: `validateCryptoPolicy` rejects lab suites when `mode: 'production'`.
- `requireCryptoPolicy` distinguishes `newSuites` (creation) and `legacySuites` (historical use).
- Downgrade: unknown schema, suite or provider throws; a failed provider raises
  "fallback is forbidden"; retired keys cannot sign; revoked keys cannot be used at all.
- Persisted envelopes re-validated at release in `services/admission/integrity.mjs`.

See `docs/engineering/CURRENT_STATE.md` for whether the v3 authority release path is wired on
the current SHA. Do not claim system-level PQC E2EE beyond what that file records.

## Required checks before a crypto change

1. No private key or plaintext crosses into services. Grep the diff for `privateKey` in `services/`.
2. No new browser import from `crypto.mjs`.
3. Negative tests for: suite substitution, schema downgrade, wrong-purpose key, revoked key,
   altered AAD/context, provider failure, policy revision rollback.
4. Known-answer vectors come from the standard's authors or NIST, never regenerated by the
   implementation under test (`packages/pqc-lab/fixtures/PROVENANCE.md`).

## Commands

```sh
node --test --test-concurrency=1 tests/crypto.test.mjs tests/crypto-provider.test.mjs tests/crypto-agility/*.test.mjs tests/pqc/*.test.mjs
npm ci --prefix packages/pqc-lab --ignore-scripts && npm --prefix packages/pqc-lab test   # X-Wing KATs, Noble/OpenSSL interop
node packages/pqc-lab/benchmark.mjs > artifacts/pqc-benchmark.json                          # create artifacts/ first
```

## Language and approval limits

NIST standardisation, OpenSSL support, passing KATs or PKCS#11 integration do **not** make an
implementation SAG-graded, FIPS-validated or IAF-approved. Noble 0.7.1 is unaudited and not
constant-time. Software handles are not hardware custody. ML-KEM alone gives no sender
authentication or forward secrecy. Re-wrapping does not protect ciphertext already captured.
Standards research: `research/cryptographic-standards/CURRENT_STANDARDS.md`, review gate:
`research/cryptographic-standards/INDEPENDENT_REVIEW.md`, SAG pathway:
`research/trl56/04-sag-crypto-integration-pathway.md`.

## Definition of done

All commands above pass, the pqc-lab CI job passes, negative tests added, docs
(`docs/crypto.md`, `docs/crypto-provider-boundary.md`) and CURRENT_STATE updated, no approval language.
