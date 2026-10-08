# Rust dependency record (`native/`)

Every crate is pinned in `native/Cargo.lock` and built with `--locked`. Licence fields below were read
from the downloaded crate manifests (crates.io index, 2026-10-08), not from memory.

## Direct dependencies

| Crate                                 | Version | Source                                | Purpose                                       | Licence           | Alternative considered                                                                                                                                                                                                                         |
| ------------------------------------- | ------- | ------------------------------------- | --------------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `p256` (feature `ecdsa`, no defaults) | =0.13.2 | crates.io, RustCrypto/elliptic-curves | P-256 point validation and ECDSA verification | Apache-2.0 OR MIT | `ring` 0.17 (fast, C/asm build, no JWK-level control needed); `aws-lc-rs` (AWS-LC, FIPS-validated module family, CMake build). Rejected for v1 on build/supply-chain size; `aws-lc-rs` is the named candidate if throughput matters (ADR-011). |
| `sha2` (no defaults)                  | =0.10.8 | crates.io, RustCrypto/hashes          | SHA-256 for key IDs and chain hashes          | MIT OR Apache-2.0 | Already a transitive dependency of `p256`; no extra code.                                                                                                                                                                                      |

JSON parsing, canonical encoding and base64url are implemented in this crate (about 800 lines including unit tests)
because the contract requires behaviour general-purpose crates do not guarantee (spec §3, §8).

## Transitive dependencies (normal)

`base16ct 0.2.0`, `block-buffer 0.10.4`, `cfg-if 1.0.5`, `const-oid 0.9.6`, `cpufeatures 0.2.17`,
`crypto-bigint 0.5.5`, `crypto-common 0.1.6`, `der 0.7.10`, `digest 0.10.7`, `ecdsa 0.16.9`,
`elliptic-curve 0.13.8`, `ff 0.13.1`, `generic-array 0.14.9`, `group 0.13.0`, `hmac 0.12.1`,
`primeorder 0.13.6`, `rand_core 0.6.4`, `rfc6979 0.4.0`, `sec1 0.7.3`, `signature 2.2.0`, `subtle 2.6.1`,
`typenum 1.20.1`, `zeroize 1.9.1`. Build-only: `version_check 0.9.5`.

Licences: all `Apache-2.0 OR MIT` (or `MIT/Apache-2.0`), except `generic-array` (MIT) and `subtle`
(BSD-3-Clause). All are compatible with the project's Apache-2.0 licence.

## Security assumptions and limits

- `p256`, `ecdsa` and `elliptic-curve` declare `#![forbid(unsafe_code)]`; `sha2`, `generic-array`,
  `zeroize`, `cpufeatures` and others contain `unsafe` blocks (SIMD, memory zeroing).
- Verification handles only public data, so constant-time behaviour is not a requirement for this
  component; it would be for any future signing or decapsulation component.
- No claim is made that these crates are independently audited, FIPS-validated or approved by any
  authority. Cryptographic library approval for operational use is an external (SAG) decision.
- Known vulnerabilities: checked with `cargo audit` against the RustSec advisory database in CI
  (`native` job). Result for the committed lockfile is recorded in `docs/engineering/CURRENT_STATE.md`.

## Runtime and integration cost

0.5 MB statically linked release binary, no runtime, no network, no file writes. Build adds a Rust
toolchain to CI only; the Node runtime, container image and offline bundles are unchanged
(`native/` and `spec/` are excluded by `.dockerignore`).
