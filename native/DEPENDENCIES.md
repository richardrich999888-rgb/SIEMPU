# Rust dependency record (`native/`)

Every crate is pinned in `native/Cargo.lock` and built with `--locked`. Licence fields below were read
from the downloaded crate manifests (crates.io index, 2026-11-07), not from memory.

## Direct dependencies

| Crate                                 | Version | Source                                | Purpose                                       | Licence           | Alternative considered                                                                                                                                                                                                                         |
| ------------------------------------- | ------- | ------------------------------------- | --------------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `p256` (feature `ecdsa`, no defaults) | =0.14.0 | crates.io, RustCrypto/elliptic-curves | P-256 point validation and ECDSA verification | Apache-2.0 OR MIT | `ring` 0.17 (fast, C/asm build, no JWK-level control needed); `aws-lc-rs` (AWS-LC, FIPS-validated module family, CMake build). Rejected for v1 on build/supply-chain size; `aws-lc-rs` is the named candidate if throughput matters (ADR-012). |
| `sha2` (no defaults)                  | =0.11.1 | crates.io, RustCrypto/hashes          | SHA-256 for key IDs and chain hashes          | MIT OR Apache-2.0 | Already a transitive dependency of `p256`; no extra code.                                                                                                                                                                                      |

JSON parsing, canonical encoding and base64url are implemented in this crate (about 800 lines including unit tests)
because the contract requires behaviour general-purpose crates do not guarantee (spec §3, §8).

## Locked dependencies

The table includes direct, transitive, build and target-specific entries from the lockfile.
Licence declarations were read from each downloaded manifest. They are compatible with
Apache-2.0; they do not establish independent cryptographic assessment.

| Crate            | Version | Declared licence  |
| ---------------- | ------- | ----------------- |
| `autocfg`        | 1.5.1   | Apache-2.0 OR MIT |
| `base16ct`       | 1.0.0   | Apache-2.0 OR MIT |
| `block-buffer`   | 0.12.1  | MIT OR Apache-2.0 |
| `cfg-if`         | 1.0.5   | MIT OR Apache-2.0 |
| `cmov`           | 0.5.4   | Apache-2.0 OR MIT |
| `const-oid`      | 0.10.2  | Apache-2.0 OR MIT |
| `cpubits`        | 0.1.1   | MIT OR Apache-2.0 |
| `cpufeatures`    | 0.3.1   | MIT OR Apache-2.0 |
| `crypto-bigint`  | 0.7.10  | Apache-2.0 OR MIT |
| `crypto-common`  | 0.2.2   | MIT OR Apache-2.0 |
| `ctutils`        | 0.4.8   | Apache-2.0 OR MIT |
| `der`            | 0.8.3   | Apache-2.0 OR MIT |
| `digest`         | 0.11.3  | MIT OR Apache-2.0 |
| `ecdsa`          | 0.17.0  | Apache-2.0 OR MIT |
| `elliptic-curve` | 0.14.3  | Apache-2.0 OR MIT |
| `ff`             | 0.14.0  | MIT/Apache-2.0    |
| `group`          | 0.14.0  | MIT/Apache-2.0    |
| `hmac`           | 0.13.0  | MIT OR Apache-2.0 |
| `hybrid-array`   | 0.4.15  | MIT OR Apache-2.0 |
| `libc`           | 0.2.190 | MIT OR Apache-2.0 |
| `num-traits`     | 0.2.19  | MIT OR Apache-2.0 |
| `p256`           | 0.14.0  | Apache-2.0 OR MIT |
| `primefield`     | 0.14.0  | Apache-2.0 OR MIT |
| `primeorder`     | 0.14.0  | Apache-2.0 OR MIT |
| `rand_core`      | 0.10.1  | MIT OR Apache-2.0 |
| `rfc6979`        | 0.6.0   | Apache-2.0 OR MIT |
| `sec1`           | 0.8.1   | Apache-2.0 OR MIT |
| `sha2`           | 0.11.1  | MIT OR Apache-2.0 |
| `signature`      | 3.0.0   | Apache-2.0 OR MIT |
| `subtle`         | 2.6.1   | BSD-3-Clause      |
| `typenum`        | 1.20.1  | MIT OR Apache-2.0 |
| `wnaf`           | 0.14.1  | Apache-2.0 OR MIT |
| `zeroize`        | 1.9.1   | Apache-2.0 OR MIT |

## Security assumptions and limits

- `p256`, `ecdsa` and `elliptic-curve` declare `#![forbid(unsafe_code)]`; `sha2`,
  `zeroize`, `cpufeatures` and others contain `unsafe` blocks (SIMD, memory zeroing).
- Verification handles only public data, so constant-time behaviour is not a requirement for this
  component; it would be for any future signing or decapsulation component.
- No claim is made that these crates are independently audited, FIPS-validated or approved by any
  authority. Cryptographic library approval for operational use is an external (SAG) decision.
- Known vulnerabilities: checked with `cargo audit` against the RustSec advisory database in CI
  (`rust-native` job). Result for the committed lockfile is recorded in `docs/engineering/CURRENT_STATE.md`.

## Runtime and integration cost

0.5 MB statically linked release binary, no runtime, no network, no file writes. Build adds a Rust
toolchain to CI only; the Node runtime, container image and offline bundles are unchanged
(`native/` and `spec/` are excluded by `.dockerignore`).

## 2026-11-07 advisory remediation

CI on `76fb20e348b9f9b66ecad16e17729f2f8bd6691b` blocked
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387) in
`crypto-bigint` 0.5.5. The fixed requirement is >=0.7.6. `p256` 0.14.0 brings
`elliptic-curve` 0.14.3 and `crypto-bigint` 0.7.10; direct `sha2` is aligned with
its transitive 0.11.1 version to avoid duplicate digest stacks. The workspace minimum
Rust declaration is 1.87 to match dependency manifests; validation uses CI's 1.97.0.
The public-key parser follows the upstream API renames `Sec1Point` and
`from_sec1_point`; wire format, signature algorithm and rejection rules stay unchanged.
Sources inspected: downloaded crates.io manifests and p256/ecdsa source, 2026-11-07.
No advisory exemption is added. RustSec, unchanged conformance vectors, differential
checks and the full mission workflow must pass before this candidate is accepted.
