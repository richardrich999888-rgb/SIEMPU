# ADR-012: Rust adoption through specified, differentially tested reference components

Status: accepted for the evidence verifier, 2026-10-08. Further components require their own evidence.

Renumbered from ADR-011 on merge into the integration branch (source `4af847b`, branch
`claude/siepmu-trl56-recovery-9o6qet`); ADR-011 on this branch is the HPKE-PQ deferral.

## Context

The platform is Node.js with zero runtime npm dependencies. The continuation directive asks for a
measured Rust programme for memory-, concurrency- and hardware-sensitive components, explicitly not a
rewrite. Moving code to another language without a frozen contract risks silent semantic drift in exactly
the places that carry the security argument (canonical encoding, signature checks, release decisions).

## Decision

1. **Process per component:** freeze the Node behaviour as a language-neutral specification in `spec/`;
   generate vectors **by executing the Node reference** (`scripts/evidence-vectors.mjs`); implement in
   `native/<component>`; accept only when (a) the Rust implementation passes every vector, (b) a
   differential check against the Node CLI passes on real authority output and a seeded mutation
   campaign, and (c) performance, memory and dependency costs are measured and recorded.
2. **First component: independent evidence verifier, general mode** (`native/evidence-verify`,
   `spec/SIEPMU-EVIDENCE-v1.md`). Chosen because it is pure, holds no private keys, has one well-defined
   reference, and a second independent implementation directly strengthens the "independently verify
   the evidence" requirement. Strict release mode (durable SQLite replay store) stays in Node: it would
   add a SQLite dependency and its atomicity argument is already tested there.
3. **Crypto backend:** RustCrypto `p256 =0.13.2` (ECDSA verify) and `sha2 =0.10.8`, exact pins, no
   default features. Pure Rust, no C build, `forbid(unsafe_code)` in `p256`/`ecdsa`/`elliptic-curve`.
   Rationale and limits: `native/DEPENDENCIES.md`.
4. **Own JSON parser** (no `serde_json`): the contract needs exact control over number conversion,
   duplicate members (rejected) and lone surrogates (rejected); see spec §8 divergences D1–D3.
5. **No private keys and no central-service role** for any Rust component without a separate ADR.
   The TypeScript/browser boundary is unchanged: browsers keep WebCrypto; a native boundary (Tauri or
   a local helper) is only considered for endpoint key custody with hardware, under its own ADR.

## Evidence (this host: 4 vCPU Intel Xeon 2.10 GHz, Node 24.21.0, rustc 1.97.0)

- `cargo test`: 26 unit tests + 2 vector-conformance tests (63 evidence and 16 canonical vectors),
  byte-identical success output. A corrupted expected message and a corrupted expected stdout were
  each detected (mutation check of the conformance test itself).
- `npm run test:native`: real demo evidence (chain, saved checkpoint, receipt with bindings) gives
  byte-identical results; 400 seeded mutations (seed 0x51e9) give identical status, stdout and stderr.
- `cargo clippy --all-targets -- -D warnings` with `clippy::all` denied and `clippy::pedantic` warned.
- Benchmark (`scripts/native-benchmark.mjs`, median of 5 fresh processes):

  | Records |   Input | Node wall / peak RSS | Rust wall / peak RSS | Rust speed vs Node |
  | ------: | ------: | -------------------: | -------------------: | -----------------: |
  |   1 000 | 0.5 MiB |      284 ms / 63 MiB |      318 ms / 11 MiB |              0.89× |
  |  10 000 | 5.0 MiB |    1 919 ms / 95 MiB |    3 053 ms / 25 MiB |              0.63× |
  |  50 000 |  25 MiB |   8 621 ms / 190 MiB |  15 958 ms / 117 MiB |              0.54× |

- Profiling (`cargo run --release --example profile`): ECDSA verification is ~98 % of Rust run time
  (315 µs per verify versus 149 µs in Node/OpenSSL); parsing plus canonical hashing of 5 000 records
  takes ~18 ms.

## Consequences

- Rust is justified for this component by **implementation diversity and memory** (1.6–5.7× lower
  peak RSS, 0.5 MB static binary, no runtime), **not speed**. The pure-Rust P-256 backend is ~2× slower
  than OpenSSL. If verification throughput matters, evaluate `aws-lc-rs` (AWS-LC, assembly; AWS-LC offers a FIPS-mode build whose
  CMVP certificate and operational environment must be confirmed before relying on it) behind the same `TrustedKey` interface; that adds a C/CMake build and must be measured.
- Porting found one latent reference defect: the member-set check compared `sort().join('|')`, so one
  member named `keyId|payload` satisfied two expected names. Every path still rejected later, so no
  forgery was possible; fixed with a regression test (`tests/crypto.test.mjs`).
- Three accept/reject divergences are specified and tested (D1–D3). The Node reference still accepts
  them; changing that is a separate, deliberate contract change.
- Next candidates, in order: authorization/release state-machine model checking (formal model, not a
  port), then a native endpoint key-custody helper only when a TPM/PKCS#11 target is available.
  Ciphertext relay and protocol parsing in Rust remain unjustified until a measured bottleneck exists.
