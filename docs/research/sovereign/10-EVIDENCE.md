# 10 — Source-linked engineering evidence

Host for every local run: 4 vCPU Intel Xeon @ 2.10 GHz, 16 GiB, Linux 6.18 container, Node 24.21.0
(official tarball, SHA-256 verified), OpenSSL 3.5.8, rustc 1.97.0, TLA+ tools 1.8.0 (pinned SHA-256 from
`ci.yml`). Hosted CI on this branch: **not yet run** at the time of writing; it is triggered by the pull request.

## Commits on this branch (base `86744a8`)

| SHA       | Content                                                                              |
| --------- | ------------------------------------------------------------------------------------ |
| `50303b5` | CodeQL `js/file-system-race` fix in the KAT vector reader + regression tests         |
| `d879b4a` | D-T5-01 fix: incremental custody protocol v2 (ADR-014), 22 negative/functional tests |
| `1a0218d` | Rust range verifier, SIEPMU-EVIDENCE-RANGE-v1 + 25 vectors, measurements             |
| `ae9b904` | Research record, sovereignty matrix + guard test, frozen TRL 5 re-run                |
| `4975a61` | Claim-gate wording fix (validate on `ae9b904` failed check-claims; see below)        |

## Full gate run on `4975a61` (clean tree)

| Command                                                       | Result                                                    |
| ------------------------------------------------------------- | --------------------------------------------------------- |
| `npm run validate`                                            | **PASS** (353/353 tests; 97.68 % lines, 89.88 % branches) |
| `npm run test:security`                                       | 140/140                                                   |
| `npm run test:engineering`                                    | 39/39                                                     |
| `npm run test:e2e`                                            | 3/3                                                       |
| `npm run build:native && npm run test:native`                 | 3/3 (Rust vs Node differential, incl. mutation campaign)  |
| `cargo fmt --check && cargo clippy -D warnings && cargo test` | 26 unit + 3 conformance suites (CJSON, EVIDENCE, RANGE)   |
| `npm --prefix packages/pqc-lab test`                          | 7/7                                                       |
| `npm run test:mission`                                        | PASS, classical and lab-PQC profiles (18 steps each)      |
| `npm run demo:hpsc`                                           | PASS (Demos 1–4)                                          |
| `python3 research/trl56/validate.py --self-test`              | PASS                                                      |

## Other runs (exact revision stated)

| Run                                       | Revision                           | Result                                                                                              |
| ----------------------------------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| Baseline `npm test`                       | `86744a8`                          | 315/315 (before any change)                                                                         |
| Full vs incremental custody benchmark     | `d879b4a` (clean)                  | `docs/assurance/d-t5-01-incremental.md`; raw JSON in `docs/assurance/evidence/`                     |
| `npm run formal:check`                    | `formal/` unchanged from `86744a8` | Faithful 3,837,180 states, no error; `nonatomic`, `unguarded` violate as designed                   |
| TLC reachability probe for `AnchorPrefix` | throwaway copy, not committed      | Unreachable under the model's abstraction (ADR-014)                                                 |
| Three-namespace TRL 5 matrix              | `1a0218d` (untracked docs only)    | 33/33; frozen `docs/trl5/evidence/1a0218d/`                                                         |
| `npm run validate`                        | `ae9b904`                          | **FAIL**: check-claims and claims-audit flagged 9 wrapped negations in new docs; fixed in `4975a61` |
| Hosted Security workflow                  | `86744a8` (base)                   | FAIL: CodeQL `js/file-system-race`; fixed in `50303b5`, hosted re-run pending                       |

## Mutation checks of the new tests (each must fail when its subject is broken)

| Test                                                       | Mutation                                                          | Observed                      |
| ---------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------- |
| `sovereignty-matrix.test.mjs`                              | delete `rust-crate:subtle` row; mark OpenSSL as SYNTRIASS source  | 2 failures                    |
| Rust `evidence_range_vectors_conform`                      | change an expected error message; change an expected `toSequence` | fails on both                 |
| `evidence-vectors.mjs --check` after the verifier refactor | (positive control)                                                | all 63 frozen cases unchanged |

## Not run

Browser acceptance (`test:browser:isolated`), container build and Trivy (no Docker daemon), hosted CodeQL on
the new code, kernel netem loss profiles (no `sch_netem`), Secure BOSS Linux.
