# 02 — Sovereign technology ownership matrix

Machine-readable source: [`sovereignty-matrix.csv`](sovereignty-matrix.csv) (74 rows). It is checked by
`tests/sovereignty-matrix.test.mjs` against `package-lock.json`, `packages/pqc-lab/package-lock.json` and
`native/Cargo.lock`. A new dependency without a row, a wrong version, a missing evidence file, or a
third-party row marked as SYNTRIASS source fails the build.

## Categories kept separate

| Category                   | Meaning in this matrix                                                          |
| -------------------------- | ------------------------------------------------------------------------------- |
| SYNTRIASS source           | Source written for this project, in this repository, under Apache-2.0           |
| Foreign-origin open source | Third-party code (runtime, libraries, tools), whoever operates it               |
| Foreign standard           | Public algorithm or protocol specification (NIST, IETF)                         |
| Foreign service            | Third-party-operated service (GitHub hosting, Actions runners, CodeQL)          |
| Imported hardware          | Every CPU, NIC and storage device used so far                                   |
| Operated by operator       | Can run on infrastructure the operator controls, without a vendor control plane |
| Project-tested             | Covered by this repository's tests; **not** independent qualification           |
| Independently qualified    | Requires a report under `docs/assurance/qualification/`. **None exists.**       |

## Summary (at this branch)

| Layer                      | SYNTRIASS source           | Foreign-origin                              | Indigenous implementation | Operator-run without vendor | Qualified |
| -------------------------- | -------------------------- | ------------------------------------------- | ------------------------- | --------------------------- | --------- |
| Application services       | 6                          | runtime only                                | Source: yes               | Yes                         | No        |
| Protocol, evidence formats | 3 specs + code             | —                                           | Source: yes               | Yes                         | No        |
| Crypto composition         | 3 (incl. lab)              | —                                           | Composition only          | Yes                         | No        |
| Crypto algorithms          | 0                          | 11 standards                                | **No**                    | n/a                         | No        |
| Crypto implementations     | 0                          | OpenSSL, WebCrypto, RustCrypto, Noble (lab) | **No**                    | Yes                         | No        |
| Runtime and storage        | 0                          | Node.js, V8, SQLite, Alpine                 | **No**                    | Yes                         | No        |
| Verification tooling       | 3 (Node, Rust, TLA+ model) | Rust crates, TLC                            | Source: yes               | Yes                         | No        |
| Build and CI               | scripts                    | GitHub, CodeQL, gitleaks, Trivy             | No                        | **No** (hosted)             | No        |
| Hardware                   | 0                          | all                                         | **No**                    | n/a                         | No        |

## What the matrix supports saying

- "Application, protocol, custody and verification **source code** is SYNTRIASS-developed and runs on
  operator-controlled infrastructure with **zero runtime npm dependencies** and no mandatory foreign control
  plane."
- "Operator-held keys and self-hosted storage" — true in the code (software keys, local SQLite); no
  hardware key custody exists.

## What it does not support (do not claim)

- "Indigenous cryptography" — every algorithm and every implementation in use is foreign-origin.
- "Fully indigenous" or "sovereign stack" — runtime, OS, crypto libraries and all hardware are foreign-origin.
- "Qualified", "certified", "SAG-graded" — no independent qualification of any row.
- Self-hosting is operational control, not technological sovereignty.

## Highest-leverage gaps to change the picture

1. **Graded Indian crypto provider** behind the existing provider seam (plan: `08-INDIAN_CRYPTO_PROVIDER_PLAN.md`).
   This is the only route to "indigenous cryptographic implementation"; it is external (SAG/C-DAC/vendor),
   not something this repository can create by writing code.
2. **Self-hosted CI** (Gitea/Forgejo + self-hosted runners + offline CodeQL alternative) to remove foreign
   services from the build path; reproducible-build evidence to make the build verifiable by a third party.
3. **Secure BOSS Linux profile** for the OS row (`07-AIR_GAP_ARCHITECTURE.md` §6).
4. **Independent qualification** (STQC/CERT-In-empanelled lab) of the SYNTRIASS rows.
