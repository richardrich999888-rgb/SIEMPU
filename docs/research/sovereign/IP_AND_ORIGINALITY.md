# Intellectual property, provenance and originality register

**This repository is public.** Anything committed here is a public disclosure. Candidate patent claims, claim
language and novelty arguments are therefore **not** kept in this repository. They are held privately by the
founder pending professional IP review. Do not add them here without the founder's written authorisation.

## 1. Provenance rules applied on this branch

- Every line of new code on `claude/siepmu-sovereign-research-w886dv` was written for this project in this
  session; no third-party source was copied. Commits carry the session and co-author trailers.
- Designs consulted are public: RFC 6962/9162 (Certificate Transparency), RFC 9180 (HPKE), RFC 9420 (MLS),
  RFC 5869, RFC 7914, RFC 8446, NIST FIPS 180-4/186-5/197/203/204, Schneier–Kelsey (1999),
  Crosby–Wallach (USENIX Security 2009), public SQLite/PostgreSQL documentation. No proprietary code or
  access-controlled material was used.
- No new third-party dependency was added. The Rust range verifier uses only the crates already pinned for
  ADR-012 (`p256 =0.13.2`, `sha2 =0.10.8`).

## 2. Licence review of everything the build uses

Machine-checked in [`sovereignty-matrix.csv`](sovereignty-matrix.csv) (`tests/sovereignty-matrix.test.mjs`).

| Licence                    | Components                                                              | Compatibility with Apache-2.0 distribution                            |
| -------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Apache-2.0 / MIT dual      | RustCrypto crates, libc, cfg-if, typenum, zeroize, rand_core, …         | Compatible (keep notices)                                             |
| MIT                        | Node.js, @noble/\* (lab only), eslint, prettier, globals, generic-array | Compatible (keep notices)                                             |
| BSD-3-Clause               | `subtle`                                                                | Compatible (keep notice)                                              |
| Apache-2.0                 | OpenSSL 3.x, TypeScript, Playwright                                     | Compatible                                                            |
| Public domain              | SQLite                                                                  | Compatible                                                            |
| Mixed (incl. GPL userland) | Alpine base image                                                       | Container distribution needs the image's source-offer obligations met |

Notices: `packages/pqc-lab/THIRD-PARTY-NOTICES.txt` exists for the lab package; a consolidated notice file for
the Rust binary and the container image is **not** yet produced (gap).

## 3. Per-invention record (public-safe fields only)

| Item                                                      | Technical problem                                           | Public prior art (non-exhaustive)                     | Original design decisions recorded in | Status                                                                     |
| --------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------- | -------------------------------------------------------------------------- |
| Policy-epoch-bound release (Trust Before Release)         | Release key only under current policy, provably             | Envelope encryption, key escrow with policy, ABE      | ADR-001, ADR-003, `formal/`           | Disclosed publicly since `main`                                            |
| Custody lease binding evidence head + authorization state | Detect rollback/fork and silent state change before release | Transparency logs, signed tree heads, WAL checkpoints | ADR-014 (this branch)                 | Disclosed publicly; ADR-014 claims no novelty for incremental verification |
| Duty-role concealment after commit                        | Hide existence without losing signed decision               | Access-control concealment patterns                   | ADR-009                               | Disclosed publicly                                                         |

## 4. Required before any claim of novelty or exclusivity

1. Professional patent search and opinion (Indian Patent Office practice and any foreign filing strategy).
2. Counsel's view on the effect of the public disclosures above (dates are in the Git history).
3. Founder decision on what may be published further.

Until then the project describes these as "engineering design decisions", never as inventions, patents or
patent-pending.
