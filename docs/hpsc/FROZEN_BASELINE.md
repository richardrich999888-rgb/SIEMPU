# Frozen demonstration baseline for the 13 October 2026 HPSC

## Frozen code revision

`0e8d1b9e50594fc87e07856a99673473c6b5445f`, branch `claude/siepmu-engineering-recovery-3nwgc8`
(PR #17, draft; not merged).

Commits after this revision change documentation and the claims register only. Verify that with:

```sh
git diff --stat 0e8d1b9 HEAD -- apps services packages scripts tests database deployment native .github
# expected output after the freeze: changes limited to the HPSC/TRL guard tests and budget model
```

## Hosted evidence on the frozen revision (all PASS, 8 October 2026)

| Workflow | Event        | Run         | Jobs                                                                                                            |
| -------- | ------------ | ----------- | --------------------------------------------------------------------------------------------------------------- |
| CI       | push         | 37761613000 | native (validate, e2e, Trust Before Release, Demo 3, Demo 4), rust-native, pqc-lab, browser, container, testbed |
| CI       | pull_request | 37761620422 | same                                                                                                            |
| Security | push         | 37761613051 | codeql gate, secret-scan, dependency-and-regression                                                             |
| Security | pull_request | 37761620429 | same                                                                                                            |

Links: `https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/<run>`.

## Local evidence on the frozen revision (Node 24.21.0, Linux)

| Check                                         | Result                                                      |
| --------------------------------------------- | ----------------------------------------------------------- |
| `npm run validate`                            | PASS, 249/249 tests, 97.5 % lines                           |
| `npm run test:e2e`                            | 3/3                                                         |
| `npm run demo`                                | 9/9 steps                                                   |
| `npm run demo:trust-before-release`           | 14/14 steps                                                 |
| `npm run demo:documents`                      | 10/10 steps; Rust verifier ACCEPT genuine / REJECT tampered |
| `npm run demo:monitoring`                     | 11/11 steps; Rust verifier ACCEPT genuine / REJECT tampered |
| Rust: fmt, clippy -D warnings, tests, vectors | PASS (merge `ecc5b51`, unchanged in `0e8d1b9`)              |

## Signed offline release (integrity-verifiable package)

Built from a clean worktree at the frozen revision with a **throwaway laboratory signing key** held
outside the repository:

```text
status SIGNED_LAB_BUNDLE, revision 0e8d1b9e…, version 1, 116 files
manifest SHA-256 5fd7b76ded9349de879c1936335052db7ab0e8800c2d3cf59b552f1a178883f0
```

- Install with the independently held public key: `INSTALLED`.
- Same bundle with one file altered: refused (`PACKAGE_SIZE_LIMIT`).
- `packages/pqc-lab` is absent from the bundle (ADR-008).

**Before 13 October, the founder must rebuild with their own release key.** The throwaway key is
not retained, so this exact bundle cannot be re-signed. Keep the public key and ledger on separate
media.

```sh
git checkout 0e8d1b9e50594fc87e07856a99673473c6b5445f
SIEPMU_RELEASE_KEY=<protected private JWK, mode 0600> node scripts/offline-release.mjs build <bundle-dir> 1
SIEPMU_RELEASE_TRUST=<public JWK> SIEPMU_RELEASE_LEDGER=<ledger path> \
  node scripts/offline-release.mjs install <bundle-dir> <empty-dir> --initialize
```

## Fallbacks

1. **Primary:** the frozen revision above.
2. **Last known passing build before the HPSC additions:** `b758230`. That is PR #17 before the
   Rust merge, all green (CI 37756775965 / 37756781079). It lacks Demos 3 and 4 and the telemetry
   fix.
3. **If no laptop demo is possible:** the hosted `native-evidence` and `rust-native-evidence`
   artefacts for the frozen runs, labelled **recorded**.
