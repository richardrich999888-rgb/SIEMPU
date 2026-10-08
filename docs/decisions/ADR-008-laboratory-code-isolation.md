# ADR-008: laboratory PQC code never enters a release artefact

Status: accepted, 2026-10-08. Commit `2fc827e`.

## Context

`packages/pqc-lab` contains endpoint private-key providers and depends on `@noble/post-quantum`
0.7.1, which upstream states is unaudited and not constant-time. `scripts/build.mjs` copied every
`packages/**` source file into `dist/` (the container image), and `packages/release/offline.mjs`
walked all of `packages/` into signed offline bundles. The authority registry imported lab code
for constants.

## Decision

- Services import suite identifiers, sizes and strict decoders from
  `packages/crypto-provider/pqc-identifiers.mjs` only.
- `scripts/build.mjs` skips `packages/pqc-lab` and any `node_modules`; `offline.mjs` excludes
  `RELEASE_EXCLUDED_PATHS` (`packages/pqc-lab`). `tests/offline-release.test.mjs` asserts it.
- Lab suites are additionally gated at runtime by `SIEPMU_ALLOW_PQC_LAB=1` and the crypto policy.

## Consequences

A laboratory endpoint is run from a source checkout, never from a release bundle. Promoting any
PQC provider to a release requires a new ADR, independent review and a provider that is not lab-scoped.
