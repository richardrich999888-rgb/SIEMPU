---
name: siepmu-testing-and-assurance
description: How to locate and run SIEPMU native, acceptance, browser, network, security, cryptographic, integration and performance tests, how CI is structured, and how to record evidence with exact-source traceability. Use when running tests, diagnosing a failing gate, adding tests, or writing any statement about test results.
---

# SIEPMU testing and assurance

## Environment

Node **24.21.0** (CI and container); engines `>=24.19.0 <25`. Python 3 for research validation.
Chromium via Playwright for browser tests. `npm ci --ignore-scripts` first. Tests use
`node:test` with `--test-concurrency=1` (many tests start real processes and ports).

## Commands (all verified in package.json / Makefile)

| Purpose                                                                                               | Command                                                                                   |
| ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Full native gate (check, lint, typecheck, format, coverage tests, security, audit, build, sbom, demo) | `npm run validate` -> `artifacts/validation/report.json`                                  |
| All tests with coverage thresholds (lines 85, branches 75, functions 85)                              | `npm run test:coverage`                                                                   |
| Acceptance (vertical slice, authorized backlog, revocation)                                           | `npm run test:e2e`                                                                        |
| Security regression subset                                                                            | `npm run test:security`                                                                   |
| Engineering candidate (TLS, custody, FLASH, monitoring, offline release, providers)                   | `npm run test:engineering`                                                                |
| Browser, isolated deployment                                                                          | `npm run test:browser:isolated` (`make browser`)                                          |
| PQC lab (Noble X-Wing KATs, interop)                                                                  | `npm ci --prefix packages/pqc-lab --ignore-scripts && npm --prefix packages/pqc-lab test` |
| Demo and benchmark                                                                                    | `node scripts/demo.mjs`, `node scripts/benchmark.mjs`                                     |
| Claims audit                                                                                          | `npm run audit:claims`                                                                    |
| Research record consistency                                                                           | `python3 research/trl56/validate.py --self-test`                                          |
| Single file                                                                                           | `node --test --test-concurrency=1 tests/<file>.test.mjs`                                  |

Text corruption gate: `scripts/text-integrity.mjs` (in `npm run check`). Failed gates print a
bounded "failing tests" excerpt in the job log (`failureExcerpt` in `scripts/validate.mjs`).

## Test map

| Area                                 | Tests                                                                                                          |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Authority, races, crashes            | `tests/authority.test.mjs` (+ `helpers/crash-worker.mjs`, `policy-worker.mjs`)                                 |
| Persisted integrity, schema versions | `tests/admission-integrity.test.mjs`, `versioned-envelope.test.mjs`, `protocol-reconciliation.test.mjs`        |
| Duty roles, FLASH                    | `tests/filed-mission-*.test.mjs`, `flash-approval.test.mjs`                                                    |
| Crypto                               | `tests/crypto.test.mjs`, `crypto-provider.test.mjs`, `crypto-agility/`, `pqc/`                                 |
| Evidence, verifier                   | `tests/verifier-replay.test.mjs`, `checkpoint-custody.test.mjs`                                                |
| HTTP, routing, API contract          | `tests/http.test.mjs`, `routing-boundary.test.mjs`, `auth-routing.test.mjs`, `contracts/api-contract.test.mjs` |
| Transport, services                  | `tests/transport/`, `independent-services.test.mjs`, `monitoring.test.mjs`                                     |
| Network failure                      | `tests/network-failure/recovery.test.mjs`                                                                      |
| Recovery, backup, migrations         | `tests/recovery.test.mjs`, `offline-release.test.mjs`                                                          |
| Browser                              | `apps/unit-client/browser-check.mjs`, `tests/browser/shell-upgrade.mjs`                                        |

Helpers: `tests/helpers/fixture.mjs` (`provision`, `coreFixture`, `httpFixture`, `startStack`) and
`client.mjs` (`ApiClient`, `createObject`, `decryptObject`, transports).

## CI (`.github/workflows/`)

`ci.yml`: `native` (research validation, `npm run validate`, e2e, engineering evidence),
`pqc-lab`, `browser`, `container` (needs native), `testbed` (needs native; netem, 75 exchanges).
`security.yml`: dependency/regression, secret scan, CodeQL with `scripts/sarif-gate.mjs`
(blocks severity >= 7, error level, unrated security; no suppression).

## Evidence rules

Every reported result names: SHA, command, Node version, environment (local container vs hosted
runner), expected and actual outcome, artefact path or run URL, and limitations. Never copy an
older result into a new record. A local pass does not substitute for the hosted gate.
`scripts/record-engineering-evidence.mjs --verified` records CI evidence.

## Diagnosing failures

1. Get the hosted log for the exact run (GitHub MCP `get_job_logs`), not a re-run summary.
2. Reproduce locally with the same Node version and command.
3. If it passes locally, treat it as environment- or timing-dependent and find the cause. Never
   label it "flaky" without identifying the test. Never skip, disable or quarantine a test.
4. Fix the root cause; add a regression test.

## Definition of done

`npm run validate` PASS and `npm run test:e2e` PASS locally on the commit, hosted CI green on the
same SHA, and `docs/engineering/CURRENT_STATE.md` updated with the run URLs.
