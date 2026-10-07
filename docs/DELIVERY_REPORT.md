# Engineering delivery record

This is a working **synthetic-data prototype**, with completed local engineering validation. It is not an operationally accredited defence system. [Both-brief execution checklist](EXECUTION_CHECKLIST.md) maps all 90 numbered sections to implementation, tests and remaining scope.

## Implemented and executed

- Native Node 24 backend, browser client and administrator console, three distinct services and two SQLite stores.
- Versioned migrations, password/TOTP identity, role/mission policies, approved device possession, body-bound enrollment/operation proofs and controlled offline identity recovery.
- Endpoint-encrypted text/file transfer, encrypted persistent local vault/outbox, bounded offline creation and reconnection admission.
- Atomic policy-epoch-bound recipient issuance with signed evidence, independent verifier, idempotent retries and encrypted backup/restore.
- Structured redacted logging, counters, alerts, health endpoints, operational console and a synthetic integration-schema adapter.
- Docker/Compose, security/quality CI, machine-readable claims, SBOM generation and artifact-only release packaging.

Source is organized under `apps/`, `services/`, `packages/`, `database/`, `scripts/`, `tests/` and `deployment/`. There are no npm runtime dependencies. Pinned npm development tools provide ESLint, Prettier, scoped TypeScript checking and Playwright.

## Actual validation record

The archived `2026-10-07T19:54:20.976Z` run of `npm run validate -- --benchmark` passed all eleven command gates: syntax, lint, typecheck, formatting, coverage tests, narrow local security rules, npm dependency audit, package build, SBOM, HTTP demonstration and benchmark.

- **72 tests passed; zero failures, cancellations or skips.** Includes independent native/WebCrypto interoperability, real HTTP services, negative authorization tests, two-process policy races, process exits around commit, 100 retries, schema upgrades and restored encrypted backups.
- **Nine HTTP demonstration stages passed.** Revoked-recipient backlog is held while eligible content is released.
- **14 claims passed the fresh execution-evidence gate.** Source digest checks reject stale results. Local records are not independent attestation.
- **Real Chromium browser record contains 15 passing checks**, covering MFA, fresh enrollment/approval, key/challenge substitution rejection, text and exact-byte file download, unsafe filename handling, cooperative two-tab locking, policy HOLD/release, real offline reload and reconnect authentication.
- **Benchmark: 9.86 objects/s**, 30 sequential synthetic 4 KiB objects on loopback. This is not a WAN, concurrency, capacity or field result. [Full measurements](performance.md).
- Local npm audit reported no known npm dependency vulnerabilities. This is not a statement about all runtime, OS or application vulnerabilities.

The [native record](testing/native-validation.json), [browser record](testing/browser-results.json) and [test snapshot](hpsc/node-test-snapshot.json) carry dates, scopes and limitations. Coverage gates measure an explicit set of authority/network/crypto/verifier modules; the typecheck currently covers relay authentication/client modules.

After adding SARIF compatibility regressions and the container acceptance runner, the archived `2026-10-07T20:20:42.347Z` [CI-fixes native validation](testing/native-ci-fixes-validation.json) passed all ten non-benchmark gates with **78 tests, zero failures/skips/cancellations**, nine HTTP demo stages and 14 evidence-backed claims. The recorded coverage gate passed. The earlier benchmark and browser records retain their original execution scope; later source changes require a new run and do not inherit these outcomes.

## Hosted and release evidence

Following the application scan review, [native scan-fix validation](testing/native-scan-fixes-validation.json) passed all ten non-benchmark gates with **87 tests, zero failures/skips/cancellations**, nine HTTP demo stages and 14 evidence-backed claims. Scoped coverage was 94.95% lines, 85.10% branches and 96.06% functions. This is the recorded local execution of the fixes; hosted container, browser and scanner results remain separate gates.

The first GitHub run built the container and brought all three services to healthy status, then exposed a host-network probe failure. It also found a browser label problem, formatting mismatch and one prose-only secret-scan false positive. Fixes and narrowly scoped regressions are committed in the subsequent change.

A subsequent run passed native validation, real-browser acceptance and Gitleaks. Its blocking image scan exposed inherited Debian and bundled npm vulnerabilities; the final runtime now uses a pinned official Alpine Node image with unused package managers removed. The SARIF gate also needed standards-based support for CodeQL query-pack rule references. Its severity threshold remains unchanged. CI now exercises encrypted file exchange, revocation and evidence verification against the actual built containers, and retains the full SARIF report for review. These corrections require the current hosted run to pass; a source change alone is not a clean scan result.

The [hosted scan review](security/HOSTED_SCAN_REVIEW.md) records observed findings and their dispositions; a finding disposition is not a passing rerun. The current hosted result is the authoritative status at [GitHub Actions](https://github.com/richardrich999888-rgb/SIEMPU/actions). Quality jobs execute native validation, actual browser tests, container build/start/probes, Gitleaks, blocking CodeQL SARIF evaluation and Trivy. Only after those jobs pass does the package-candidate job execute release packaging, verify checksums and upload the source/runtime archives, SBOMs and evidence. No production deployment or GitHub Release publication is automatic. Checksums are unsigned; they are not an attestation or certificate.

## Security boundary and remaining work

Release linearizes when issuance and evidence commit in one transaction. A later revocation cannot recall a released key or plaintext. The control authority can misrelease opaque wrapped keys if compromised, though it lacks recipient private keys. Endpoint compromise and malicious client distribution remain outside E2EE protection.

Remaining work includes SAG algorithm/assessment decisions, approved IAF integration, hardware-backed identity/key custody, TLS deployment with an approved ingress, external identity integration, independent assessment, high availability, fleet/WAN testing, operational retention/monitoring and independent checkpoint custody. No cross-domain guard, air-gap peer exchange, forward secrecy, post-quantum deployment, patent grant or production readiness is claimed. The public directory exposes active identity/device metadata to bound users; pilot metadata policy needs refinement.

## Reproduce

```sh
npm ci --ignore-scripts
npm run bootstrap
npm start
# Open http://127.0.0.1:8080; provisioned synthetic credentials remain in .data only.

npm run hpsc
npm run validate -- --benchmark
npx playwright install --with-deps chromium
npm run test:browser  # against a fresh running synthetic deployment

docker compose run --rm bootstrap
docker compose up -d --wait
```

Use a fresh synthetic data directory for each browser rehearsal; previously consumed TOTP codes and changed demo policy are deliberately not silently reset. [HPSC runbook](hpsc/demo-runbook.md) and [deployment](deployment.md) provide the precise operational sequence. Backup/restore and local maintenance commands are documented in [disaster recovery](disaster-recovery.md) and [identity](identity.md).
