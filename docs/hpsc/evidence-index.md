# Evidence index

| Evidence                  | Reproduction / source                                                                                                                           | Scope                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Node tests and coverage   | `npm run test:coverage`; generated `artifacts/test-coverage.txt`; [captured summary](node-test-snapshot.json)                                   | 57 passed, zero failed at snapshot; rerun after code changes            |
| Real Chromium run         | [browser JSON](../testing/browser-results.json), [validation narrative](../testing/browser-validation.md), `apps/unit-client/browser-check.mjs` | Local actual browser/stack; hosted job separately verified              |
| Scripted HPSC acceptance  | `node scripts/demo.mjs`; `artifacts/demo/results.json`                                                                                          | Real HTTP plus logical sender disconnection                             |
| Detached signatures/chain | `apps/verifier/verify.mjs`; `tests/crypto.test.mjs`                                                                                             | External roots/expected bindings/checkpoint are caller inputs           |
| Policy race / crash       | `tests/authority.test.mjs`, independent helper processes                                                                                        | Tested commit orders/fault windows, not every possible schedule         |
| Restore/migration         | `tests/recovery.test.mjs`                                                                                                                       | Synthetic encrypted recovery and v1/v2 upgrade                          |
| Performance               | [captured JSON](performance-results.json), [scope](../performance.md), `scripts/benchmark.mjs`                                                  | Sequential local 30 × 4 KiB profile                                     |
| Supply chain / release    | `.github/workflows/quality.yml`, `.github/workflows/release.yml`, `scripts/sbom.mjs`                                                            | Configuration is not hosted execution proof; inspect exact-head Actions |
| Claims/remaining work     | [claims](../claims.md), [implementation status](../IMPLEMENTATION_STATUS.md), [complete brief checklist](../EXECUTION_CHECKLIST.md)             | No external approval implied                                            |

Generated artifacts are ignored by Git unless copied intentionally as non-sensitive evidence. Keep runtime keys, passwords, MFA seeds and database files out of commits and release packages. Captured results are historical records; none prove a later amended commit automatically passes.

## Final native release gate

`npm run validate` produces `artifacts/validation/report.json` plus per-gate logs. [Claim audit](../../scripts/audit-claims.mjs) requires the report to match the current source digest, mandatory passing gates, test counts and completed demo stages. Use this fresh report for final counts rather than the historical 57-test snapshot. The report deliberately does not assert external browser/container/hosted SAST execution.
