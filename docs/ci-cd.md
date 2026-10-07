# CI evidence and merge gates

`.github/workflows/ci.yml` and `.github/workflows/security.yml` run on pushes to `main`,
`feature/**`, `security/**`, `release/**`, `hotfix/**` and the inherited `codex/**` branches.
Both also support pull requests, manual dispatch and reusable calls. No active workflow
deploys an operational service, publishes an image or creates a release.

| Workflow / check context               | Actual operation                                                                                                                                                                                                           | Evidence and practical boundary                                                                                                                          |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CI / `native`                          | Locked install, syntax/JSON, Prettier, ESLint, strict scoped checkJs, full Node suite with coverage, named HTTP acceptance, synthetic demo, build, application SBOM                                                        | Test output, runtime manifest and SBOM. Floors remain 85% lines, 75% branches, 85% functions; scope is in `package.json`.                                |
| CI / `container`                       | After native passes: Compose validation, digest-pinned Docker build, explicit bootstrap, three healthy containers, public metadata, denied login, UID and commit identity assertions, Trivy HIGH/CRITICAL gate, image SBOM | Actual Docker execution and scan on the hosted runner; local manifests alone do not prove this.                                                          |
| CI / `browser`                         | Pinned Playwright/Chromium, isolated fresh stack, actual browser acceptance, cleanup                                                                                                                                       | Selected synthetic screenshots and result text; no user profiles, credential files or browser storage directories.                                       |
| Security / `dependency-and-regression` | Locked dependency audit, local security rules and security regression tests                                                                                                                                                | Registry advisories and regression behavior; HIGH/CRITICAL dependency findings block.                                                                    |
| Security / `secret-scan`               | Pinned Gitleaks action/tool with full checkout history available                                                                                                                                                           | Findings block; exact event scan range is reported by Gitleaks. No broad rule/path exemptions.                                                           |
| Security / `codeql`                    | JavaScript/TypeScript security-extended analysis and executable SARIF gate                                                                                                                                                 | Gate blocks severity >=7, error-level findings and ungraded security results; missing/malformed output fails closed. Lower severities still need review. |

Actions are pinned to full reviewed commit SHAs. The application runtime is pinned to Node
24.19.0; Docker also pins the base manifest digest. Pins provide reproducibility, not an
absence of vulnerabilities. Do not waive scanner findings or weaken tests to obtain green CI.

Native artifacts are required after successful checks. If an earlier check fails, the final
upload may publish partial evidence without adding a misleading missing-file failure; the
original failing step still fails the job. Disposable container volumes are removed in the
final cleanup step. The isolated browser runner owns its temporary processes and data cleanup.

## Local equivalent

`make ci` / `npm run ci` runs syntax, formatting, lint, scoped type checking, coverage, named
HTTP acceptance, local security rules, build and application SBOM. `make browser` runs the
separate isolated Chromium flow after installing its browser. `npm run test:security` runs
the security-focused regression suite. `make help` and
[local development](deployment/local-development.md) enumerate the command interface.

Local CI excludes registry advisory lookup, Gitleaks, CodeQL and Trivy. Those are hosted
security gates. It also excludes Docker when the host lacks Docker. A local pass must never
be reported as a hosted pass. `build` creates an allowlisted native JavaScript package and
SHA-256 file inventory, not transpiled code. The TypeScript checker covers only the modules
listed in `tsconfig.json`; other modules are linted and tested, not implicitly type checked.

## Investigated inherited failures

The actual logs for [run 37675166393](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37675166393)
were inspected during this phase:

| Check       | Observed failure                                                                                                | Current response                                                                                                                                                       |
| ----------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native      | Prettier reported `tests/crypto.test.mjs`; the always-upload step then also failed because no artifacts existed | Keep formatting blocking; format source and retain the primary failure in logs. Require evidence explicitly on the success path.                                       |
| Secret scan | One `generic-api-key` finding in ordinary threat-model prose at a historical commit                             | Preserve the already-reviewed exact `.gitleaksignore` fingerprint; do not exclude the document or rule.                                                                |
| Container   | Image built and three services were healthy; host `curl` then exited 7                                          | Preserve the existing gateway edge network fix and use explicit IPv4 host transport while retaining the configured Host/Origin checks. Actual rerun remains necessary. |
| Browser     | `getByLabel('From unit')` timed out                                                                             | Preserve the existing corrected admin label and run the workflow against an isolated, disposable stack. Actual rerun remains necessary.                                |

This historical diagnosis is not a claim that the new workflows have passed. Use the
candidate commit's actual run conclusions and retained artifacts for that claim.

## Protected merge and deferred delivery

Work goes through `feature/*`, `security/*`, `release/*` or `hotfix/*`; do not create permanent
branches without a purpose. The foundation work stays on `feature/repository-foundation`.
Merge requires successful build, tests, lint, type checks, security checks, browser flow and
Docker verification, plus review of the exact candidate commit.

The reviewable [.github/rulesets/main.json](../.github/rulesets/main.json) requires those
checks and a PR, prevents force pushes/deletion and has no bypass actors. It is
**NOT APPLIED**: the connected integration lacks administration access. A checked-in ruleset
does not make `main` protected. Confirm actual enforcement before merge.

The old dispatch-only artifact packaging recipe is retained at
[`deploy/disabled-workflows/release.yml`](../deploy/disabled-workflows/release.yml), outside
GitHub's active workflow directory. There is no CD workflow. Staging deployment is deferred
until CI is reliable and its target environment is agreed. Release automation follows that
work; neither is invented in this phase. The inactive recipe is reference material requiring
review before reactivation, including all artifact paths and security dependencies.
