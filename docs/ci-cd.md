# CI evidence and delivery gates

`.github/workflows/quality.yml` runs for main and `codex/**` pushes, pull requests and manual dispatch. It never deploys an operational service or publishes an image.

| Job            | Actual operation                                                                                                                                                                                                       | Evidence / practical boundary                                                                                                                                                                                                                                                                                                               |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native         | Node 24.19.0, locked install, syntax/JSON checks, ESLint, Prettier, scoped strict TypeScript checkJs, narrow local security rules, npm audit, full Node test runner with coverage, allowlist package, application SBOM | Coverage output and package hashes. TypeScript checks the actual relay HMAC/client implementations identified in tsconfig.json; other application modules are linted and tested but not type checked. Blocking native coverage floors: 85% lines, 75% branches and 85% functions. Tests/helpers and uninstrumented browser UI are excluded. |
| Secret scan    | Pinned Gitleaks action against repository history                                                                                                                                                                      | Findings block that job. A personal account can use this action without an organization license; organization migration requires checking upstream license requirements.                                                                                                                                                                    |
| CodeQL         | Pinned CodeQL action, JavaScript/TypeScript extractor, security-extended queries                                                                                                                                       | SARIF gate blocks security severity >=7, any error-level result and ungraded security results. Missing/malformed outputs fail closed; suppressions do not waive this gate. Lower-severity findings remain review work.                                                                                                                      |
| Container      | Pinned base image build, Compose config validation, explicit synthetic bootstrap, three healthy services, public metadata request, nonroot UID assertion                                                               | Actual Docker runtime checks on hosted runner. No local Docker execution was available during initial development.                                                                                                                                                                                                                          |
| Container scan | Pinned Trivy action/tool, image vulnerability scan, HIGH/CRITICAL exit gate, image CycloneDX SBOM                                                                                                                      | This may block on inherited OS vulnerabilities. Do not suppress a finding to obtain a green badge; document disposition or update the base.                                                                                                                                                                                                 |

Only narrow artifacts are uploaded. `.data`, database/key files, profiles, passwords and TOTP seeds are never artifact paths. The disposable container deployment is removed with volumes in the final CI cleanup step.

The browser job installs pinned Playwright and Chromium on the hosted runner, provisions fresh synthetic users, launches the three actual processes and executes `apps/unit-client/browser-check.mjs`. Assertions cover browser MFA/device binding, encrypted exchange, policy change/reconnection, safe rendering, encrypted persistence and real offline app-shell reload. This job must run successfully before browser behavior is called measured. It publishes only selected synthetic screenshots and result text; no profile, credential file or browser storage directory is uploaded.

`quality.yml` runs the actual release packager after native validation, Gitleaks, the blocking CodeQL gate, container checks/scanning and browser acceptance all succeed. It verifies every generated SHA-256 checksum and uploads a commit-named candidate artifact. `release.yml` is additionally available for manual dispatch and reuses the full quality workflow. It produces a version-matched source archive (including deployment manifests, docs and tests), runtime archive, application/image SBOMs, selected test/browser evidence, a commit-bound release manifest and SHA-256 checksum list. It uploads workflow artifacts only. It does not create a GitHub Release, publish a container, modify a deployment environment, sign an artifact or claim operational approval. A clean committed tree and a genuine image SBOM from the quality run are required by the packaging script. The release depends on the blocking SARIF gate as well as the image/secret gates; lower-severity code-scanning alerts still need review.

The standalone demo and benchmark scripts and browser acceptance runner are repository-only tools; they are excluded from the runtime deployment bundle because they depend on test helpers or development tooling. The source release includes them. Hosted benchmark numbers are optional diagnostic data, not acceptance SLAs or field-performance claims.

## Local commands

```sh
npm run check
npm run lint
npm run format:check
npm run typecheck
npm test
npm run test:coverage
npm run security
npm audit --audit-level=high
npm run build
npm run sbom
```

`npm run verify` chains syntax, lint, format, scoped type checks, tests, local security rules, package and application inventory. It does not run CodeQL, Gitleaks or Trivy locally and does not prove CI success. The package is native JavaScript: `build` is an allowlisted deployment package with SHA-256 file inventory, not a transpiler.

Before merging: review actual run status, failing tests, scanner findings, broad release-gate coverage and the claims register. Branch protection and deployment approvals are repository administration choices; no settings were changed by this implementation. Production release signing, release attestations, isolated sovereign build runners and cryptographic provenance for the build are planned external controls.

All action refs were resolved to full release commit SHAs using their upstream Git repositories. Version comments aid review; the SHA is authoritative. Pinning an older reviewed tool is not a claim that it is the newest available tool.

The SARIF gate is an executable policy, with tests for high/critical findings, suppressions, malformed output, unresolved rules and empty output directories. Local tests validate this gate logic; only an observed hosted CodeQL run establishes scanner findings for a particular commit. A passing threshold does not mean the program is vulnerability free.

Coverage is scoped by the test command to authority, gateway, relay, crypto/protocol, detached verifier and the SARIF policy implementation. It excludes test modules/helpers and does not infer browser UI coverage from Node coverage. The configured aggregate floors passed locally at 93.44% lines, 82.46% branches and 94.94% functions across 57 tests on the measured implementation; coverage is rerun on each commit. Component-specific results, particularly HTTP branch coverage, still require review.

`npm run validate` is the native CI entry point. It executes the quality/test/demo stages once, records sanitized gate logs and `artifacts/validation/report.json`, and checks claims against fresh source-bound evidence. `npm run audit:claims` validates the manifest independently; `npm run hpsc` runs validation followed by the strict evidence audit. The register is JSON syntax within YAML 1.2, with an explicit Prettier parser override to preserve its dependency-free JSON parser contract.
