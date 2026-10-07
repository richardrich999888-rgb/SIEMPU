# Supply-chain boundaries and inventory

The application has **zero npm runtime dependencies**. Native Node HTTP, crypto, WebCrypto and SQLite are the runtime facilities. This reduces npm package exposure; it does not eliminate Node, OpenSSL, SQLite, browser, operating-system, Docker, build-host or GitHub Actions supply-chain risk.

All application source is newly authored. No private portfolio repository source, uploaded proposal, secret or restricted external document belongs in this public repository. `third_party/migration-ledger.csv` records reuse decisions. Apache-2.0 is the repository license, not a permission to incorporate unrelated source without license review.

Controls implemented:

- `npm ci --ignore-scripts` against the committed lockfile; the runtime dependency graph must remain empty. ESLint, Prettier, TypeScript, Node typings, lint globals and Playwright are pinned development dependencies in the same lockfile.
- Explicit build allowlist. Provisioned identities, databases, secret files, `.env`, test output and uploaded files are excluded from the image context or runtime package.
- Docker official Node base pinned by immutable manifest digest. The digest was resolved through the Docker registry for `24.19.0-bookworm-slim`.
- GitHub Actions pinned by full commit SHA. Dependabot proposes changes; review remains necessary.
- Read-only repository permissions by default. CodeQL alone receives `security-events: write`; jobs do not request cloud deployment credentials.
- ESLint semantic rules, Prettier format checks, strict TypeScript checkJs on the relay authentication/client boundary, local narrow secret/dynamic-code checks, CI Gitleaks history scan, CodeQL security-extended analysis, npm audit and Trivy image vulnerability scan.
- Runtime application package hashes in `dist/manifest.json` and an application CycloneDX SBOM. The application SBOM includes all lockfile components (including development tools) and Node only; the CI image SBOM covers container components discovered by Trivy.

The build manifest is an unsigned local integrity inventory. The repository does not claim SLSA build provenance, reproducible byte-for-byte image builds, signed production images, a sovereign toolchain, an air-gapped dependency mirror, FIPS validation, SAG grading or a completed third-party security audit.

The hosted CI uses public GitHub, Docker registry and vulnerability databases. No operational data or locally provisioned files may be submitted as artifacts. Only scoped test coverage, synthetic browser screenshots/results, application inventory, packaging manifest and image SBOM are uploaded. The optional artifact-only release workflow bundles these with source/runtime archives and unsigned checksums. Synthetic CI provisioning is disposable and its output is suppressed, not uploaded.

## Updating dependencies and tools

For every base image/Node/action/scanner update: review upstream change and provenance, update immutable pins and documentation, run native checks/tests, build/start the image, inspect the image vulnerability findings, review SBOM differences, and retain the observed workflow run identifier. Do not label a pending CI configuration as a completed scan.

A zero dependency lockfile does not capture Node's bundled components. See the image SBOM, official Node release security notes and the exact runtime versions in measured test output. Vulnerability scanners can have false negatives, stale databases and incomplete reachability analysis.

Primary references: [Node 24 SQLite API](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html), [GitHub action pinning guidance](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions), [CodeQL workflow configuration](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning), [Trivy action](https://github.com/aquasecurity/trivy-action), [Gitleaks action](https://github.com/gitleaks/gitleaks-action).
