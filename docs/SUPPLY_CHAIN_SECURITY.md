# Supply-chain boundaries and inventory

The application has **zero npm runtime dependencies**. Native Node HTTP, crypto, WebCrypto and SQLite are the runtime facilities. This reduces npm package exposure; it does not eliminate Node, OpenSSL, SQLite, browser, operating-system, Docker, build-host or GitHub Actions supply-chain risk.

All application source is newly authored. No private portfolio repository source, uploaded proposal, secret or restricted external document belongs in this public repository. `third_party/migration-ledger.csv` records reuse decisions. Apache-2.0 is the repository license, not a permission to incorporate unrelated source without license review.

Controls implemented:

- `npm ci --ignore-scripts` against the committed lockfile; the runtime dependency graph must remain empty. ESLint, Prettier, TypeScript, Node typings, lint globals and Playwright are pinned development dependencies in the same lockfile.
- Explicit build allowlist. Provisioned identities, databases, secret files, `.env`, test output and uploaded files are excluded from the image context or runtime package.
- Docker official Node base pinned by immutable manifest digest. The `24.21.0-alpine3.24` manifest digest was verified against immutable official Docker image metadata; [source and rationale](../security/README.md#container-remediation-evidence).
- GitHub Actions pinned by full commit SHA. Dependabot proposes changes; review remains necessary.
- Read-only repository permissions by default. CodeQL alone receives `security-events: write`; jobs do not request cloud deployment credentials.
- ESLint semantic rules, Prettier format checks, strict TypeScript checkJs on the relay authentication/client boundary, local narrow secret/dynamic-code checks, CI Gitleaks history scan, CodeQL security-extended analysis with a local SARIF severity gate, npm audit and Trivy image vulnerability scan.
- Runtime application package hashes in `dist/manifest.json` and an application CycloneDX SBOM. The application SBOM includes all direct/transitive lockfile components (including development tools), Node, and component versions exposed by `process.versions`, including OpenSSL and SQLite; the CI image SBOM covers container components discovered by Trivy.

The build manifest is an unsigned local integrity inventory. The repository does not claim SLSA build provenance, reproducible byte-for-byte image builds, signed production images, a sovereign toolchain, an air-gapped dependency mirror, FIPS validation, SAG grading or a completed third-party security audit.

The hosted CI uses public GitHub, Docker registry and vulnerability databases. No operational data or locally provisioned files may be submitted as artifacts. Only scoped test coverage, synthetic browser screenshots/results, application inventory, packaging manifest and image SBOM are uploaded. The optional artifact-only release workflow bundles these with source/runtime archives and unsigned checksums. Synthetic CI provisioning is disposable and its output is suppressed, not uploaded.

## Updating dependencies and tools

For every base image/Node/action/scanner update: review upstream change and provenance, update immutable pins and documentation, run native checks/tests, build/start the image, inspect the image vulnerability findings, review SBOM differences, and retain the observed workflow run identifier. Do not label a pending CI configuration as a completed scan.

Zero npm runtime dependencies do not mean zero bundled libraries. The application inventory explicitly names nonempty runtime-reported components, records ABI/Unicode/time-zone versions separately as metadata, and marks their licenses as unreviewed instead of assuming the Node license applies to all components. Upstream lockfile license declarations are preserved for npm packages; they are not an independent legal review. Runtime-reported component versions do not establish packaging provenance, all vendor patches or complete transitive closure. Compare the image inventory, exact Node distribution license notices and official release security notes before a deployment approval. Vulnerability scanners can have false negatives, stale databases and incomplete reachability analysis.

Primary references: [Node 24 SQLite API](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html), [GitHub action pinning guidance](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions), [CodeQL workflow configuration](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning), [Trivy action](https://github.com/aquasecurity/trivy-action), [Gitleaks action](https://github.com/gitleaks/gitleaks-action).

`.gitleaksignore` contains one exact historical fingerprint for ordinary endpoint-assets prose detected as a generic API key in the first implementation commit. The source text was inspected and is not a credential. The exception is tied to that commit, file, line and scanner rule; it does not disable scanning for a file, directory or credential class. A second exact fingerprint (commit `aa1ab91`, `tests/crypto-agility/wrap-derivation.test.mjs` line 40) covers a pinned known-answer HKDF output computed from public sequential test inputs; it is a regression vector, not a key that protects anything.
