# ADR-001: preserve the existing demonstrator technology stack

Status: accepted for the repository-foundation phase, 2026-10-08.

This task-requested filename coexists with the earlier `ADR-001-scope-and-authority.md`.
They address different decisions; links use full filenames to avoid identifier ambiguity.

## Context

The inspected working branch already contains an executable native JavaScript application,
three HTTP processes, browser clients, versioned SQLite migrations, tests, a lockfile, Docker
configuration and CI. Replacing it with a new framework would discard testable behavior and
increase the migration surface before the first vertical slice is verified.

The current decision boundary is a synthetic single-host demonstration of encrypted exchange
and policy-epoch-bound release. Distributed authority, operational identity integration,
approved cryptographic suites and deployment accreditation remain separate decisions.

## Decision

| Concern       | Selected implementation                                                    | Reason and practical limit                                                                     |
| ------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Runtime       | Node.js 24.21.0 CI/container; >=24.19.0 <25 engine; native ESM JavaScript  | Preserve existing code and pin the tested runtime; maintain its security updates               |
| HTTP services | Native `node:http`, gateway / control authority / ciphertext relay         | Small inspectable surface; application owns validation and HTTP hardening                      |
| Browser UI    | Existing HTML/CSS/JavaScript and service worker                            | Supports the required workflow without introducing framework migration                         |
| State         | Native `node:sqlite`, migrations, WAL, one authority writer                | Atomic policy/decision/evidence transactions; not a claim of horizontal HA                     |
| Cryptography  | Native Node crypto and browser WebCrypto behind existing modules           | Uses platform algorithms; no custom primitives; suite approval and key custody remain external |
| Tooling       | npm lockfile, ESLint, Prettier, TypeScript checkJs                         | Reproducible development tools; type checking is explicitly scoped by `tsconfig.json`          |
| Testing       | Node test runner, HTTP fixtures, Playwright Chromium                       | Unit/integration/acceptance tests plus actual browser execution                                |
| Packaging     | Source allowlist with file hashes, pinned multistage Docker image, Compose | Reproducible local packaging; hosted Docker build/start/scan must pass                         |
| CI            | GitHub Actions `ci.yml` and `security.yml` with SHA-pinned actions         | Enforce checks on working branches and pull requests; no CD yet                                |

There are no npm runtime dependencies. Node, OpenSSL, SQLite, the OS, browser and development
tools are still third-party dependencies requiring provenance and vulnerability review.

## Consequences

Keep identity/device/policy/admission/evidence modules within the same authority transaction
boundary. A documented module interface is preferable to separate deployable services where
the latter would invalidate the release consistency model. See
[runtime boundaries](ADR-004-runtime-and-services.md) and
[transactional release](ADR-003-transactional-release.md).

Expand strict type coverage incrementally without claiming unchecked code is type-safe.
Do not add runtime dependencies or change crypto providers without tests and review of the
new trust boundary. Designed for integration with service-mandated and approved cryptographic
suites. No SAG grading is asserted.

The branch may merge only after actual build, tests, lint, type checks, security gates and
Docker verification pass. Staging and release automation are deferred until those gates are
reliable; the old artifact recipe is retained outside active workflow discovery.

## Container security update

The inherited Debian 12 image failed the actual Trivy gate with 60 OS HIGH/CRITICAL
findings and 12 bundled npm dependency findings in run 37678323924. The candidate switches
both image stages to official Node 24.21.0 on Alpine 3.24, pinned by manifest digest, and
removes unused runtime npm/Yarn. The application has no runtime npm dependencies or native
addon artifacts to copy across libc boundaries. This changes the container libc to musl,
so an in-image SQLite/crypto smoke check plus hosted startup and scan remain required.
Local 24.19.0 test results establish compatibility only, not the updated image's success.
See [verified source and security gate](../../security/README.md#container-remediation-evidence).
