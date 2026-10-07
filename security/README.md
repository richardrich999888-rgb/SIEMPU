# Security validation entry points

| Check                     | Executable entry point                          | What it establishes                                                                                                        |
| ------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Local repository rules    | `make security`                                 | Narrow credential-pattern, runtime-material and dynamic-code checks                                                        |
| Security regressions      | `npm run test:security`                         | Authentication, authorization, policy races, cryptography, HTTP boundary, recovery, receipt replay and SARIF-gate behavior |
| Locked dependency audit   | `npm audit --audit-level=high`                  | Current registry advisories for locked development dependencies; requires registry access                                  |
| Secret scanning           | `.github/workflows/security.yml`, `secret-scan` | Gitleaks findings for the event's scanned Git history                                                                      |
| SAST                      | `.github/workflows/security.yml`, `codeql`      | Security-extended analysis with a fail-closed high/critical/error severity gate                                            |
| Container vulnerabilities | `.github/workflows/ci.yml`, `container`         | Trivy HIGH/CRITICAL gate for the actual built image                                                                        |

Local rules do not replace Gitleaks, dependency audit, CodeQL or image scanning. A passing
scan is scoped to a particular commit, scanner and advisory database; it is not a security
certification. Keep findings visible and fix the cause. Do not lower coverage or security
thresholds to make the badge green.

The sole `.gitleaksignore` entry is an exact historical fingerprint for ordinary prose in
`docs/threat-model/README.md`, verified against the originating commit. It does not exempt a
file, directory or rule. Any new exception requires equally narrow evidence and review.

Design and evidence: [threat model](../docs/threat-model/README.md),
[security baseline](../docs/security.md),
[regression log](../docs/security/SECURITY_REGRESSION_LOG.md), and
[supply-chain policy](../docs/SUPPLY_CHAIN_SECURITY.md).
