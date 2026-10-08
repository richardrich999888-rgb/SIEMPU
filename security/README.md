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

## Container remediation evidence

The actual [container job 112987497404](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37678323924/job/112987497404)
built and started the old Debian image successfully, then Trivy blocked 60 OS findings
(56 HIGH, 4 CRITICAL) and 12 npm-package findings (11 HIGH, 1 CRITICAL). Several OS findings
were marked unfixed or deferred, so upgrading only the available Debian packages would not
clear the unchanged gate. No CVE exclusion or `ignore-unfixed` option was added.

The replacement candidate is `node:24.21.0-alpine3.24` with OCI index digest
`sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1`, verified against
[official immutable Docker image metadata](https://github.com/docker-library/repo-info/blob/bd079853ca1711683fe7fb1944a6071f4e5f89e8/repos/node/remote/24.21.0-alpine3.24.md).
It contains Alpine 3.24.2 and Node 24.21.0. The Dockerfile removes unused npm/Yarn from the
runtime stage, following the [official Node image guidance](https://github.com/nodejs/docker-node/blob/main/docs/BestPractices.md#smaller-images-without-npmyarn).
This removes installed components; it does not hide scanner results. Build tools remain
in the build stage and locked development dependencies remain subject to the dependency audit.

The Alpine libc change requires fresh image testing. An image-build smoke check exercises
`node:sqlite` and native crypto; hosted Compose tests then check bootstrap, service health,
HTTP behavior and nonroot execution. Trivy still blocks every reported HIGH/CRITICAL finding.
The replacement is **NOT YET VERIFIED** until those hosted steps succeed on the candidate.

The SARIF parser's component support follows the
[GitHub CodeQL SARIF documentation](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/sarif-output)
and [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.pdf).
Regression cases exercise extension severities, reference mismatches, malformed analysis and
accepted suppressions without weakening the blocking policy.
