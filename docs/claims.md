# Claims and evidence discipline

The [implementation status](IMPLEMENTATION_STATUS.md), [traceability matrix](TRACEABILITY_MATRIX.md), [execution checklist](EXECUTION_CHECKLIST.md) and generated validation records define the claim boundary. Design ADRs alone do not prove implementation.

| Permitted bounded statement                                      | Evidence                                                | Limitation                                                 |
| ---------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------- |
| Endpoint-encrypted synthetic text/file objects interoperate      | Crypto, HTTP and authority tests; browser text exchange | No compromised-endpoint or forward-secrecy claim           |
| Current-authority gate fences tested stale-release races         | Independent-process race/crash tests                    | Commit is capability issuance; no post-commit recall       |
| Mandatory MFA and current role/device/session checks exist       | Identity/negative API tests                             | Demo identity authority; no external PKI integration       |
| Detached receipts and anchored chains detect tested tamper       | Verifier and negative vectors                           | Trusted signer/checkpoint required; signature is not truth |
| Browser local vault/queue survives tested offline reload         | Recorded real Chromium run                              | One browser/environment; no hardware custody               |
| Encrypted restore and migration upgrade passed synthetic tests   | Recovery suite                                          | No automatic full-snapshot anti-rollback                   |
| Sequential 30 × 4 KiB loopback workload measured 12.21 objects/s | Benchmark JSON and [performance scope](performance.md)  | Not an IAF SLA or maximum capacity                         |

The machine-readable [CLAIMS_REGISTER.yaml](../CLAIMS_REGISTER.yaml) uses JSON syntax valid as YAML 1.2. It records claim ID/text/status, source, implementation, commit binding, tests, result, evidence, date and limitation. Accepted statuses include TESTED, MEASURED, IMPLEMENTED_UNVERIFIED, SIMULATED, PLANNED, EXTERNALLY_APPROVED and NOT_SUPPORTED.

[Claim audit](../scripts/audit-claims.mjs) checks required fields, referenced files, unsupported approval language and evidence when required. [Validation runner](../scripts/validate.mjs) executes mandatory native gates, captures redacted logs/test counts/demo stages, and binds the report to Git commit, dirty-tree state and source digest before/after. Evidence mode rejects missing/failed gates, source changes and unsupported measured claims. Run `npm run validate`, then `node scripts/audit-claims.mjs --require-evidence` before external use. Native evidence does not imply a browser, container or hosted scanner ran: those remain separate observations.

This automation is implemented; its final complete execution result must be read from `artifacts/validation/report.json` and the claim-audit output. A manifest field saying TESTED is conditional on valid fresh execution evidence, not itself proof of a pass.

Never claim IAF approved, SAG graded/certified, defence certified, zero vulnerabilities, unhackable, guaranteed delivery, instant revocation, patent granted/patentable or 100% Indian IP without evidence for the exact statement. No such external approval is established here.
