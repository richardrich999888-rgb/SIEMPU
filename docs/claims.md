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

Use statuses MEASURED, IMPLEMENTED_UNVERIFIED, SIMULATED, PLANNED, EXTERNALLY_APPROVED or NOT_SUPPORTED in machine-readable claim records. For each external claim retain implementation path, full commit/configuration, command, result, evidence and limitation. If a root `CLAIMS_REGISTER.yaml` is not yet present, the machine-readable claim automation is an explicit missing release gate rather than something this table supplies.

Never claim IAF approved, SAG graded/certified, defence certified, zero vulnerabilities, unhackable, guaranteed delivery, instant revocation, patent granted/patentable or 100% Indian IP without evidence for the exact statement. No such external approval is established here.
