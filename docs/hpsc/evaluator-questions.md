# Evaluator answers tied to this build

| Question                                 | Accurate answer / where to inspect                                                                                                                                                      |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Is this just a design?                   | No: browser clients, three services, SQLite migrations, crypto, verifier and executable tests are in source. See README and evidence index.                                             |
| What is standard engineering?            | MFA, encryption, RBAC, queues, signed logs and transactional outbox patterns. We claim no novelty in their names.                                                                       |
| What exactly is differentiated?          | A tested current-authority issuance transaction binds object/destination/epoch/evidence; broader product and patent advantage remain to validate.                                       |
| Can a revoked device drain an old queue? | Current approved device/user/role/mission checks gate release; old creation grants are insufficient. Already-issued keys cannot be recalled.                                            |
| What happens in the race?                | Both policy update and issuance serialize under the authority database write transaction. Commit ordering defines the result.                                                           |
| Can the administrator decrypt?           | Admin API role does not bypass recipient checks; control has opaque wrapped keys, not recipient private keys. Host/client/authority compromise is a different trusted-boundary failure. |
| Is the device hardware-trusted?          | No. This build proves software-key possession, not TPM integrity or malware absence.                                                                                                    |
| Can evidence be rewritten?               | Tamper is detectable under an independently trusted key and saved checkpoint. A malicious signer can sign false assertions; unanchored tail removal is not detectable.                  |
| Does this integrate with IAF?            | The adapter validates an authenticated synthetic schema. A live approved interface is not available.                                                                                    |
| SAG status?                              | No grading/approval evidence. Approved suite and assurance integration remain sponsor gates.                                                                                            |
| Is it production-ready?                  | No: measured prototype, with explicit identity, hosting, key custody, scale and independent-assurance work.                                                                             |
| Budget/timeline?                         | Require founder-approved programme figures and sponsor dependencies; the software does not establish funding commitments.                                                               |

Use [evaluation rubric](evaluation.md) for a recorded hostile review. Do not manufacture an independent score. The ten principal rejection risks and responses are listed there; source fixes and tested regressions belong in [security log](../security/SECURITY_REGRESSION_LOG.md).
