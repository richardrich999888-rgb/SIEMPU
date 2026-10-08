# TRL 5 advancement test matrix (declared before execution)

**Declared:** 8 October 2026, before any run of `scripts/trl5-validation.mjs`. The git history
of this file shows the thresholds were not changed after the results were seen.

**Thresholds** are **provisional and applicant-defined**:

- The IAF has not defined a relevant environment or acceptance criteria (open question Q14).
- No threshold below is an IAF requirement.
- A run passes only if every criterion is met.
- A deviation is recorded as a failure, never re-scoped after the fact.

**Environment:** `docs/trl5/ENVIRONMENT.md`. Three hosts (A sender unit, B platform, C recipient
unit) in separate network namespaces on one kernel. They are linked by veth, and Host B's internal
services are unreachable from A and C.

**Requirement IDs** refer to `docs/requirements/README.md` (R1–R12).

| ID        | Test                                                 | Requirement            | Criterion (all must hold)                                                                                                                                                      |
| --------- | ---------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| T1.1      | MFA login per host                                   | R5                     | Units on A and C and the administrator on B authenticate with password + TOTP + device proof                                                                                   |
| T1.2      | Wrong one-time password                              | R5                     | HTTP 401                                                                                                                                                                       |
| T1.3      | Untrusted gateway certificate                        | R6                     | A client trusting a different CA cannot connect (TLS failure)                                                                                                                  |
| T1.4      | Exchange A→C, 64 KiB and 512 KiB                     | R1, R2, R5             | Recipient on C decrypts; SHA-256 of plaintext equals sender's; signed release and DELIVERY_ACK receipts                                                                        |
| T1.5      | Unauthorised party on C                              | R7                     | Claim refused (403/404/409); no key material returned                                                                                                                          |
| T1.6      | Plaintext absent at Host B                           | R5, R10                | No 64-byte window of either plaintext appears in any file under Host B's state directory                                                                                       |
| T2.1      | Policy withdrawn before issuance                     | R7                     | Claim refused with a signed HELD decision                                                                                                                                      |
| T2.2      | Revocation during disconnection                      | R7, R2                 | With A's link down, two objects are queued offline and recipient R2 is deactivated. After the link is restored, R2's object is never released; R3's object is delivered intact |
| T2.3      | Concurrent release and revocation (20 trials)        | R7                     | No `RELEASE_ISSUED` record carries an epoch during which the policy was withdrawn                                                                                              |
| T2.4      | Stale epoch                                          | R7                     | Claim with an earlier epoch is refused                                                                                                                                         |
| T2.5      | Duplicate submission                                 | R2                     | Re-submitting the same sealed object returns the same object; exactly one `SUBMITTED` record                                                                                   |
| T3.1–T3.5 | Impairment profiles P0–P4 (5 exchanges each, 64 KiB) | R2, R3                 | 100 % delivery with matching digests under every profile; measured latency recorded                                                                                            |
| T3.6      | Link outage 20 s                                     | R2                     | Requests during the outage fail; first success ≤ 10 s after restore; the queued object is delivered intact                                                                     |
| T4.1      | Document via adapter on C to unit on A               | R8                     | Delivered; destination validates; signed DELIVERY_ACK; source sees DELIVERED                                                                                                   |
| T4.2      | Duplicate document                                   | R8, R2                 | Same object returned; one `SUBMITTED` record                                                                                                                                   |
| T4.3      | Altered replay under same request ID                 | R8                     | Refused (409)                                                                                                                                                                  |
| T4.4      | Unauthorised destination                             | R8, R7                 | Refused                                                                                                                                                                        |
| T4.5      | Unpinned source certificate                          | R8, R6                 | Refused (403)                                                                                                                                                                  |
| T4.6      | Adapter interruption                                 | R8, R2                 | Submission fails while down; after restart, the resubmitted document is delivered exactly once                                                                                 |
| T5.1      | Security events at the independent collector         | R6                     | AUTH_FAILURE, ACCESS_DENIED, RELEASE_DENIED and AUTHORITY_CHANGED received within 10 s, with no plaintext                                                                      |
| T5.2      | Operator acknowledgement and access control          | R6                     | Operator acknowledge returns 200; a non-operator identity is refused (403)                                                                                                     |
| T5.3      | Ciphertext relay failure and recovery                | R2, R6                 | Submission refused while the relay is down, with no partial object; accepted after restart                                                                                     |
| T5.4      | Evidence integrity on Host C                         | R2                     | Node and Rust verifiers ACCEPT the exported chain and REJECT a tampered copy                                                                                                   |
| T6.1      | Database rollback                                    | R2, R10                | After an older authority database is restored, protected requests are refused (`RECOVERY_QUARANTINED`)                                                                         |
| T6.2      | Reauthorisation after recovery                       | R2                     | After the consistent database is restored, service resumes; earlier revocations still hold                                                                                     |
| T7.1      | No mandatory external service                        | R4 (sovereign profile) | No host has a route out of the enclave (connections to two public addresses fail), yet the full workflow works                                                                 |
| T7.2      | Signed offline installation                          | R12                    | Signed bundle installs; a tampered bundle is refused                                                                                                                           |
| T7.3      | Local keys and audit                                 | R10                    | Authority, custody and collector keys and evidence are local files on Host B; evidence verified offline on Host C                                                              |
| T8.1      | Sustained load, 30 s                                 | R11                    | Zero digest mismatches and zero unexplained failures. Report throughput, p50/p95/p99 latency, CPU, RSS, link bytes and database growth                                         |

Packet loss is **not** emulated on the local kernel (no `sch_netem`). Loss profiles run only in
the hosted CI job, where kernel netem is available, and are reported separately from the local
results.
