# Trust Before Release — demonstration procedure and evidence

Script: `scripts/trust-before-release.mjs` (`npm run demo:trust-before-release`).
Output: `artifacts/trust-before-release/report.json`, `report.md`, `evidence.json`, `receipt.json`,
`public-key.json`. CI runs it in the `native` job on every pushed SHA (10 timing iterations) and
uploads the report as part of `native-evidence`. All identities and content are synthetic.

## Run and reset

```sh
npm ci --ignore-scripts
npm run demo:trust-before-release                    # 20 timing iterations (default)
SIEPMU_TBR_ITERATIONS=5 npm run demo:trust-before-release   # bounded 5..200
rm -rf artifacts/trust-before-release                # reset
```

Each run provisions fresh identities, PKI and keys in a temporary directory, starts the five
service processes, and deletes the temporary directory on exit. `SIEPMU_ALLOW_PQC_LAB=1` is set
only for the child processes of the run and restored afterwards. Requires `openssl` on `PATH` for
the laboratory CA.

## What each step establishes

| #   | Step                          | Establishes                                                                                                                                                                      | Does not establish                                          |
| --- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| 1   | Five-process secure stack     | Gateway, authority, relay, custodian and collector run as separate processes with TLS 1.3 and mTLS identities                                                                    | Separate hosts or networks                                  |
| 2   | MFA and device binding        | Password + TOTP + signed device challenge for Units A, B, C and admin                                                                                                            | Hardware authenticators                                     |
| 3   | Enrol second Unit B user      | Admin enrolment and device approval path                                                                                                                                         | Real identity proofing                                      |
| 4   | PQC key registration          | Keys generated at endpoints; only public descriptors registered; admin activation                                                                                                | Hardware key custody                                        |
| 5   | Crypto policy                 | Laboratory suite admitted by an explicit, revisioned policy                                                                                                                      | Approved suite                                              |
| 6   | Baseline exchange             | End-to-end encryption, exact bytes, unrelated Unit C gets 404                                                                                                                    | —                                                           |
| 7   | Unit A disconnected           | Fault proxy drops Unit A's connections; objects are sealed locally with a cached creation grant; submission fails                                                                | Radio or WAN behaviour                                      |
| 8   | Revocation while disconnected | Recipient deactivation commits before Unit A reconnects                                                                                                                          | —                                                           |
| 9   | Reconnect                     | Queued objects submitted; current policy re-checked: revoked recipient's object HELD (`USER_REVOKED`) with a verified signed decision; revoked user refused before any key route | Recall of keys issued before revocation                     |
| 10  | Eligible recipient            | Second Unit B recipient receives the key and decrypts exact bytes                                                                                                                | —                                                           |
| 11  | Downgrade rejection           | Suite substitution rejected; classical object refused once policy removes classical from new-use suites                                                                          | Protection of data already captured under classical crypto  |
| 12  | Independent verification      | Strict receipt verification, replay rejection, full signed chain with checkpoint                                                                                                 | Independent custody on separate infrastructure              |
| 13  | Authority restart             | Decisions persist; retry returns the same issuance; exactly one `RELEASE_ISSUED`; revoked object stays HELD                                                                      | Crash during commit (covered by `tests/authority.test.mjs`) |
| 14  | Timings                       | Per-stage p50/p95/max on this host                                                                                                                                               | Capacity, WAN latency or acceptance thresholds              |

## Recorded local result

Commit `cfdaae1` plus the uncommitted demonstration script, Node 24.21.0, OpenSSL 3.5.8,
4-vCPU Linux container, 20 iterations, 16 KiB payload: 14/14 PASS. Per-object p50: grant 96 ms,
endpoint seal 12 ms, submit + prepare 230 ms, claim 159 ms, endpoint open 12 ms, total 507 ms.
Each HTTP request opens a new TLS 1.3 connection (bounded client without keep-alive), so the
round-trip stages are dominated by handshakes and operation-proof challenges. Hosted results for
pushed SHAs are in the CI `native-evidence` artefact and `docs/engineering/CURRENT_STATE.md`.

## Interpretation limits

This is reproducible laboratory evidence on one host. It is not a relevant-environment trial,
representative demonstration, independent assessment, sponsor acceptance, SAG grading or TRL
decision. The PQC suite is a laboratory composition awaiting independent review.
