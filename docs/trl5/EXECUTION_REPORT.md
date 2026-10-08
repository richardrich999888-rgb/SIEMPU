# TRL 5 advancement execution report

## Run

| Field         | Value                                                                                                             |
| ------------- | ----------------------------------------------------------------------------------------------------------------- |
| Revision      | `1348b868df832b46820796af7733ecfe3540f3ac`, clean working tree (`dirty: false`)                                   |
| Source digest | `aa30fa71a4302e137ba579af3fcb27665249235bdc3ec4920b53f1b55a1540f3` (`scripts/audit-claims.mjs sourceDigest`)      |
| Command       | `npm run trl5:validate` (root; namespaces and qdiscs need CAP_NET_ADMIN)                                          |
| Window        | 2026-10-08 15:31:47Z – 15:37:20Z                                                                                  |
| Environment   | `ENVIRONMENT.md`: three namespaces on one kernel, no netem                                                        |
| Criteria      | `ACCEPTANCE_MATRIX.md`, committed in `8dda0a1` before any execution and unchanged since                           |
| Result        | **PASS, 33/33**                                                                                                   |
| Evidence      | `docs/trl5/evidence/1348b86/` (copy of `artifacts/trl5/`). `evidence-manifest.json` holds a SHA-256 for each file |

To re-verify the frozen copy:
`cd docs/trl5/evidence/1348b86 && sha256sum` each file, and compare with `evidence-manifest.json`.
To reproduce: check out `1348b86`, run `npm ci --ignore-scripts && npm run build:native`, then
`sudo npm run trl5:validate`.

## Results

| ID   | Result | Observed (from `test-results.json`)                                                                                                  |
| ---- | ------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| T1.1 | PASS   | MFA login: alice (A), admin (B), bob, bravo, eve (C); 159–201 ms each                                                                |
| T1.2 | PASS   | Wrong TOTP: 401                                                                                                                      |
| T1.3 | PASS   | Client trusting a different CA: `SELF_SIGNED_CERT_IN_CHAIN`, no connection                                                           |
| T1.4 | PASS   | 64 KiB and 512 KiB A→C: SHA-256 equal; release and DELIVERY_ACK event IDs returned                                                   |
| T1.5 | PASS   | eve on C: 404 `OBJECT_NOT_FOUND` (concealment)                                                                                       |
| T1.6 | PASS   | 101 files and 7.4 MB under Host B scanned for every 64-byte window of both plaintexts (raw, hex, base64): 0 hits                     |
| T2.1 | PASS   | 409 `POLICY_DENIED`; evidence `SUBMITTED/PENDING` → `RELEASE_DENIED/HELD`                                                            |
| T2.2 | PASS   | Send during A↔B outage fails (`ECONNRESET`). Revoked rcp2: 401 `USER_REVOKED`, 0 `RELEASE_ISSUED`. rcp3 delivered intact            |
| T2.3 | PASS   | 20 trials, both commit orders (11 released, 9 refused), 40 policy changes, **0** issuances at a withdrawn epoch                      |
| T2.4 | PASS   | Claim at stale epoch 67: 409 `EPOCH_MISMATCH`; fresh claim succeeds                                                                  |
| T2.5 | PASS   | Same object ID twice; exactly one `SUBMITTED` record                                                                                 |
| T3.1 | PASS   | P0 baseline: 5/5 intact                                                                                                              |
| T3.2 | PASS   | P1 100 ± 20 ms: 5/5 intact                                                                                                           |
| T3.3 | PASS   | P2 300 ± 100 ms: 5/5 intact                                                                                                          |
| T3.4 | PASS   | P3 1 Mbit/s (TBF): 5/5 intact                                                                                                        |
| T3.5 | PASS   | P4 200 ± 50 ms + 2 Mbit/s: 5/5 intact                                                                                                |
| T3.6 | PASS   | 20.0 s link down: request fails (`ECONNRESET`); first success 269 ms after restore (limit 10 s); queued 64 KiB object intact         |
| T4.1 | PASS   | Document from Host C system to Host A unit: `DELIVERED`, signed ack; source status `DELIVERED`                                       |
| T4.2 | PASS   | Duplicate: same document, object and request ID; one `SUBMITTED`                                                                     |
| T4.3 | PASS   | Altered replay under same request ID: 409                                                                                            |
| T4.4 | PASS   | Unauthorised destination: `ADAPTER_REJECTED`                                                                                         |
| T4.5 | PASS   | Unpinned source certificate: `SOURCE_NOT_AUTHENTICATED`                                                                              |
| T4.6 | PASS   | Adapter down: `ECONNREFUSED`. After restart, delivered once, one `SUBMITTED`                                                         |
| T5.1 | PASS   | Collector received AUTH_FAILURE, ACCESS_DENIED, RELEASE_DENIED, AUTHORITY_CHANGED in 377 ms; content-free                            |
| T5.2 | PASS   | Operator acknowledge 200; non-operator identity 403                                                                                  |
| T5.3 | PASS   | Relay down: 503 `RELAY_UNAVAILABLE`, object count unchanged (56 → 56); accepted after restart                                        |
| T5.4 | PASS   | 270-record chain verified on Host C: Node ACCEPT, Rust ACCEPT; tampered copy REJECT by both                                          |
| T6.1 | PASS   | Older control DB restored: 503 `RECOVERY_QUARANTINED` for every protected request                                                    |
| T6.2 | PASS   | Consistent DB restored: send succeeds; user revoked after the old backup still refused 401 `USER_REVOKED`                            |
| T7.1 | PASS   | Each host: two public addresses → `ENETUNREACH`; all other tests ran without external services                                       |
| T7.2 | PASS   | Signed bundle (131 files) installs. Appended tamper refused (`PACKAGE_SIZE_LIMIT`); same-length byte flip refused (`RELEASE_DIGEST`) |
| T7.3 | PASS   | Authority, custody, collector and PKI keys are local files on Host B; T5.4 verification ran offline on Host C                        |
| T8.1 | PASS   | 54 sent, 54 delivered, 0 mismatches, 0 failures (performance: `PERFORMANCE_REPORT.md`)                                               |

## Defects found during execution

The criteria were never changed. Each fix was made before the evidentiary run, and the fix commits
are in the branch history.

| ID      | Kind    | Found by         | Defect                                                                                                       | Resolution                                                                                                       |
| ------- | ------- | ---------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| H-1     | Harness | First run        | Synthetic usernames below the authority's 3-character minimum                                                | Renamed (1bdd79e)                                                                                                |
| H-2     | Harness | T2.3             | Looked for `AUTHORITY_CHANGED`; policy changes are recorded as `POLICY_CHANGED`                              | Fixed (1bdd79e); the race now provably exercises both commit orders                                              |
| H-3     | Harness | T7.2             | Tampered a path outside the bundle layout                                                                    | Fixed (1bdd79e)                                                                                                  |
| H-4     | Harness | T3.2, T3.3, T3.5 | WAN emulator reordered chunks (one timer per chunk is not order-preserving in Node), giving `BAD_RECORD_MAC` | Single FIFO delay queue; regression test (1bdd79e)                                                               |
| H-5     | Harness | Audit of 33/33   | T6.2 accepted an agent crash as "revoked user refused"; T1.6 scanned one window, not all                     | Exact 401 `USER_REVOKED` required; full-window raw/hex/base64 scan with positive and negative controls (e05e1c8) |
| P-1     | Product | T5.3             | Relay unreachable gave HTTP 500 `INTERNAL_ERROR`                                                             | 503 `RELAY_UNAVAILABLE`; integrity faults deliberately not mapped; regression test fails on old code (e05e1c8)   |
| D-T5-01 | Product | T8.1             | Custody authorisation cost is linear in chain length, twice per request, serialised                          | **Open.** See `PERFORMANCE_REPORT.md` and gate G2                                                                |

## Hosted CI (independent re-execution of the same revision)

| Field    | Value                                                                                                                                                                           |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Run      | CI run 37800666173, job `relevant-env` 113391683858 (GitHub-hosted `ubuntu-24.04`, kernel netem loaded)                                                                         |
| Revision | `1348b86`, the same revision as the local run; the job gate requires `source.commit == GITHUB_SHA` and `dirty == false`                                                         |
| Result   | **PASS, 35/35**: the 33 local tests, with P1–P4 on kernel netem instead of the userspace relay, plus T3.L1 (50 ms, 1 % loss) and T3.L2 (100 ± 20 ms, 3 % loss), 5/5 intact each |
| Evidence | Workflow artifact `trl5-relevant-env-evidence` (ID 11561171403, zip SHA-256 `25199bd7…12f5`), retained 30 days                                                                  |

The other seven CI jobs on the same run were also green: native, rust-native, formal (TLA+),
pqc-lab, browser, container and the 10-zone testbed. The hosted run is also three namespaces on one
kernel, so it adds packet loss and a second machine type. It does **not** add host separation.

## Not executed

- Separate machines or VMs (not available; `ENVIRONMENT.md`).
- Packet loss on the local kernel. It was exercised only in the hosted run above.
- Load above about 1.6 exchanges per second. The custody defect bounds throughput, so higher
  offered load would only lengthen the queue.
- Independent witness.
