# 04 — D-T5-01: root cause, redesign and evidence

Decision record: [ADR-014](../../decisions/ADR-014-incremental-checkpoint-custody.md). This page is the
evidence summary.

## Root cause

`Authority.dispatch` serialises every protected request and calls `recoveryGuard.authorize()` before and after
routing. Each call shipped the **whole** evidence chain and the custodian re-verified every signature from
genesis, although it already retained a verified anchor. Cost per request: 2 × (fixed + k·n), with no
concurrency. A second consequence was not stated in the original report: above 100,000 records (verifier cap)
or about 39,800 minimal records (16 MiB custodian body limit), every authorisation fails, so the authority
fails closed permanently.

## Redesign (implemented, `d879b4a`)

Custody protocol v2: ship only records after the custodian's anchor (at most 512 per request), verify them as a
contiguous, signed, hash-linked extension of the anchor (`verifyEvidenceRange`, shared record rules with the
full-chain verifier), and move the anchor in one transaction under the same rollback, fork and
state-without-evidence rules. Signed, read-only anchor query for restarts. v1 kept for bootstrap and audit.

## Evidence (all on stated SHAs, this host: 4 vCPU Xeon 2.10 GHz, Node 24.21.0, OpenSSL 3.5.8)

| Check                                                                                                                                                                | Revision                        | Result                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| In-process authorisation cost                                                                                                                                        | `d879b4a`                       | Full chain 165.9 / 1,631.8 / 18,245.2 ms at 1k / 10k / 100k; incremental 3.4–4.1 ms flat to 250k ([report](../../assurance/d-t5-01-incremental.md)) |
| Records verified per authorisation                                                                                                                                   | `d879b4a`                       | Full chain = chain length; incremental = 4 (the records a request appended)                                                                         |
| Negative tests (rollback, fork, gap, reorder, tamper, replay, stale base, silent state change, storage hole, crash between batches, restarts, forged anchor answers) | `1a0218d`                       | 22 new tests pass (`tests/incremental-custody*.test.mjs`)                                                                                           |
| Existing custody, recovery, secure-stack tests                                                                                                                       | `1a0218d`                       | Pass (`test:engineering` 39/39, `test:security` 140/140)                                                                                            |
| TLA+ model                                                                                                                                                           | `1a0218d` tree                  | Faithful 3,837,180 states, no error; both mutants violate (coverage limit in ADR-014)                                                               |
| Mission workflow, HPSC rehearsal                                                                                                                                     | `1a0218d` tree                  | 18/18 classical and lab PQC; HPSC rehearsal PASS                                                                                                    |
| Three-namespace TRL 5 matrix                                                                                                                                         | `1a0218d` (untracked docs only) | **33/33 PASS**; frozen in `docs/trl5/evidence/1a0218d/`                                                                                             |

### Sustained load T8.1 on the relevant environment (same declared workload)

| Measure                | Before `1348b86` | After `1a0218d`  |
| ---------------------- | ---------------- | ---------------- |
| Send throughput        | 1.56 exchanges/s | 5.93 exchanges/s |
| Send latency p50 / p95 | 5,047 / 5,172 ms | 1,312 / 1,527 ms |
| Claim throughput       | 1.01 claims/s    | 3.76 claims/s    |
| Custodian average CPU  | 72.3 %           | 17.1 %           |
| Control average CPU    | 32.4 %           | 85.3 %           |

Kernel netem was not available in this container (TBF and a userspace delay relay were used, loss not emulated),
the same limitation as the earlier local run. Hosts are namespaces on one kernel.

## What is now the bottleneck

The control authority (85 % CPU): serialised dispatch, two custodian round trips per request, and the
authorization-state digest that reads all identities on every authorisation. Next work, in order of expected
gain: (1) incremental authorization-state digest; (2) one authorisation per request when the pre-route head is
already leased (needs a TLA+ change first); (3) TLS connection reuse between control and custodian.
