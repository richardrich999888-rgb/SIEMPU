# TRL 5 advancement performance report

Run `1348b86` (clean). Source data: `docs/trl5/evidence/1348b86/metrics.json`.

All three hosts share 4 vCPU (Xeon @ 2.10 GHz) and 16 GiB. CPU contention between hosts is
therefore real and inflates latency. These are **laboratory measurements, not capacity figures**.
Samples are small (n = 3 or 5 per impairment profile), so percentiles above p50 are indicative only.
p99 is reported only where n ≥ 100.

## Exchange latency under impairment (A→C, 64 KiB, end to end)

An exchange is one agent process on Host A sealing and submitting, then one agent process on Host
C logging in from its saved session, claiming, decrypting and acknowledging. The figures include
two Node process start-ups and every TLS handshake.

| Profile | Condition              | Mechanism (local)     | Control request p50 | Exchange p50 | Exchange max | Intact |
| ------- | ---------------------- | --------------------- | ------------------- | ------------ | ------------ | ------ |
| P0      | baseline               | none                  | 213 ms              | 1,303 ms     | 1,341 ms     | 5/5    |
| P1      | 100 ± 20 ms one-way    | userspace relay       | 592 ms              | 3,004 ms     | 3,092 ms     | 5/5    |
| P2      | 300 ± 100 ms one-way   | userspace relay       | 1,405 ms            | 6,502 ms     | 6,793 ms     | 5/5    |
| P3      | 1 Mbit/s               | kernel TBF            | 223 ms              | 2,548 ms     | 2,681 ms     | 5/5    |
| P4      | 200 ± 50 ms + 2 Mbit/s | userspace relay + TBF | 1,009 ms            | 5,266 ms     | 5,336 ms     | 5/5    |

- **Delay amplification.** Every client request opens a new TLS connection and pays several round
  trips: TCP, TLS 1.3 and HTTP. This roughly quadruples the one-way delay per request. Connection
  reuse would cut it, but it is not implemented.
- **Outage (T3.6).** The link was down for 20.0 s. The first successful request came 269 ms after
  restore, and the queued object was delivered intact.

## Sustained load (T8.1)

Configuration: 4 senders on Host A, each with 2 concurrent workers, 4 KiB payloads, a 30-second
send window, and then all recipients claim on Host C.

| Measure                                | Value                         |
| -------------------------------------- | ----------------------------- |
| Sent / delivered / mismatched / failed | 54 / 54 / 0 / 0               |
| Send throughput                        | **1.56 exchanges/s**          |
| Send latency p50 / p95 / max           | 5,047 / 5,172 / 5,251 ms      |
| Claim throughput                       | 1.01 claims/s                 |
| Claim latency p50 / p95 / max          | 3,760 / 4,143 / 4,168 ms      |
| Host B: custodian CPU (avg) / peak RSS | **72.3 %** / 236 MiB          |
| Host B: control CPU / RSS              | 32.4 % / 261 MiB              |
| Host B: gateway, relay, collector CPU  | 3.5 %, 0.6 %, 8.5 %           |
| A↔B link bytes (rx / tx at Host B)    | 1.05 MB / 0.97 MB             |
| Authority database growth              | 8.1 MB, ≈ 150 KB per exchange |

The bottleneck is the **independent checkpoint custodian**, not cryptography, the network or the
relay.

## Defect D-T5-01: custody cost grows with the evidence chain

**Mechanism** (`services/control/core.mjs dispatch`, `services/evidence/custody.mjs`):

1. Every request except health checks is serialised behind one dispatch queue.
2. Each request calls `recoveryGuard.authorize()` twice, once before routing and once after.
3. Each authorisation sends the **entire** evidence chain to the custodian. The custodian
   re-verifies every record signature from genesis with `verifyEvidence`, then anchors the head.

The cost per request is therefore 2 × (fixed + k·n) for chain length n, with no concurrency.
Total work for N requests grows as O(N²).

**Measured, in-process** (`scripts/custody-scaling.mjs`; no TLS, so a lower bound):

| Evidence records | One authorisation (median of 5) |
| ---------------- | ------------------------------- |
| 250              | 43 ms                           |
| 500              | 88 ms                           |
| 1,000            | 178 ms                          |
| 2,000            | 316 ms                          |
| 4,000            | 588 ms                          |

A least-squares fit gives **0.144 ms per record + 20 ms**.

**Measured, deployed path:** control-request latency per 200-request segment over the run, from
the content-free control log.

| Requests  | p50      | p95      |
| --------- | -------- | -------- |
| 0–199     | 61 ms    | 107 ms   |
| 200–399   | 98 ms    | 188 ms   |
| 400–599   | 125 ms   | 160 ms   |
| 600–799   | 165 ms   | 1,286 ms |
| 800–999   | 1,243 ms | 1,445 ms |
| 1000–1199 | 796 ms   | 890 ms   |

- **Before load.** Latency rises steadily with chain length; the segments up to request 600
  precede the load test.
- **Under load.** The 800–1199 segments are dominated by queueing behind the serialised custody
  exchange.

**Projection, an extrapolation and not a measurement:** at 10,000 records, one authorisation is
about 1.5 s in-process. That makes each request ≥ 3 s of serialised custody work, which fails any
interactive use within days of operation.

**Proposed fix (gate G2), not implemented in this sprint:**

- **Incremental checkpoints.** The authority sends only the records after the custodian's anchored
  sequence. The custodian verifies that they chain from its saved head hash and that their
  signatures are valid, then advances the anchor.
- **Unchanged guarantees.** Rollback detection (`saved.sequence > head.sequence`) and fork
  detection (a different hash at the anchored sequence) are kept.
- **Full verification remains:** at bootstrap, on custodian restart, and on demand.
- **Requirements before any merge:** an ADR, and negative tests for rollback, fork, a gap,
  reordering and a stale anchor.
- **Not a mitigation:** batching or caching on the authority side without the protocol change. It
  would weaken the per-request custody guarantee and is rejected.

## Not measured

- Multi-machine latency.
- Packet loss (hosted CI only).
- Payloads above 512 KiB.
- Sessions longer than about 6 minutes.
- Memory growth over hours.
- Browser endpoint performance.

## Addendum 2026-10-10: D-T5-01 fix

Incremental custody (ADR-014) removes the chain-length term: per-authorisation cost is 3.4–4.1 ms flat from
1,000 to 250,000 records in-process (`docs/assurance/d-t5-01-incremental.md`, measured on `d879b4a`). The
relevant-environment re-run at `1a0218d` measured 5.93 exchanges/s (send p50 1,312 ms) with the custodian at
17.1 % CPU; the control authority (85.3 % CPU) is now the bottleneck. Frozen evidence:
`docs/trl5/evidence/1a0218d/`.
