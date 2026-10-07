# Measured performance

Latest source: [machine-readable result](hpsc/performance-results.json), recorded at `2026-10-07T19:54:20.774Z` during the final native validation. Node v24.19.0, Linux x64, Intel Xeon Platinum 8573C; 9 logical CPUs visible. Workload: **30 sequential 4 KiB synthetic objects**, one sender, two sessions, loopback HTTP and three server processes.

| Operation | Samples | p50 ms | p95 ms |
| --------- | ------: | -----: | -----: |
| Encrypt   |      30 |   1.22 |   5.71 |
| Submit    |      30 |  31.69 | 128.00 |
| Prepare   |      30 |  17.11 |  50.60 |
| Claim     |      30 |  22.03 |  31.72 |
| Decrypt   |      30 |   1.10 |   4.29 |

Total workload elapsed 3041.86 ms; achieved **9.86 objects/s**. Nearest-rank percentiles. Timings include proof challenge round trips. Client CPU/RAM values are in the result JSON; they are not aggregate server resource consumption.

An [earlier same-host run](hpsc/performance-results-earlier.json) measured 12.21 objects/s. Shared-host scheduling varies; this is not a controlled architecture comparison or an SLA.

Run `npm run benchmark`; optional `SIEPMU_BENCH_ITERATIONS` accepts 5–300. This does not measure maximum capacity, WAN delay/loss, large fanout, server CPU/RAM, storage growth, reconnect storms, hardware or field military networking. Preserve the environment and source digest with each run.
