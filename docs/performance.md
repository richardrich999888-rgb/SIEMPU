# Measured performance

Source: [benchmark runner](../scripts/benchmark.mjs), generated `artifacts/benchmark/results.json`, recorded at `2026-10-07T19:22:37.734Z`. Node v24.19.0, Linux x64, Intel Xeon Platinum 8573C; 9 logical CPUs visible. Workload: **30 sequential 4 KiB synthetic objects**, one sender, two sessions, loopback HTTP and three server processes.

| Operation | Samples | p50 ms | p95 ms |
| --------- | ------: | -----: | -----: |
| Encrypt   |      30 |   1.14 |   5.68 |
| Submit    |      30 |  25.20 |  41.27 |
| Prepare   |      30 |  17.89 |  29.05 |
| Claim     |      30 |  23.32 |  35.60 |
| Decrypt   |      30 |   1.28 |   3.48 |

Total workload elapsed 2457.74 ms; achieved **12.21 objects/s**. Nearest-rank percentiles. Timing includes operation-proof round trips where used. Two login/device-bind samples ranged 98.36–152.94 ms; two samples are insufficient for a robust authentication distribution. Client CPU was 646,021 µs user + 76,475 µs system; client RSS 124,657,664 bytes. These are client-process numbers, not aggregate server consumption.

Run `node scripts/benchmark.mjs`; optional `SIEPMU_BENCH_ITERATIONS` accepts 5–300. Results vary by host/configuration. This is not maximum throughput, WAN/loss performance, fanout, concurrency, server CPU/RAM, storage-growth, reconnect-storm, hardware or military-network evidence. Those remain NOT MEASURED. Preserve each run's source commit and environment rather than replacing an earlier result silently.
