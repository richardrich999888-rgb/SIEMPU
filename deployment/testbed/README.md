# Deterministic userspace impairment experiments

`fault-proxy.mjs` implements bounded HTTPS application-request interruptions, response truncation, deterministic delay/jitter and chunk pacing. It is explicitly **not packet-loss emulation, bandwidth calibration or tc/netem**. Profiles are repeatable inputs for a synthetic laboratory, not IAF acceptance targets.

| Profile     | Added delay | Deterministic jitter | Response pacing         |
| ----------- | ----------- | -------------------- | ----------------------- |
| stable      | 0 ms        | 0 ms                 | 64 KiB chunks, no wait  |
| constrained | 25 ms       | repeating 0/10/5 ms  | 4 KiB chunks, 5 ms wait |
| interrupted | 5 ms        | 0 ms                 | 2 KiB chunks, 1 ms wait |

The controller can disconnect before forwarding, hold an offline state, or cut a response after an exact byte count. There is no remote fault-control API. The controller is available only to the local test harness. All upstream traffic uses the secure HTTPS peer; the proxy can only call bounded `/api/...` paths on its fixed configured destination.

`tests/network-failure/recovery.test.mjs` executes an outage followed by 64 KiB encrypted exchange, truncates the issued-key response and recovers exact bytes with a fresh device proof, verifies only one `RELEASE_ISSUED` event, and separately changes current unit policy during an outage so queued ciphertext becomes HELD with signed `RELEASE_DENIED` evidence. The measured recovery interval includes the explicitly injected outage/retry and is printed as test diagnostics with request/cut/response-byte counters. It is a single synthetic scenario measurement, not a statistically qualified percentile or throughput benchmark.

In the development environment, `/usr/sbin/tc` exists but effective/bounding Linux capabilities are zero, including absent `CAP_NET_ADMIN`; Docker is absent. No qdisc was changed and no container run or netem trial is claimed. Relevant-environment validation must repeat these invariants using operator-controlled network namespaces/hosts and approved `tc/netem` profiles, synchronized timing, repeated samples and independent evidence custody. Extended disconnections, true low-bandwidth packet shaping, concurrent multi-host clients and clock faults remain distinct unexecuted scenarios.
