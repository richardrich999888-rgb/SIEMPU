# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Review date: 2026-10-08 (India). Frozen implementation: `main` at `49774e2111197412efb31d459317c0df23a838af`.
Engineering plan for synthetic, authorised tests; not SAG/IAF approval or a TRL award.
Source hierarchy: official PS-69, filed-proposal copies, frozen code and execution evidence, then candidate documentation.
See [source register](source-evidence-register.json) and [proposal reconciliation](17-proposal-reconciliation.md).

## Minimum TRL 5 relevant environment proposal

Two or more managed user workstations/browser clients in separate virtual LANs representing LAB-UNIT-A and LAB-UNIT-B; gateway/control/relay on independent service processes; separate authenticated synthetic connector service; evidence/monitoring observer in a distinct trust zone; managed DNS/NTP, TLS trust, controlled WAN impairment Linux host. Real organisations/locations/units are not represented.

## Topology and operational controls

Lab endpoints -> firewall/VLAN -> impaired untrusted public-Internet emulator -> TLS gateway -> auth control and ciphertext relay -> encrypted at-rest stores. A second management VLAN carries health and redacted telemetry; independent verifier reads exported signed receipts with external checkpoint. Capture traffic at ingress/relay to verify no plaintext within inspected wire payloads. No real IAF network routing, production keys or operational data.

## Reproducible impairment matrix (illustrative lab variables, NOT IAF SLAs)

| Profile                | Example input                                | Invariant checked                         |
| ---------------------- | -------------------------------------------- | ----------------------------------------- |
| N0 stable              | <10 ms added RTT, 0 simulated loss           | baseline                                  |
| N1 latency             | +150ms delay with jitter 30ms                | no key release bypass/duplicate           |
| N2 loss                | 2% packet loss, burst windows                | bounded retries, idempotence              |
| N3 constrained         | 512 Kbit/s shaping                           | queuing, backpressure and file bounds     |
| N4 isolation           | complete client cut for 30 min               | local ciphertext only; no peer delivery   |
| N5 flapping            | 60s down/30s up cycles                       | safe resumption and current policy checks |
| N6 DNS/cert            | DNS NXDOMAIN; expired service certificate    | fail closed and evidence                  |
| N7 clock               | simulated skew using isolated VM time        | reject stale proofs/expiry                |
| N8 control unavailable | kill authority, relay still up               | no unauthorised release                   |
| N9 snapshot rollback   | restore older copy in isolated disposable VM | detect or document undetected rollback    |

Profiles N0–N9 are initial experimental values pending sponsor and repeatability review. Run multiple repetitions, preserve seed/qdisc command, kernel/image hash, timestamp, workload and actual telemetry. Record gross throughput, p50/p95/p99 when sample count supports it, delivery timeliness, retries, data integrity and fail-closed rate.

## Tools and separation

- Linux tc/netem: network packet impairment, per-interface scheduling; requires root in isolated lab; https://man7.org/linux/man-pages/man8/tc-netem.8.html
- Toxiproxy (deferred alternative): deterministic TCP cuts/latency if netem is insufficient; https://github.com/Shopify/toxiproxy
- Mininet: defer unless elaborate virtual host topology needed; ns-3: defer to protocol simulation research, not essential for HTTP application validation.
- TLS test authority, packet capture, synchronised time stamps, disposable client profiles and scrubbed structured logs.
- Hardware: existing managed endpoints and isolated test network preferred to tactical radios/rugged purchases.

## Reality limitations

Emulation cannot recreate real public-ISP routing, malware prevalence, classified key handling, field-grade environmental tests, IAF identity/control domains or sponsor security policy. Separate demonstrator measurements from IAF acceptance.
