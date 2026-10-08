# TRL 5 advancement environment

**Status:** applicant-defined laboratory environment. The IAF has not defined a relevant environment
(open question Q14). This environment is the applicant's best available approximation. It is
**not** a sponsor-agreed relevant environment and has not been independently witnessed.

## What "host" means here

The three hosts are **Linux network namespaces on one kernel**, not physical machines or virtual
machines. They are isolated in the following ways:

| Isolated per host                                              | Shared by all hosts                          |
| -------------------------------------------------------------- | -------------------------------------------- |
| Network stack: interfaces, addresses, routes, loopback, ports  | Kernel, CPU, memory, clock                   |
| Name resolution (`/etc/netns/<ns>/hosts`)                      | File system (the state directories differ)   |
| State directory: profiles, sessions, TLS identities, databases | Node.js runtime binary                       |
| Processes started for that host (`ip netns exec`)              | The operator account (root) that starts them |

Virtual machines were not available to this run. The container has no `/dev/kvm`, no QEMU and no
Docker daemon. The namespace topology was the strongest separation available, and the
limitation is recorded rather than hidden. A multi-machine run is the first external gate in
`READINESS_DECISION.md`.

## Topology

```text
 Host A  siepmu-a                  Host B  siepmu-b                        Host C  siepmu-c
 sender unit                       platform                                recipient unit
 alice, snd1-4                     gateway  0.0.0.0:8443  (only external)  bob, bravo, eve, rcp2, rcp3, lrx1-4
 WAN emulator 127.0.0.1:8443 ──►   control 127.0.0.1:8441                  document system + adapter :8446
                                   relay   127.0.0.1:8442                  Node + Rust verifiers
 10.69.1.2/24 sa0 ═══ veth ═══ sb1 10.69.1.1/24   custodian 127.0.0.1:8444
                                   collector 127.0.0.1:8445
                                   10.69.2.1/24 sb2 ═══ veth ═══ sc0 10.69.2.2/24
```

- **Routing.** Hosts A and C have no route to each other. Everything passes through Host B's TLS
  gateway.
- **Internal services.** Host B's internal services bind Host B's loopback, which no other
  namespace can reach.
- **Outside network.** No namespace has a default route or any route to the outside network
  (T7.1).
- **Name resolution.** Each host resolves `web` to the address it reaches the gateway on. The
  gateway certificate SAN is `DNS:web`, so TLS hostname verification is real. Host A resolves
  `web` to its own loopback, where the WAN emulator listens.
- **Conductor.** The conductor (`scripts/trl5-validation.mjs`) runs in the root namespace and has
  **no network path** to any host. It acts only by starting processes inside a host namespace
  (`deployment/relevant-env/platform.mjs agent()`). Each step is a fresh agent process. Agents
  reuse a saved session token, because the authority refuses a TOTP code replayed within its
  30-second step.

### Material each host holds

| Host | Private material                                                                                                        | Public material                                        |
| ---- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| A    | profiles of alice and snd1–4 (device keys, password, TOTP secret)                                                       | CA certificate, authority public key, peer descriptors |
| B    | authority database and keys, custody and collector keys, relay secret, lab PKI, admin profile, operator client identity | —                                                      |
| C    | profiles of bob, bravo, eve, rcp2, rcp3, dmsc and lrx1–4; adapter and document-system TLS identities                    | CA certificate, authority public key, peer descriptors |

Recipient private keys exist only on the recipient's host. The conductor writes profiles into host
state directories during provisioning. This is a laboratory shortcut that stands in for
per-device enrolment on separate machines, and it is listed as a gap.

## Network impairment

| Mechanism                  | Where                       | Used for                                           | Notes                                                                                                       |
| -------------------------- | --------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Userspace WAN delay relay  | Host A, in front of gateway | P1, P2, P4 delay and jitter (local run)            | `deployment/relevant-env/wan-relay.mjs`. In-order and seeded (mulberry32). Delays whole chunks, not packets |
| Kernel TBF qdisc           | A↔B veth, both ends        | P3, P4 bandwidth (local run)                       | Real kernel rate limiting                                                                                   |
| Link administratively down | A↔B veth, both ends        | T2.2, T3.6 outages                                 | Real loss of connectivity                                                                                   |
| Kernel netem               | A↔B veth, both ends        | P1–P4 and loss profiles L1/L2 (hosted CI job only) | The local kernel has `# CONFIG_NET_SCH_NETEM is not set`                                                    |

Packet loss is emulated **only** in the hosted CI job (`relevant-env` in `.github/workflows/ci.yml`).
The local run reports P0–P4 and outages only.

## Inventory (local run)

| Item          | Value                                                                                 |
| ------------- | ------------------------------------------------------------------------------------- |
| OS            | Ubuntu 24.04.5 LTS (container), kernel 6.18.44                                        |
| CPU / memory  | 4 vCPU Intel Xeon @ 2.10 GHz, 16 GiB, shared by all three hosts                       |
| Node.js       | 24.21.0 (official linux-x64 tarball)                                                  |
| Rust          | rustc 1.97.0, for the release verifier `native/target/release/siepmu-evidence-verify` |
| iproute2      | 6.1.0 (`ip`, `tc`), Ubuntu package 6.1.0-1ubuntu6.4                                   |
| Kernel config | `CONFIG_NET_NS=y`, `CONFIG_NET_SCH_TBF=y`, netem not built                            |

The machine-readable inventory of each run is `artifacts/trl5/environment-inventory.json`. It
holds the source commit, a dirty flag, the source digest, runtime versions and the capability
probe.

## Dependencies added for this environment

**No runtime or npm dependency was added.**

| Dependency                   | Version | Source and licence              | Why                                                      | Review                                                                |
| ---------------------------- | ------- | ------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------- |
| iproute2 (`ip`, `tc`)        | 6.1.0   | Ubuntu archive; GPL-2.0         | Namespaces, veth, TBF and netem. The standard Linux tool | OS-distributed; invoked with fixed argv arrays, never through a shell |
| Kernel netem (`sch_netem`)   | kernel  | Linux kernel; GPL-2.0           | Loss and delay in hosted CI                              | Loaded with `modprobe` on the runner                                  |
| TLA+ tools (existing CI job) | 1.8.0   | github.com/tlaplus/tlaplus; MIT | Already used by `npm run formal:check`                   | Unchanged by this sprint                                              |

Tools considered and **not** adopted:

- **k6.** Load is generated by the agents through the real client stack (sealing, MFA sessions,
  signed requests). A protocol-level load tool would bypass endpoint cryptography and measure the
  wrong thing.
- **OpenTelemetry.** The platform already exports signed, content-free telemetry to an independent
  collector (T5.1). An OpenTelemetry pipeline adds a dependency and a new data path for
  observability that already exists.
