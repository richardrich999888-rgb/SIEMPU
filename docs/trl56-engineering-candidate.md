# AIRON–SIEPMU TRL 5/6 engineering candidate

This document describes the repository candidate on which the engineering gates run. It is a laboratory readiness package, not an IAF acceptance statement, a SAG approval, a certification, or a self-awarded TRL.

The candidate now has:

- an explicit TLS 1.3 transport profile with mutual TLS on service links, certificate-chain validation, certificate identity pins, CRL support, rotation tests, and a hard failure when a secure profile is configured with a plaintext override;
- an isolated testbed generator with separate web, control, relay, checkpoint, collector, adapter, unit A, unit B, denied unit, and administrator zones;
- a versioned crypto-provider boundary. WebCrypto remains the laboratory provider. A second Node runtime provider exercises the same approved suite and wire format. Opaque software handles are tested, while hardware-backed custody remains an integration gate;
- independent checkpoint custody with a separate SQLite store and signing key. Startup and protected dispatch enter quarantine until the authority chain, authorization-state digest, freshness window, and independently retained head agree;
- a separate integration adapter with its own endpoint identity, schema validation, replay/idempotency store, and policy-controlled submission path;
- a separate security collector that accepts only signed redacted events, rejects unknown fields and secrets, deduplicates batches, enforces retention bounds, and returns signed acknowledgements;
- a provisional dual-control action for FLASH release. Creating a FLASH object does not release it. A commander in the same unit and mission must approve the exact envelope digest at the current epoch. This is an applicant-proposed laboratory policy pending sponsor confirmation;
- a signed offline package that includes a Node runtime, hashes every file, refuses links and path traversal, preserves an independent monotonic ledger, and requires a separately signed rollback authorization for a lower version;
- a hosted CI testbed job that applies Linux `tc/netem` profiles, records observed qdisc state and measurements, and uploads the machine-readable evidence.

The current software provider advertises `hardwareBacked: false`, `pqc: false`, and `sagGraded: false`. Those values are intentional. The implementation does not claim that WebCrypto, PKCS#11, SoftHSM, or a software KAT satisfies the filed SAG requirement. A sponsor-authorised provider, exact permitted algorithm set, lifecycle rules, and formal evaluation route remain external decisions.

The candidate’s offline operation is an autonomous local service enclave with a controlled reconnect path. It is not a claim that a browser can continue to issue authority credentials without an authority, nor that a previously released plaintext can be recalled. Inter-enclave transfer, military PKI, classified information handling, hardware key custody, and sponsor acceptance remain integration boundaries.

## Reproduction

The focused engineering suite is:

```text
npm run test:engineering
```

The full native suite is:

```text
npm test
```

The local testbed topology is generated with:

```text
npm run testbed:provision
```

The impairment runner requires Docker, `sudo`, `nsenter`, and `tc` on the host used for the run:

```text
npm run testbed:run
```

The local managed workspace does not have the network-admin capability needed for namespace impairment. The hosted CI job is therefore the authoritative netem execution path; local secure-stack, custody, adapter, collector, crypto-provider, role, and offline-package tests remain executable without that capability.

## Evidence interpretation

The source revision, runner image, Node version, network profile, observed qdisc state, workload count, failure count, and measured percentiles are recorded in `artifacts/testbed/measurements.json` by CI. A percentile is omitted when the sample size is too small. No IAF service-level target is inferred from the provisional laboratory targets.
