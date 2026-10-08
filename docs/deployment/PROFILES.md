# Deployment profiles: connected and isolated

Both profiles run the same services and the same release invariant. Only the network boundary and
the update path differ. Neither profile is approved for operational or classified use.

| Aspect                | Connected profile                                                                  | Isolated profile                                                                                       |
| --------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Purpose               | Units exchange over approved public or private networks to an operator-run gateway | A locally managed enclave keeps working with no external control plane                                 |
| Ingress               | TLS 1.3 gateway only; exact origin and Host allowlist; no CORS                     | Same gateway, reachable only on the enclave network                                                    |
| Service links         | mTLS with certificate pins (control↔relay, custodian, collector; adapter→gateway) | Same                                                                                                   |
| Identity roots        | Operator-held lab CA today; production PKI is a sponsor decision (Q05)             | Same CA, provisioned offline                                                                           |
| Updates               | Signed offline bundle or CI-built image pinned by digest                           | **Signed offline bundle only**: manifest signature, per-file hashes, rollback ledger                   |
| External dependencies | None required at runtime (zero npm runtime dependencies)                           | None                                                                                                   |
| Reconnection          | n/a                                                                                | Before any new release, the authority re-checks its state against the independent checkpoint custodian |
| Evidence              | Custodian and collector on separate service identities                             | Same; operators export evidence on media                                                               |
| Tested by             | Container CI job; secure-stack tests; Demos 2–4                                    | Testbed CI job (10 zones, netem); `tests/offline-release.test.mjs`; `tests/recovery.test.mjs`          |

## Hardening applied in both

- Containers run as UID/GID 1000 with a read-only root filesystem, dropped capabilities,
  `no-new-privileges`, and PID and memory limits.
- The relay cannot mount identity or key volumes.
- Secrets are files with mode `0600`; nothing is stored in Git.
- Health endpoints disclose no identities.
- Telemetry is redacted and signed, and sent to an independent collector.

## Not provided

- **Orchestration:** no Kubernetes or K3s. The current single-authority design does not need it.
  Evaluate it as a funded option for M3 if multi-host operation calls for it.
- **Platform:** no HA authority, no HSM, and no approved hosting environment.
- **Physical transfer:** air-gap transfer between enclaves is a separate authorisation boundary.
  No transfer procedure is authorised.

## Operating procedures

- Health, backup, restore and identity recovery: `docs/deployment.md`.
- Secure lab profile: `docs/secure-airgap-profile.md`.
- Frozen demonstration build and offline bundle: `docs/hpsc/FROZEN_BASELINE.md`.
