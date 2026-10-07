# Operating the demonstrator

Use the [tested entry points](../README.md), [deployment instructions](deployment.md) and [.env.example](../.env.example). `npm run bootstrap` explicitly provisions random synthetic profiles and keys in the ignored private data directory. `npm start` starts the three services. Never use demo identities for operational data or expose default HTTP to the public internet.

The admin console shows users/units/devices/sessions, policy/epoch, object states, alerts and metrics; privileged mutations require signed device proofs. The auditor sees read-only security/evidence. Session tokens remain in memory; a page restart requires reauthentication for network operations.

Control logs structured timestamp, service, request ID, method, result, reason and latency. It intentionally omits request bodies, protected plaintext, tokens and private keys. Persistent alerts cover authentication/authorization denial, authority changes and denied release. Metrics expose request/error counters, state counts, epoch, uptime and process RSS. This is local observability, not a full SIEM, distributed tracing backend or trained anomaly detector.

Health endpoints are documented in [deployment](deployment.md). Investigate HOLD using its reason and signed receipt; do not bypass policy to clear a queue. Stop writers before backup, retain a verification root/checkpoint independently, and exercise [restore](disaster-recovery.md). Operator tasks still needed for a pilot: approved TLS/key custody, log retention, storage/queue capacity planning, incident response ownership, monitoring export, patch cadence and hardware/device management.

## Offline identity recovery

Stop services and use the controlled local maintenance path:

```sh
SIEPMU_MAINTENANCE_CONFIRMED=1 node scripts/recover-identity.mjs alice /protected/new-recovery-material.json
```

This requires the authority's local keys/database. It rotates password/TOTP, revokes all user sessions and increments authority while leaving device enrollment unchanged. Transfer the new private material through the approved enrollment channel, then destroy that output. The command does not create self-service recovery or prove administrator honesty. Test coverage is in `tests/additional-boundaries.test.mjs`.
