# Implemented architecture

The implementation runs three Node 24 processes: [web gateway](../services/web/server.mjs), [control authority](../services/control/core.mjs) and [ciphertext relay](../services/relay/server.mjs). [start.mjs](../scripts/start.mjs) manages local process lifecycle; [Compose](../compose.yaml) defines the container equivalent. The unit workspace and administration console are browser applications.

The gateway serves a static allowlist and proxies same-origin API requests. Control owns identity, devices, roles, policies, admission, evidence and metrics in a single transactional SQLite authority. Relay has a separate ciphertext database and authenticated workload interface. These are bounded processes; identity/policy/evidence modules deliberately share one transaction boundary.

The sender encrypts locally. Relay receives ciphertext; control retains the signed envelope and opaque recipient-wrapped content key. Recipient claim revalidates current authority and commits a unique issuance plus evidence before returning usable envelope/key material. The relay does not have recipient private keys or wrapped content keys. A compromised control authority can still release wrapped keys improperly.

This is a single-host prototype, with no horizontal high-availability or distributed consensus claim. See [ADRs](decisions/README.md), [crypto](crypto.md), [release semantics](reconnection.md), [requirements](requirements/README.md) and [limitations](limitations.md).
