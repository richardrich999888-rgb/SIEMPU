# Reconnection and release invariant

The [unit client](../apps/unit-client/app.mjs) maintains an [encrypted revision-checked vault/outbox](../apps/unit-client/vault-store.mjs). Cached grants permit bounded local creation. After browser reload, cached shell/vault support local work; networking requires fresh MFA and device binding. Reconnection refreshes control state and re-evaluates queued objects. There is no offline peer delivery.

The enforcement point is [Authority.claim](../services/control/core.mjs): `BEGIN IMMEDIATE` serializes issuance with policy updates. Current authority plus expected epoch are checked, then a unique issuance, signed receipt, object state and evidence commit atomically. Only afterward does the API return the opaque wrapped content key and ciphertext. READY is not a capability.

**Bounded invariant:** a policy change committed before issuance prevents use of the superseded decision. A release committed first may already be usable; later revocation cannot recall keys/plaintext. This is not atomic network delivery or global instantaneous revocation. A committed retry retains receipt identity but rechecks authority before redisclosure.

[Authority tests](../tests/authority.test.mjs) use separate-process/database races, crash hooks, restart and duplicate claims; the negative control demonstrates a check-then-send race. [Browser validation](testing/browser-validation.md) covers real offline browser reload and policy hold/release. The comparison is a negative control, not a comprehensive comparison against mature secure collaboration/TDF systems. Local restart safety is separate from malicious complete snapshot rollback.
