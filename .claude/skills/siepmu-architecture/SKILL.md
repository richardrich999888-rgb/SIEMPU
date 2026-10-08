---
name: siepmu-architecture
description: Running architecture of SIEPMU - services, processes, ports, storage, trust zones, the endpoint client, wire protocol, and a source-code map distinguishing implemented components from plans. Use before modifying any service, adding a route, moving logic between components, or answering "where is X implemented".
---

# SIEPMU architecture (implemented, as of the integration branch)

Read `docs/engineering/CURRENT_STATE.md` first for the exact SHA this describes.

## Processes and trust zones

| Process                | Entry point                                                      | Holds                                                                           | Must never hold                   |
| ---------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------- |
| Web gateway            | `services/web/server.mjs`                                        | static shell, same-origin proxy to authority                                    | plaintext, keys, DB               |
| Control authority      | `services/control/server.mjs` -> `core.mjs` (`Authority`)        | users, devices, policy, epoch, **opaque wrapped keys**, evidence chain (SQLite) | plaintext, recipient private keys |
| Ciphertext relay       | `services/relay/server.mjs`                                      | ciphertext blobs by SHA-256 (separate SQLite)                                   | keys, plaintext, policy           |
| Checkpoint custodian   | `services/evidence/server.mjs`, `custody.mjs`                    | independently signed evidence heads                                             | authority signing key             |
| Security collector     | `services/monitoring/server.mjs`, `collector.mjs`                | signed redacted telemetry                                                       | content, keys, tokens             |
| Integration adapter    | `services/integration/server.mjs`, `adapter.mjs`                 | synthetic external schema checks                                                | real military interfaces          |
| Browser endpoint       | `apps/unit-client/app.mjs`, `packages/crypto/crypto.mjs`         | device keys (encrypted vault), plaintext                                        | —                                 |
| UI decision/role model | `apps/unit-client/decisions.mjs`, `capabilities.mjs` (ADR-013)   | content-free explanations; deny-by-default view gating                          | enforcement (authority only)      |
| Rust verifier          | `native/evidence-verify` (ADR-012, `spec/SIEPMU-EVIDENCE-v1.md`) | public keys, exported evidence (general mode only)                              | private keys, replay store        |
| Admin console          | `apps/admin-console/admin.mjs`                                   | role-gated views                                                                | content                           |
| Verifier               | `apps/verifier/verify.mjs`                                       | public keys, exported evidence                                                  | —                                 |

Local dev ports: web 8080, control 8081, relay 8082 (`README.md`). The secure profile
(`deployment/secure/harness.mjs`) runs all five services over TLS 1.3 with mTLS identities.
The 10-zone testbed (`deployment/testbed/provision.mjs`, `run.mjs`) adds Unit A, Unit B,
denied unit and administrator zones under Linux netem.

## Object lifecycle (authority `core.mjs`)

`POST /api/grants` (creation grant) -> endpoint encrypts -> `POST /api/objects`
(`validateSubmission`) -> `POST /api/objects/:id/prepare` (`prepare`: READY or HELD + signed
ADMISSION evidence) -> FLASH only: `POST /api/objects/:id/authorize` (`authorizeRelease`) ->
`POST /api/objects/:id/claim` (`claim`: transactional re-check `authorityReason` +
`approvalReason` + epoch, then RELEASE_ISSUED or RELEASE_DENIED) -> relay fetch and digest check
-> `POST /api/objects/:id/ack`. Routes are exact static matches in `#route` (no dynamic dispatch).
States: PENDING, READY, HELD, RELEASED, DELIVERED.

## Wire contract

- Schema v1 (no labels), v2 (+`messagePriority`, `messageDomain`), v3 (lab provider envelope: +`providerId`, `suiteVersion`, `senderCryptoKeyId`, `suitePolicyRevision`, `providerSignature`).
- Single definition: `packages/crypto/crypto.mjs` (`contextFields`, `envelopeFieldsFor`,
  `hasEnvelopeShape`, `hasMissionLabels`). Re-exported by `packages/object-format/schema.mjs`.
- Canonical JSON: `packages/protocol/canonical.mjs`. Types: `packages/object-format/types.d.ts`.
- Persisted envelopes are re-validated at every decision: `services/admission/integrity.mjs`.
- Evidence schema: `services/evidence/decision.mjs`; verifier is intentionally independent.

## Storage

`database/migrations/001..005*.sql`, checksummed by `Authority.migrate()`. Never edit an applied
migration; add a new numbered file. Relay DB is separate. Backups: `scripts/backup.mjs`.

## Source map (where to look)

| Concern                                 | Files                                                                                   |
| --------------------------------------- | --------------------------------------------------------------------------------------- |
| Identity, MFA, sessions, device binding | `core.mjs` `login`, `challenge`, `proof`, `bound`; `services/control/primitives.mjs`    |
| Policy and release                      | `core.mjs` `authorityReason`, `prepare`, `claim`, `approvalReason`, `dutyVisible`       |
| Duty roles                              | `packages/mission/policy.mjs`                                                           |
| Crypto (classical endpoint)             | `packages/crypto/crypto.mjs`                                                            |
| Crypto agility / PQC                    | `packages/crypto-provider/`, `services/crypto-policy/registry.mjs`, `packages/pqc-lab/` |
| Transport                               | `packages/transport/tls.mjs`                                                            |
| Release packaging                       | `scripts/build.mjs`, `packages/release/offline.mjs`, `Dockerfile`                       |
| Browser offline shell                   | `apps/unit-client/sw.js`, `vault-store.mjs`                                             |

## Architectural invariants

See `CLAUDE.md`. In particular `crypto.mjs` imports only `canonical.mjs` (ADR-007) and lab code
is excluded from release artefacts (ADR-008).

## Planned or partial (do not describe as implemented)

Horizontal authority availability, hardware key custody (TPM/HSM/PKCS#11), FIDO2, real IAF PKI,
real military interfaces, traffic-analysis resistance, cross-domain guards, disconnected
peer-to-peer delivery. Browser PQC is not implemented (no ML-KEM in the browser endpoint).

## Workflow for architectural change

1. Read the relevant ADRs in `docs/decisions/`.
2. Identify the trust boundary affected; state it in the commit message.
3. Add or update tests at the boundary (negative cases first).
4. Run `npm run validate` and `npm run test:e2e`; update `docs/engineering/CURRENT_STATE.md`.
5. New decision -> new `docs/decisions/ADR-NNN-*.md` and index row.

## Definition of done

No trust-boundary regression, invariants intact, ADR written for any boundary change, docs and
OpenAPI (`docs/api.openapi.json`, checked by `tests/contracts/api-contract.test.mjs`) updated.
