---
name: siepmu-defence-integration
description: Integrating SIEPMU with military systems using synthetic adapters only - adapter contracts, authorization boundaries, sponsor-supplied specifications, and recording sponsor questions instead of inventing classified interfaces. Use when a task mentions AFNET, DCN, IAF PKI, legacy systems, tactical networks, message formats, external interfaces, or the integration adapter.
---

# SIEPMU defence integration (synthetic only)

## Rule zero

No real military interface, protocol, message format, network, credential or classified
specification is present or may be inferred. Every external system is represented by a
**synthetic adapter** with an explicit, versioned, authenticated contract. If a real interface
detail is needed, stop and record the question.

## Existing synthetic integration

| Component       | Path                                                        | Behaviour                                                                                                                      |
| --------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Adapter service | `services/integration/server.mjs`, `adapter.mjs`            | Independent process; mTLS identity; authenticated schema validation; sender/destination policy; replay prevention; idempotency |
| Adapter client  | `packages/integration/client.mjs`                           | Signed synthetic submissions                                                                                                   |
| Authority route | `POST /api/integration/validate` (admin-scoped, `core.mjs`) | Validates synthetic schema only                                                                                                |
| Tests           | `tests/independent-services.test.mjs`                       | mTLS, exchange, idempotency, redaction, acknowledgement                                                                        |
| Docs            | `docs/independent-services.md`                              |                                                                                                                                |

Follow-up (not done): port the PR #16 adapter negative cases (stale freshness, ambiguous in-flight
restart quarantine, durable admission capacity) onto this adapter. See
`docs/engineering/RECONCILIATION_MATRIX.md`.

## Boundary rules

- The adapter never receives plaintext or recipient keys; it forwards ciphertext submissions or
  validated metadata through the authority's normal admission and release path.
- The adapter cannot bypass current-policy release, FLASH approval or duty checks.
- Adapter identities are separate mTLS identities with their own pins; compromise of the adapter
  must not grant authority administrative rights.

## When an interface or policy is unknown

1. Implement against a synthetic schema marked `SYNTHETIC` in code and docs.
2. Add a row to `research/trl56/16-iaf-clarification-register.md` with: the exact question, why it
   blocks, what assumption the synthetic adapter makes, and the owner (sponsor).
3. Mirror it in `docs/requirements/open-questions.md` if it affects requirements.
4. Never commit sponsor-provided specifications to this public repository.

## Interoperability research

`research/trl56/05-iaf-interoperability-readiness.md`, `research/defence-comparison/README.md`
(note: source records D04-D15 were lost and must be re-retrieved before citing).

## Definition of done

Synthetic contract versioned and tested (positive and negative), sponsor question recorded,
no real-system claim, `npm run test:engineering` passes.
