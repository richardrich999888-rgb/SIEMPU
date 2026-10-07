# Implemented API

Authoritative dispatch: [core.mjs](../services/control/core.mjs); transport validation: [server.mjs](../services/control/server.mjs). The versioned [implementation contract](protocols/IMPLEMENTATION_CONTRACT.md) specifies envelopes and bodies. The [OpenAPI 3.1 route specification](api.openapi.json) inventories implemented endpoints; request/response schema coverage is explicitly partial, so the protocol contract remains authoritative for cryptographic bodies.

| Surface                                                                                              | Current access / purpose                                                   |
| ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| GET `/api/meta`; `/health`, `/live`, `/ready`                                                        | Public version/key/profile; authority database health                      |
| POST `/api/auth/login`                                                                               | Password + current unused TOTP; rate limited                               |
| `/api/auth/me`, `/logout`, `/challenge`, `/bind`                                                     | Session lifecycle and device possession                                    |
| POST `/api/devices/enroll`                                                                           | Logged-in user, signed enrollment challenge; pending admin approval        |
| GET `/api/control`, `/api/directory`                                                                 | Bound approved device; signed epoch/directory snapshots                    |
| POST `/api/grants`                                                                                   | Bound operator and body-bound operation proof                              |
| GET/POST `/api/objects`                                                                              | Participant list / signed sender submission; no list exposes wrapped keys  |
| POST `/api/objects/:id/prepare`, `/claim`, `/ack`                                                    | Scoped one-use proofs; recipient-only claim/ACK; current authority checked |
| `/api/admin/overview`                                                                                | Bound admin/auditor; redacted operational view                             |
| `/api/admin/units`, `/users`, `/devices/:id/approve`, `/revoke`, `/sessions/:id/revoke`, `/policies` | Bound admin and body-bound signed operation proof for mutations            |
| `/api/evidence/export`, `/checkpoint`, `/api/metrics`                                                | Bound admin/auditor                                                        |
| POST `/api/integration/validate`                                                                     | Admin; synthetic schema validation, no external military connection        |

Mutations require `application/json`; supplied Origin must match. Session uses Authorization Bearer, not a cookie. Operation challenges bind session, device, operation, canonical body hash, random nonce and expiry. HTTP errors expose stable code and request ID; held claims return 409 with reason and signed decision, without usable key material. Observe published limits at `/api/meta` and concrete validation in source. Test examples: [HTTP](../tests/http.test.mjs), [authority](../tests/authority.test.mjs).
