# Implemented API

Authoritative dispatch: [core.mjs](../services/control/core.mjs); transport validation: [server.mjs](../services/control/server.mjs). The versioned [implementation contract](protocols/IMPLEMENTATION_CONTRACT.md) specifies envelopes and bodies. The [OpenAPI 3.1 contract](api.openapi.json) inventories implemented endpoints and defines tested request/response schemas for the authentication, device-proof, grant, object exchange, and policy-update slice below. The protocol contract remains authoritative for signature encoding, canonical body hashing and policy semantics. Each operation declares its coverage in `x-contract-coverage`; a route inventory entry does not imply complete schema or success-path test coverage.

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

## Executable contract coverage

Run `node --test tests/contracts/api-contract.test.mjs`. The suite launches the real gateway, control authority and relay with fresh synthetic identities. It validates successful request and response bodies against the checked-in OpenAPI schemas, checks every documented protected route rejects a missing bearer token, and exercises these 14 success operations:

| Operations              | Contract and behavioral checks                                                                      |
| ----------------------- | --------------------------------------------------------------------------------------------------- |
| Login, me, logout       | Token/user/expiry; nullable unbound device; revoked session rejection                               |
| Challenge, bind, enroll | Purpose-specific challenge fields; one-use P-256 signatures; pending enrollment                     |
| Control, grant          | Signed epoch/policy snapshot and creation grant                                                     |
| List, submit, prepare   | Full envelope and wrapped-key schema at submission; signed receipts; metadata-only list and prepare |
| Claim, ACK              | Recipient device restriction; decryptable claim; issuance receipt; client ACK transition            |
| Admin policy update     | Admin role and exact-body proof; policy/epoch change; subsequent signed HOLD without key material   |

The tests verify signed receipts and decrypt a claimed payload with an independent protocol peer. They reject invalid, replayed and body-mismatched proofs, undeclared envelope fields, missing claim/ACK fields and malformed policy inputs; stale expected epochs return a signed HOLD. Request schema checks describe valid client bodies; runtime rejection of every schema-invalid permutation is not claimed. OpenAPI cannot establish signature validity, canonical base64 encoding, cross-field expiry relationships, or current authorization: runtime checks and protocol tests cover those semantics.

The contract checker supports the explicit JSON Schema vocabulary used here and rejects unsupported validation keywords. It is a test helper with no added runtime dependency, not a general OpenAPI validator. Other admin, evidence, directory, integration and metadata success responses remain outside this bounded schema slice. Their route/authentication inventory coverage is labeled explicitly.

## Errors and correlation

Every control API response supplies a server-generated `X-Request-Id`. The gateway preserves that ID for proxied responses and generates its own for local rejections. Incoming request IDs are not echoed or trusted. JSON errors always include `{error, code, requestId}`; `requestId` must equal the response header. Successful bodies retain their endpoint-specific shape.

An admission HOLD returns HTTP 409 and additionally includes metadata `object` and signed `receipt`. It never includes `envelope`, `wrappedKey`, or `ciphertext`. `DecisionReceipt` specifies the decision ID, release state, reason, authority/policy references, object digests and proof evidence. `DELIVERED` means a client acknowledgment, not evidence of a human reading the content.

| Rejection                                       | HTTP status | Tested code                           |
| ----------------------------------------------- | ----------- | ------------------------------------- |
| No bearer token                                 | 401         | `UNAUTHENTICATED`                     |
| Session revoked after logout                    | 401         | `SESSION_INVALID`                     |
| Session lacks approved device binding           | 403         | `DEVICE_UNTRUSTED`                    |
| Non-admin policy mutation                       | 403         | `FORBIDDEN`                           |
| Proof does not bind the exact body              | 403         | `PROOF_BODY_MISMATCH`                 |
| Invalid proof signature                         | 403         | `INVALID_PROOF`                       |
| Consumed challenge                              | 403         | `PROOF_REPLAY_OR_EXPIRED`             |
| Sender attempts recipient claim                 | 403         | `RECIPIENT_ONLY`                      |
| Expected epoch is stale                         | 409         | `EPOCH_MISMATCH`                      |
| Policy now denies the edge                      | 409         | `POLICY_DENIED`                       |
| Undeclared envelope field / invalid ACK receipt | 400         | `ENVELOPE_SCHEMA` / `RECEIPT_INVALID` |
| Invalid required input / malformed JSON         | 400         | `INVALID_INPUT` / `INVALID_JSON`      |
| Gateway content type / Origin rejection         | 415 / 403   | `CONTENT_TYPE` / `ORIGIN_MISMATCH`    |

The direct control listener uses `JSON_REQUIRED` and `ORIGIN_DENIED` for its own content-type and Origin checks. Those differ from the public gateway codes above; both use the same error/correlation shape. Other domain errors use stable machine-readable `code` strings. Clients should branch on status/code, not human-facing `error` text.
