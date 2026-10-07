# Device interface

Device enrollment, binding and operation proofs execute within
[`Authority`](../control/core.mjs) in the control process. This directory defines
that logical boundary; it is not another network service. Device identity is
software possession of a signing key, not hardware attestation.

## Public contract

| HTTP route                            | Request                                                              | Response                                                |
| ------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------- |
| `POST /api/auth/challenge`            | `{purpose,deviceId?,operation?,requestHash?}`                        | `{challengeId,challenge}`                               |
| `POST /api/devices/enroll`            | `{label,signingPublicKey,encryptionPublicKey,challengeId,signature}` | `{device}` with status `pending`                        |
| `POST /api/auth/bind`                 | `{deviceId,challengeId,signature}`                                   | `{device}`; approved device owned by the logged-in user |
| `POST /api/admin/devices/:id/approve` | `{proof}`                                                            | `{device}`; bound administrator                         |
| `POST /api/admin/devices/:id/revoke`  | `{proof}`                                                            | `{device}`; bound administrator                         |
| `GET /api/directory`                  | None                                                                 | `{users,devices,packet}`; bound approved device         |

Public device objects are
`{id,userId,unitId,label,status,signingPublicKey,encryptionPublicKey,createdAt}`.
`unitId` is derived from the owning user. Keys are public P-256 JWKs, normalized to
`{kty,crv,x,y}` in storage; private `d` values are rejected. The endpoint client
generates separate signing and encryption keys. Enrollment labels are 1–80
characters and reuse of an existing signing key is rejected.

## Challenge and proof contract

Every challenge contains `{domain:'SIEPMU_DEVICE_PROOF_V1',nonce,sessionId,purpose,
expiresAt}`. Its nonce is 32 random bytes encoded as base64url and its lifetime is
60 seconds. The signature covers the complete canonical challenge using ECDSA
P-256/SHA-256 with 64-byte P1363 encoding, encoded as base64url.

- `enroll`: requires `requestHash = SHA256(canonical({label,signingPublicKey,
encryptionPublicKey}))`; the proposed signing key verifies the proof.
- `bind`: requires `deviceId`; the existing approved device key verifies the proof.
- `operation`: requires a bound device, `operation` and the SHA-256 canonical
  request-body hash. The challenge includes the bound `deviceId`. The operation
  request carries `proof:{challengeId,signature}`; omit `proof` when computing
  the body hash.

Operation names are `grant`, `submit`, `prepare:<objectId>`, `claim:<objectId>`,
`ack:<objectId>`, or `admin:<METHOD>:<path>`. Their exact string and body digest
must match the issued challenge.

## Internal methods and transactions

`challenge(session, body)` persists a challenge. `proof(...)` checks its session,
scope, expiry, unused status and signature, then marks it used. `operation(session,
body, operationName)` rechecks binding, checks the body digest, consumes proof in
a transaction and attaches proof references for decision evidence. Proof
consumption commits before the requested business mutation: a failed operation
needs a new challenge for retry.

Enrollment consumes proof, inserts the pending device and appends evidence in one
transaction. Binding consumes proof, binds the session and appends evidence
atomically. `change()` serializes administrator approval/revocation with epoch
changes and evidence. Revocation also revokes sessions bound to that device;
revoked keys cannot be reapproved, and administrators cannot revoke their current
device. The boundary uses `devices` and `challenges`, with session updates shared
with [identity](../identity/README.md).

Directory `packet.payload` is `{users,devices,issuedAt,epoch}` and covers active
users and approved devices belonging to active users. Clients must verify this
packet with an independently trusted authority key before using directory keys.
See [`tests/authority.test.mjs`](../../tests/authority.test.mjs) and
[`apps/unit-client/challenge.test.mjs`](../../apps/unit-client/challenge.test.mjs).
