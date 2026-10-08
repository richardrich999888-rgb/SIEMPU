# Exchange interface

The exchange boundary is implemented by [`Authority`](../control/core.mjs).
Identity, policy decisions, object metadata, issuance and evidence share its
control database. The independently running [relay](../relay/server.mjs) stores
ciphertext blobs; no additional exchange process is defined here.

## Public contract

All routes require a bound approved device. Every POST requires a one-use
[operation proof](../device/README.md) covering its full body excluding `proof`.

| HTTP route                      | Body and operation                                | Response                                                                                             |
| ------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `POST /api/objects`             | `{envelope,signature,ciphertext,proof}`; `submit` | `{object,receipt}`; operator sender                                                                  |
| `GET /api/objects`              | None                                              | `{objects}`; caller's sent/received metadata                                                         |
| `POST /api/objects/:id/prepare` | `{proof}`; `prepare:<id>`                         | `{object,receipt}`; either participant                                                               |
| `POST /api/objects/:id/claim`   | `{expectedEpoch,proof}`; `claim:<id>`             | `{object,envelope,signature,senderSigningPublicKey,receipt,ciphertext}`; exact recipient user/device |
| `POST /api/objects/:id/ack`     | `{receiptId,proof}`; `ack:<id>`                   | `{object,receipt}`; exact recipient user/device                                                      |

Held claims return HTTP 409 `{error:'Admission held',code,object,receipt}` without
an envelope or ciphertext. Successful routes return HTTP 200. `object` metadata
contains `{id,objectId,senderUserId,recipientUserId,senderDeviceId,recipientDeviceId,
senderUnitId,recipientUnitId,missionId,classification,state,reason,preparedEpoch,
ciphertextHash,createdAt,expiresAt}`. It excludes the wrapped content key. Stored
`createdAt` is submission time; the signed envelope retains the creator's time.

## Internal methods and transaction boundaries

`validateSubmission(session, body)` validates the [object wire format](../../packages/object-format/README.md),
sender/grant/destination bindings and ciphertext digest. `submit()` validates,
awaits relay `putBlob(digest, bytes)`, then rechecks sender authorization and
submission inside a transaction before inserting object and `SUBMITTED` evidence.
An exact object-ID/envelope/signature retry returns its original submission
receipt; conflicting immutable data returns `IDEMPOTENCY_CONFLICT`. Relay writes
can precede a failed control transaction; an orphan ciphertext is not an issuance.

`owned(session,id)` restricts metadata to sender or recipient. `prepare()` records
current admission as `READY` or `HELD` with a signed `ADMISSION` receipt; an
existing eligible issuance remains `RELEASED`/`DELIVERED`. Preparation does not
return the envelope or wrapped key and is not a prerequisite bypassing claim's
own validation.

`claim()` checks current authority and `expectedEpoch` inside `BEGIN IMMEDIATE`.
A denial persists `HELD` plus `RELEASE_DENIED` evidence. A first successful claim
atomically appends signed `RELEASE_ISSUED` evidence, inserts the unique issuance
and updates the object to `RELEASED`. Eligible retries recheck authority, append
`RELEASE_RETRY` evidence and reuse the original issuance receipt. The commit is
the release-capability issuance point. HTTP dispatch fetches ciphertext from the
relay afterward; a fetch failure cannot undo the committed issuance.

`ack()` requires the issuance receipt's `eventId`, updates to `DELIVERED` and
appends `DELIVERY_ACK` atomically; repeated ACKs return the prior ACK receipt.
`DELIVERED` means client acknowledgement, not proof of human reading. Later
revocation cannot recall previously disclosed keys or plaintext.

The boundary owns `objects` and `issuances` and appends to the common signed
`evidence` chain. The schema permits `REJECTED`, although validation failures
before insertion need not create a row. See
[`tests/http.test.mjs`](../../tests/http.test.mjs),
[`tests/recovery.test.mjs`](../../tests/recovery.test.mjs), and
[`docs/decisions/ADR-003-transactional-release.md`](../../docs/decisions/ADR-003-transactional-release.md).
