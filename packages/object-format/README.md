# Object-format interface v1

The implemented wire format is shared by
[`packages/crypto/crypto.mjs`](../crypto/crypto.mjs),
[`packages/protocol/canonical.mjs`](../protocol/canonical.mjs) and validation in
[`services/control/core.mjs`](../../services/control/core.mjs). This directory is
the format boundary's reference; it does not supply a second schema validator.
[`types.d.ts`](types.d.ts) supplies checked, type-only contracts for P-256 JWKs,
signed packets, grants, object contexts/envelopes, encrypted objects, payloads,
vault packets, device challenges and release scope. The annotated crypto and
client consumers use these contracts during `npm run typecheck`; untrusted wire
input still requires runtime validation.

## Encoding and schema

`SIEPMU-CJSON-v1` recursively sorts object keys, preserves array order and accepts
only null, booleans, strings and safe integer JSON numbers. It rejects negative
zero, unsupported objects, accessors, symbols, cycles and depth over 64. It is a
project encoding, not an RFC 8785 conformance claim. Binary fields use canonical
unpadded base64url; SHA-256 digests use 64 lowercase hexadecimal characters.

`encryptObject(context,payload,recipientPublicJwk,senderPrivateJwk)` returns
`{envelope,signature,ciphertext}`. The envelope has exactly these members:

| Fields                                                    | Wire values / authority constraints                                                                                   |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `schemaVersion`, `keyVersion`                             | Integer `1`                                                                                                           |
| `objectId`                                                | UUID v4 accepted by control                                                                                           |
| `senderUserId`, `senderDeviceId`, `senderUnitId`          | Bound submitting identity/device/unit                                                                                 |
| `recipientUserId`, `recipientDeviceId`, `recipientUnitId` | UUID v4 values; destination ownership and unit must match                                                             |
| `recipientKeyId`                                          | SHA-256 of canonical minimal recipient public encryption JWK                                                          |
| `missionId`                                               | `[A-Za-z0-9._:-]{1,80}` at control                                                                                    |
| `classification`, `action`                                | `DEMO`, `deliver`                                                                                                     |
| `createdAt`, `expiresAt`                                  | Safe integer milliseconds; expiry after creation and within one hour; creation at most 30 seconds ahead at submission |
| `creationGrant`                                           | Authority-signed `{payload,signature,keyId}` creation grant                                                           |
| `cryptoSuite`                                             | `P256-HKDF-SHA256-AES256GCM`                                                                                          |
| `ciphertextHash`                                          | SHA-256 of decoded content ciphertext including authentication tag                                                    |
| `nonce`                                                   | 12-byte content AES-GCM nonce                                                                                         |
| `wrappedKey`                                              | Exactly `{ephemeralPublicKey,salt,iv,ciphertext}`                                                                     |

`context` consists of every envelope field above except `ciphertextHash`, `nonce`
and `wrappedKey`. The complete canonical context is additional authenticated data
for both AES-GCM operations. The sender's signature covers the complete canonical
envelope using ECDSA P-256/SHA-256, 64-byte IEEE P1363 signature encoding.

Content uses a fresh 32-byte AES key and 128-bit authentication tag. Wrapping uses
ephemeral P-256 ECDH, HKDF-SHA256 with 32-byte random `salt` and info
`SIEPMU_WRAP_V1`, then AES-256-GCM with a 12-byte `iv`. Wrapped ciphertext is 48
bytes (32-byte content key plus tag). The public ephemeral JWK is
`{kty:'EC',crv:'P-256',x,y}`. Public keys must not carry private `d` material.

## Payload and consumer requirements

Encrypted plaintext is canonical UTF-8 JSON with exactly
`{kind:'text'|'file',name,mime,data}`. `data` is base64url. File names are 1–180
characters with no slashes, control characters, `.` or `..`; MIME types are
validated strings. Text uses `text/plain` or `text/plain;charset=utf-8` and valid
UTF-8. Both filenames and MIME types stay encrypted.

The crypto helper allows up to 16 MiB of raw payload data, but the HTTP prototype
is more restrictive: control accepts 16–1,048,592 decoded ciphertext bytes and
the transport body is capped at 1,500,000 bytes. JSON/base64 overhead reduces usable
file size; the helper limit is not a promise of upload capacity. Control also has
stricter identifier/time rules than the standalone crypto helper.

`decryptObject(submission,recipientPrivateJwk,senderPublicJwk)` validates context,
sender signature, recipient key ID, ciphertext digest and both authentication
tags before returning a validated payload. Callers must separately verify the
authority's grant, directory, control and decision packets with a trusted key;
local decryption alone does not establish current authorization. Use
`publicJwk()` before provisioning keys: the browser `keyId()` hashes the exact
supplied public JWK while control normalizes it to minimal public fields.

See [`docs/protocols/IMPLEMENTATION_CONTRACT.md`](../../docs/protocols/IMPLEMENTATION_CONTRACT.md)
and [`tests/crypto.test.mjs`](../../tests/crypto.test.mjs) for the implemented
protocol and interoperability/tampering checks.
