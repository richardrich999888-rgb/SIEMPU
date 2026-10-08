# Implementation contract v1

This is a synthetic-data demonstrator, not an approved operational system. All code is newly authored; no private portfolio source is imported.

## Runtime and services

Node >=24. Use native crypto, WebCrypto, HTTP and node:sqlite; no npm runtime dependencies. Three bounded processes: web gateway (port 8080), control authority API (8081), blind ciphertext relay (8082). Control owns identity/device/policy/admission/evidence in one transactional SQLite database. Relay has a separate SQLite store containing only immutable ciphertext blobs and workload replay nonces. Local default is loopback; network deployment requires TLS. SQLite serialises authority writes via BEGIN IMMEDIATE, WAL and synchronous FULL. Single-host prototype, no horizontal HA claim.

## Security

Password+scrypt and mandatory RFC6238 TOTP. Opaque 15-minute bearer sessions in browser memory; stored only as digest server-side. Durable TOTP replay floor and rate limits. Fresh database role/user/device checks on each operation. Four roles: admin (manage/read security), operator (send/receive), viewer (receive only), auditor (read evidence/security). Admin cannot bypass user-content authorization.

Device keys: distinct ECDSA P-256 signing and ECDH P-256 encryption keys. Enrolment requires signed server challenge and administrator approval; session binding requires proof of possession. Final sensitive operations require signed one-use session/device-bound operation challenge. Software key binding, no hardware attestation claim. Endpoint vault encrypts key material and drafts with PBKDF2-SHA256 (600000 iterations), random salt and AES-GCM. Session tokens are not persisted.

Canonical JSON is recursive sorted object keys using JavaScript key ordering, arrays preserved, null/booleans/strings and safe integers only; reject unsupported values. Protocol uses generated ASCII IDs. It is a named project encoding, not a claim of complete RFC8785 compliance. All signatures use ECDSA/SHA256 raw P1363 (64 bytes), base64url. Server public signing key pinned by local provisioning/TOFU; a compromised key directory or client distribution remains trusted-boundary risk.

## Envelope

camelCase keys. `context`: schemaVersion=1, objectId(UUID), senderUserId, senderDeviceId, senderUnitId, recipientUserId, recipientDeviceId, recipientUnitId, recipientKeyId, missionId, classification='DEMO', action='deliver', createdAt(integer milliseconds), expiresAt, creationGrant(signed packet), cryptoSuite='P256-HKDF-SHA256-AES256GCM', keyVersion=1.

Fresh 32-byte AES content key and 12-byte nonce. Payload AES256-GCM AAD = canonical(context); ciphertext includes tag. Endpoint payload is UTF8 JSON `{kind:'text'|'file', name, mime, data}` where data is base64url bytes. Filenames/content type stay encrypted.

Wrap content key using ephemeral P256 ECDH, HKDF-SHA256 with random 32-byte salt and info UTF8 `SIEPMU_WRAP_V1`, AES256-GCM random 12-byte IV, AAD canonical(context). `wrappedKey={ephemeralPublicKey,salt,iv,ciphertext}`. RecipientKeyId=SHA256(canonical(public encryption JWK)). `envelope={...context,ciphertextHash,nonce,wrappedKey}` signed as a whole by sender device. Submission `{envelope,signature,ciphertext}` (base64url ciphertext). Signature authenticates all authority-relevant fields. Authority stores envelope including opaque wrapped key; blind relay receives ciphertext only. Static recipient encryption key gives no forward secrecy. Authority cannot decrypt, but a compromised authority could release a wrapped key contrary to policy.

## Filed duty-role/priority synthetic extension (version 2)

When assigned by an authenticated administrator, `dutyRole` further restricts the original generic `operator`, `viewer`, `admin`, and `auditor` roles without elevating any of them. Message schema v2 adds sender-signed, AEAD-authenticated `messagePriority` (FLASH/IMMEDIATE/PRIORITY/ROUTINE) and `messageDomain` (GENERAL/INTEL). Sender and receiver duty assignments are checked at admission and again in the final transactional release. A duty-profile user cannot release version 1 content by omitting the labels. The recipient's object list hides unauthorised priority metadata. These synthetic labels are not classification markings or approved military entitlement rules.

Encryption, decryption, submission and persisted-object admission share one exact v1/v2 field contract. Unknown versions, extra fields and missing fields fail closed; v1 does not accept v2 labels. At prepare and release, both versions retain canonical stored-byte validation, sender-signature verification and binding to the stored object, identities, devices and ciphertext digest. The pure contract helpers are exported by the existing `packages/crypto/crypto.mjs` browser asset, which imports only the stable `canonical()` API. This deliberately avoids introducing a new module or named canonical export into older installed service-worker dependency graphs during interrupted upgrades. Cryptographic provider implementations must not be imported back into this module.

A later duty-role restriction produces a durable internal HELD decision and signed admission or release-denial evidence before the response is concealed as `404 OBJECT_NOT_FOUND`. Priority-sensitive metadata, receipts and wrapped keys are omitted from that response. Unknown object IDs and unrelated users remain opaque without mutating another user's objects.

## Authority and release

Global monotonically increasing epoch and revocationVersion in authority database. Policy edges bind fromUnit,toUnit,missionId,allow. Users have missionIds and active status. Grant signed packet binds user/device/unit, mission list, creation epoch/policy digest, issuedAt/expiresAt, max sensitivity DEMO. Grant must still be valid at server admission; no assertion that untrusted client timestamp proves pre-expiry creation. Local cached work is allowed only while grant and local rollback floor are valid, no offline peer delivery.

Object states PENDING, HELD, READY, RELEASED, DELIVERED, REJECTED. Sender may create/queue offline. Submission validates immutable object/signature/grant and current sender/device; uploads ciphertext to relay (idempotent digest path) then inserts object and evidence transactionally; orphan ciphertext is not a release. Prepare/re-evaluate checks current sender/recipient/device/roles/membership/edge/grant/expiry and records READY at epoch e, or HELD with reason. No recipient key returned here.

Recipient claim requires session bound to recipient device + proof challenge, expectedEpoch. BEGIN IMMEDIATE serialises with policy updates. Revalidate all current authorities and expectedEpoch; mismatches HOLD. Atomically persist unique release issuance, signed receipt, evidence chain entry and object state; COMMIT is the release-capability issuance linearisation point. Only then return envelope/wrapped key/ciphertext. A committed issuance may already be usable; revocation afterward cannot recall it or guarantee network-send timing. Retry rechecks current authority before redisclosing wrapped key; returns original issuance receipt on eligible retries. Recipient deduplicates object IDs and acknowledges; DELIVERED denotes accepted client ACK, not proof of human reading. Graceful/crash restart != full DB snapshot anti-rollback.

## HTTP API (all JSON except UI/assets)

- GET /api/meta -> {version,serverPublicKey,serverKeyId,limits,securityProfile}
- POST /api/auth/login {username,password,otp} -> {token,user,expiresAt}; GET /api/auth/me -> {user,device,expiresAt}; POST /api/auth/logout {}
- POST /api/auth/challenge {purpose:'enroll'|'bind'|'operation',deviceId?,operation?,requestHash?} -> {challengeId,challenge}; operation is e.g. 'submit', 'prepare:'+objectId, 'claim:'+objectId, 'ack:'+objectId, 'grant'. For operation challenges, requestHash is the SHA256 of canonical request body excluding proof. Signature signs canonical(challenge), including this body digest. The server checks the exact body digest before consuming proof.
- POST /api/devices/enroll {label,signingPublicKey,encryptionPublicKey,challengeId,signature} -> {device}; POST /api/auth/bind {deviceId,challengeId,signature} -> {device}
- GET /api/control -> signed packet {payload:{epoch,revocationVersion,policyDigest,issuedAt,expiresAt},signature,keyId}
- GET /api/directory -> {users,devices}; approved keys bound to directory signed snapshot and current device IDs. Client stores fingerprints in encrypted vault.
- POST /api/grants {proof:{challengeId,signature}} -> signed grant packet
- POST /api/objects {envelope,signature,ciphertext,proof:{challengeId,signature}} -> {object,receipt}
- GET /api/objects -> {objects} (sender/recipient only; metadata/receipts, never wrapped key)
- POST /api/objects/:id/prepare {proof} -> {object,receipt}
- POST /api/objects/:id/claim {expectedEpoch,proof} -> {object,envelope,signature,ciphertext,senderSigningPublicKey,receipt} or 409 {error,code,object,receipt}
- POST /api/objects/:id/ack {receiptId,proof} -> {object,receipt}
- GET /api/admin/overview -> {units,users,devices,sessions,policies,objects,epoch,revocationVersion,alerts,metrics} (redacted)
- POST /api/admin/units {name}; POST /api/admin/users {username,unitId,role,missionIds,dutyRole?} -> {user,initialPassword,totpSecret,otpauthUri} (one-time enrollment; the authority generates the 144-bit initial password, and a client-supplied `password` is rejected with `PASSWORD_SERVER_GENERATED` so no password ever enters an operation-proof request hash)
- PATCH /api/admin/users/:id {active?,role?,missionIds?}; POST /api/admin/devices/:id/approve {}; POST /api/admin/devices/:id/revoke {}; POST /api/admin/sessions/:id/revoke {}; PUT /api/admin/policies {fromUnit,toUnit,missionId,allow}
- GET /api/evidence/export -> {records,checkpoint} (auditor/admin); GET /api/evidence/checkpoint -> signed checkpoint; GET /api/metrics -> JSON; GET /health
- POST /api/integration/validate {schemaVersion:1,externalId,objectId,destinationUnitId,missionId} -> validation receipt only (admin; synthetic adapter, no AFNET access)

All mutation routes require application/json and same-origin when Origin is present. Admin mutations require a bound approved admin device and one-use signed operation proof whose operation='admin:'+METHOD+':'+path. Rate/size caps and safe route parsing. Enrollment/login no automatic demo fallback. Errors expose codes, never keys or stack traces.

## Evidence

Each record is signed `{payload:{sequence,previousHash,eventId,eventType,timestamp,epoch,actorId,objectId?,decision?,reason?,details},signature,keyId}`. Hash=SHA256(canonical(record)). Include full scoped decision inputs in release details. Chain append and state mutation same transaction. Checkpoint signed payload `{sequence,headHash,issuedAt}`. Verifier accepts trusted public key supplied independently; external saved checkpoint required for suffix-truncation assurance. CLI `node apps/verifier/verify.mjs receipt.json public-key.json`, or `--checkpoint saved-checkpoint.json` for chain export. Signatures do not prove factual truth.

## Test hooks

Core functions expose optional constructor hooks for tests only, never HTTP knobs. Inject before release commit / after commit failures; use independent processes/connections for race ordering. Persist revocations/epochs/evidence across restart. Required test artifacts contain synthetic content, no runtime credentials. Comparison baseline is ordinary un-fenced check/send vs current-authority transactional claim; no world-first/patentable claim.
