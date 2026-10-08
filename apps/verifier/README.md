# Detached evidence verifier

Requires Node 24.19 or newer and no installed packages. Supply a trusted public P-256 JWK obtained independently of the export being checked. The verifier needs no running admission, control, relay or web service, no credentials, and no authority database. It uses native Node cryptography independently of the server's signing implementation; only the documented canonical encoding is shared.

## Strict release decision verification

Use the explicit release mode when accepting a selected release receipt. **All three expected bindings and a durable local replay store are required.** Compute the expected digest over the ciphertext bytes; retain the intended object ID and expected issuance epoch independently of the receipt. Do not copy these expectations from an untrusted packet.

```sh
./tools/verify release-receipt.json trusted-public-key.json \
  --mode release \
  --object-digest EXPECTED_SHA256_HEX \
  --epoch 7 \
  --object-id EXPECTED_OBJECT_ID \
  --replay-store ./accepted-receipts.sqlite
```

The direct entry point `node apps/verifier/verify.mjs` accepts the same arguments. The result is `type: "release-receipt"` with `strictReleaseVerified`, `bindingVerified`, `replayChecked` and `replayRecorded` true only after all checks and the replay-store commit succeed. Invalid signatures, altered payloads, wrong digest/epoch/object ID, inconsistent signed epochs, non-release decisions, missing receipt identity, repeated receipts, and unavailable storage fail closed with exit status 1. A release receipt must identify `RELEASE_ISSUED` / `RELEASED`; a signed admission or denial is insufficient. Strict mode enforces the complete current HTTP receipt schema: UUID identities and decision ID, sequence/hash/time fields, release state and reason, object/envelope/policy digests, creation and authority epochs, revocation version, sender/recipient/device/destination references, mission/action, policy reference, and software proof challenge/session evidence. It rejects unknown or missing members and contradictory actor/recipient, destination/mission policy references, or creation epochs. Schema consistency authenticates the recorded references; it does not independently establish that those identities or policy statements were true. Legacy or internal-call receipts lacking the HTTP proof fields remain inspectable in general mode but cannot pass strict release acceptance.

SQLite stores accepted identities as the unique pair `(trusted key ID, signed event ID)`. A changed ECDSA signature over the same event does not bypass replay detection. `BEGIN IMMEDIATE`, a unique primary key, and `synchronous=FULL` make check-and-consume atomic across concurrent local verifier processes. A ten-second busy timeout permits short writer contention; longer contention fails closed. New store files are owner-readable/writable only. The parent directory must already exist. Keep it under the verifier operator's control, and use the same retained store for the same verification domain.

The receipt is consumed **before** success is printed. A crash after commit can leave an accepted identity without printed success; reconcile that identity rather than deleting the store or repeating a downstream action blindly. This provides at-most-once verifier acceptance, not an exactly-once external business action. Replay protection survives normal process restarts and applies only to that retained local store. Deleting, replacing or restoring an older store loses its later replay history; a fresh store is a new replay domain. There is no trusted hardware counter or cross-machine replay registry. A different signing key creates a separate key scope.

The module API is `verifyReleaseReceipt(input, trustedPublicKey, {objectDigest, epoch, objectId, replayStore})`; it throws on failure and consumes the identity on success. It authenticates a historical issuance decision. It does not contact the authority, establish current authorization, recall a released key, or prove human delivery.

## General signature and evidence-chain inspection

The default mode preserves read-only signature and chain inspection:

```sh
./tools/verify receipt.json trusted-public-key.json
./tools/verify evidence-export.json trusted-public-key.json --checkpoint saved-checkpoint.json
./tools/verify release-receipt.json trusted-public-key.json --object-digest EXPECTED_SHA256_HEX --epoch 7 --object-id EXPECTED_OBJECT_ID
```

Exit status 0 means the requested inspection passed. It does **not** mean strict release acceptance unless `--mode release` was used. General inspection does not consume receipts or detect single-receipt replay. Its optional binding arguments check only supplied expectations; omitted expectations remain unchecked. `--replay-store` is rejected outside release mode. A chain and a selected receipt must be verified separately: release mode rejects chain exports and `--checkpoint`.

A chain starts at sequence 1 with a previous hash of 64 zero characters. Each next record binds the SHA-256 hash of the complete preceding signed packet. A signed checkpoint binds the chain length and final hash. An external checkpoint must have been retained outside the authority before a suspected rollback. It can prove that a chain has not been truncated or replaced through its saved sequence; it cannot reveal deletion of later events that were never independently checkpointed. A checkpoint embedded in a replayed export is insufficient for this assurance.

Signatures authenticate statements under a trusted key. They do not establish factual truth, an uncompromised authority, accurate wall-clock time, or hardware-protected signing keys. The module API `verifyEvidence(input, trustedPublicKey, {checkpoint, objectDigest, epoch, objectId})` remains read-only and throws on failure.

## Executable acceptance evidence

```sh
node --test --test-concurrency=1 tests/verifier-replay.test.mjs
node --test --test-concurrency=1 tests/acceptance/*/*.test.mjs
```

The verifier tests run the actual CLI against invalid signatures, tampered payloads, wrong bindings, restarted-process replay, re-signed receipt replay, unavailable storage, and eight concurrent processes competing for a fresh receipt. Exactly one concurrent invocation must succeed.

The three named HTTP acceptance scenarios cover a complete Unit A to Unit B encrypted exchange with acknowledgement and detached verification after the services stop; queued-offline recipient revocation with no wrapped-key response; and authorized backlog release after reconnecting across an unrelated authority change. The vertical slice inspects the real relay process's `relay/relay.sqlite`, verifies the exact stored ciphertext and allowed schema, and checks for the test plaintext and wrapped-key data. This supports ciphertext-only content storage with hash, length, timestamp and workload replay metadata; it does not claim a metadata-free relay. Offline tests block the sender test transport while constructing the local queue; they do not simulate a radio, browser persistence, or operating-system network outage.
