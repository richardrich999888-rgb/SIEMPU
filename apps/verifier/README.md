# Detached evidence verifier

Requires Node 24 or newer and no installed packages. Supply a trusted public P-256 JWK obtained independently of the export being checked.

```sh
node apps/verifier/verify.mjs receipt.json trusted-public-key.json
node apps/verifier/verify.mjs evidence-export.json trusted-public-key.json --checkpoint saved-checkpoint.json
node apps/verifier/verify.mjs release-receipt.json trusted-public-key.json --object-digest EXPECTED_SHA256_HEX --epoch 7 --object-id EXPECTED_OBJECT_ID
```

Exit status 0 means verification passed. Exit status 1 means input, signature, ordering, hash linkage, or checkpoint verification failed. The verifier uses native Node cryptography independently of the server's signing implementation; only the documented canonical encoding is shared.

A chain starts at sequence 1 with a previous hash of 64 zero characters. Each next record binds the SHA-256 hash of the complete preceding signed packet. A signed checkpoint binds the chain length and final hash. An external checkpoint must have been retained outside the authority before a suspected rollback. It can prove that a chain has not been truncated or replaced through its saved sequence; it cannot reveal deletion of later events that were never independently checkpointed. A checkpoint embedded in a replayed export is insufficient for this assurance.

Signatures authenticate statements under a trusted key. They do not establish that the statements are true, that the authority was uncompromised, that its clock was accurate, or that the key was hardware protected. A release receipt proves a signed issuance decision, not human reading or continued authorization.

The optional `--object-digest`, `--epoch` and `--object-id` arguments apply to a single `RELEASE_ISSUED` receipt. Supply expectations obtained independently: compute the digest over ciphertext bytes, retain the intended object ID, and supply the expected issuance epoch. The verifier compares these expectations with signed receipt fields and checks that `payload.epoch` agrees with `details.authorityEpoch`. A correctly signed receipt for another object or epoch fails when that differing expectation is supplied. Without expected bindings, a valid signature alone does not establish that the receipt belongs to the object or epoch the operator intended. Omitted expectations are not checked. These flags do not establish current authorization or factual truth, and are deliberately rejected for whole-chain exports to avoid ambiguous record selection. Verify the full chain and the selected receipt separately.

The module API is `verifyEvidence(input, trustedPublicKey, {checkpoint, objectDigest, epoch, objectId})`; it throws on failure. Checkpoint and expected-object modes are separate.
