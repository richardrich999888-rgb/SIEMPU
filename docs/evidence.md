# Evidence and independent verification

[Authority.event](../services/control/core.mjs) signs sequence, previous hash, event ID/type, time, epoch, actor and scoped decision details. SHA-256 covers the complete signed packet. Release records bind ciphertext/envelope digest, origin, recipient/destination, mission/action, creation grant/epoch, current policy digest, revocation version and proof evidence. Signing and state transition occur in one transaction. Signed checkpoints bind count/head hash.

Run [detached verifier](../apps/verifier/verify.mjs) with an independently trusted public key:

```sh
node apps/verifier/verify.mjs receipt.json trusted-public-key.json
node apps/verifier/verify.mjs evidence.json trusted-public-key.json --checkpoint saved-checkpoint.json
node apps/verifier/verify.mjs receipt.json trusted-public-key.json --object-digest EXPECTED_HASH --epoch 7 --object-id EXPECTED_ID
```

Exit 0 passes; nonzero fails. Expected-binding flags are for a single release receipt; check a chain separately. [Verifier documentation](../apps/verifier/README.md) explains all inputs. [Negative tests](../tests/crypto.test.mjs) cover wrong roots, changed/reordered/deleted records, wrong expected digest/epoch/object and anchored prefix replay.

A signature proves the signer made the statement, not that it was true, policy correct or endpoint uncompromised. DELIVERED means client ACK, not human reading. A self-contained chain cannot detect a valid suffix removal; retain a checkpoint outside the authority before suspected rollback. Even that checkpoint says nothing about later unwitnessed records.
