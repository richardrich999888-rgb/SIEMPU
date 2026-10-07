# Demonstrator endpoint cryptography

This browser-compatible ESM module uses native WebCrypto. It also runs in Node 24. The protocol is documented in `docs/protocols/IMPLEMENTATION_CONTRACT.md`; these functions are not an approved military cryptographic implementation or an SAG-graded algorithm.

Each device has separate P-256 signing and encryption keys. Every information object has a fresh AES-256-GCM content key and nonce. An ephemeral ECDH key pair and HKDF-SHA256 derive the key that wraps the content key for the recipient. The complete context is AEAD additional authenticated data; the complete envelope is signed. The SHA-256 ciphertext hash is covered by that signature. ECDSA signatures use 64-byte IEEE P1363 encoding, not DER.

`encryptObject(context, payload, recipientPublicJwk, senderPrivateJwk)` returns `{envelope,signature,ciphertext}`. `decryptObject(submission, recipientPrivateJwk, senderPublicJwk)` verifies the signature, context, ciphertext digest, recipient key ID, authenticated key wrap and authenticated payload before returning the payload. Caller responsibilities remain:

- Obtain and pin the authority public key through a trusted provisioning channel.
- Verify authority signatures on directory snapshots, creation grants, control epochs and receipts.
- Bind the sender public key to the expected user and device through the verified directory. A key returned alongside a message is not independent identity evidence.
- Enforce online policy through the authority. Local cryptographic decryption is not proof of current authorization or that the sender's clock is accurate.
- Render message text using safe text APIs, and treat received files as untrusted content. MIME/name validation is not malware scanning or content sanitization.

Generated JWKs are minimal `{kty,crv,x,y}` public objects and add `d` for private material. `keyId` hashes the exact canonical public JWK; adding optional JWK metadata changes the identifier. The named encoding rejects floating-point numbers, negative zero, unsupported objects, sparse arrays and cycles. It is not a full RFC 8785 implementation.

`sealVault` and `openVault` encrypt JSON with AES-256-GCM and PBKDF2-SHA256 at 600,000 iterations, using a random 32-byte salt and 12-byte IV. Passphrases require at least 12 characters. KDF parameters and salt/IV are bound as additional authenticated data. Vault protection depends on passphrase entropy, the browser and endpoint. Keys and plaintext exist in application memory during use; no guaranteed memory erasure, hardware-backed storage, hardware attestation, endpoint-compromise resistance or forward secrecy is claimed. Server denial or later revocation cannot recall content keys already released or plaintext already observed.
