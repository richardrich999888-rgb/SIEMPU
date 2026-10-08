# Endpoint cryptography

Actual implementation: [WebCrypto module](../packages/crypto/crypto.mjs), [canonical encoding](../packages/protocol/canonical.mjs), [server primitives](../services/control/primitives.mjs). Module [usage and boundary notes](../packages/crypto/README.md) specify the API.

A fresh AES-256-GCM key/nonce encrypts each text/file payload. Ephemeral P-256 ECDH plus HKDF-SHA256 derives an AES-GCM wrapping key for the recipient's static encryption key. Separate P-256 ECDSA keys sign the whole envelope, using SHA-256 and 64-byte P1363 signatures. Signed context includes identities, units, mission, destination key ID, grant, times, suite, action, hash and nonce. Canonical context is authenticated associated data.

Authority holds the opaque wrapped key until committed release; relay holds ciphertext alone. Filename and MIME are encrypted; routing identity/mission/time/size remain visible. Recipient verifies trusted sender binding, signature, digest, recipient-key ID, key wrap and payload authentication before display.

Local vault uses PBKDF2-SHA256 (600,000 iterations), random salt and AES-GCM; parameters are bound as AAD. No custom primitive is used. The project JSON encoding is not full RFC8785. Tests include independent native/WebCrypto interoperability, every context-field substitution, wrong recipient, tag corruption, malformed encoding and vault tamper: [crypto tests](../tests/crypto.test.mjs).

Protocol schema v2 additionally authenticates `messagePriority` and `messageDomain` in both sender signature and AEAD associated data. Version 1 is accepted only for users without a newly assigned duty role; recipients with a duty role hold all v1 objects rather than bypassing priority policy. Neither version provides the originally filed SAG/PQC dual-layer provider; approval and secure interoperability remain outstanding.

No forward secrecy for static recipient keys, hardware custody, automatic key recovery/rotation, memory-erasure guarantee or SAG grading is claimed. Compromised endpoints or a malicious key directory/client distribution can defeat confidentiality.
