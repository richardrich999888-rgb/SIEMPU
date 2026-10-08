# Cryptographic provider boundary

`packages/crypto/crypto.mjs` is a protocol layer. `createObjectCryptography(provider)` selects one provider explicitly and does not retry another provider when the selected provider fails.

The version-1 provider contract exposes:

- key generation and opaque private-key handles;
- public-key projection and key identity;
- signing and signature verification;
- WebCrypto-compatible digest, ECDH, HKDF and AES-GCM operations;
- provider version, suite inventory and capabilities;
- explicit suite negotiation and failure errors;
- key destruction and usage checks.

`packages/crypto/providers/webcrypto.mjs` is the supported software demonstration provider. `packages/crypto/providers/node-classic.mjs` uses the independent Node crypto API for conformance comparison. Both are software providers using the platform runtime. They are not HSMs, FIPS validations, SAG modules, or hardware custody.

The signed envelope binds the crypto suite, key version, recipient key ID, context and ciphertext digest. A provider with no approved suite, an unknown version, an invalid handle, a wrong usage, or a provider failure fails closed. No unapproved downgrade path exists.

Post-quantum cryptography is deliberately a roadmap decision. The platform has a provider seam and versioned suite context so a sponsor-approved hybrid or replacement suite can be introduced after public standards, key sizes, transition rules, and evaluation requirements are fixed. It does not insert an unreviewed hybrid protocol into the demonstrator.
