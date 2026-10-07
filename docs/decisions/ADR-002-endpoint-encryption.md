# ADR-002: ciphertext relay and separate key-release gate

Status: accepted design; implementation evidence is tracked separately.

## Context

R5 explicitly requires E2EE. A relay that decrypts payloads for inspection creates a different boundary. A relay holding both ciphertext and a recipient-decryptable wrapped key could release the object early if compromised, despite an application policy check.

## Decision

Use Node native crypto and browser WebCrypto, not a new primitive. The endpoint generates a fresh AES-256-GCM content key and nonce for every object. Canonical signed context is also AEAD associated data. Separate P-256 ECDSA signing and P-256 ECDH encryption keys identify the software device. Ephemeral ECDH, HKDF-SHA256 and AES-GCM wrap the content key to the recipient's pinned encryption-key identity.

The blind relay stores immutable ciphertext only. The trusted control authority stores the signed envelope and opaque recipient-wrapped key, and returns them only after current-authority claim commits. It does not possess endpoint decryption keys. Object listing, administration and monitoring must omit the wrapped key. Relay and authority compromise are therefore different cases.

Use the exact encoding and domain separation in the implementation contract. Project canonical JSON accepts only the defined value subset; it is not a claim of complete RFC8785 conformance. Sign all authority-relevant fields, including recipient key identity, destination, action, grant, suite, hashes and expiry. Reject unknown/invalid protocol versions and malformed cryptographic inputs.

Keep sessions in memory. Encrypt endpoint private-key material and drafts in a local vault using PBKDF2-SHA256, a random salt and AES-GCM. The iteration count in the v1 contract is 600,000; it must be measured for supported devices. Never persist an unencrypted private key or session token for convenience.

## Consequences and limits

The authority cannot ordinarily decrypt the object, but a compromised authority can release a wrapped key contrary to policy. A compromised client distribution or key directory can defeat trust without an independent pin. A compromised endpoint can disclose plaintext. Static recipient encryption keys provide no forward secrecy; later possession can expose retained ciphertext and wrapped keys. Recovery, key rotation and escrow require a separately reviewed protocol before production use.

Origin, destination, mission, classification, timing, sizes and decision metadata remain visible to the control authority; filenames and content type remain inside the encrypted payload. The prototype does not provide anonymity or traffic-analysis resistance. Payload confidentiality does not by itself protect plaintext database metadata, authentication secrets or backups.

No SAG grading, cryptographic-module certification or new-cryptography claim follows from this choice.
