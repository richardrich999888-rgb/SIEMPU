# ADR-010: laboratory schema-v3 objects use the normal authority release transaction

Status: accepted for laboratory use, 2026-10-08.

## Context

PR #16 added PQC providers, a provider engine and an authority `CryptoPolicyRegistry`, but no
application path used them: `Authority` ignored `allowPqcLab`, classical submission rejected v3,
and the endpoint envelope module was corrupted and never imported. Running a real object through
the engine exposed a second defect: `wrapKey` inlined the whole application context into HKDF
`info`, and WebCrypto limits `info` to 1024 bytes. Every real context (with its signed creation
grant) exceeded the limit, so wrap v1 never worked for an actual object.

## Decision

- **Gate.** `SIEPMU_ALLOW_PQC_LAB` (only omitted or exactly `1`) -> `Authority({allowPqcLab})`.
  Closed gate: key registration, v3 submission and lab policy changes return
  `403 PQC_LAB_DISABLED`; a persisted v3 object is HELD at release.
- **Keys.** A bound device registers its own public descriptor (`POST /api/crypto/keys`, signed
  operation proof `crypto-key:register`); status `pending` until an administrator activates it
  (`PATCH /api/admin/crypto/keys/{keyId}`). Status and suite-policy changes go through `change()`
  and advance the epoch. Revocation is terminal.
- **Policy at both decision points.** `CryptoPolicyRegistry.reason(e, creation)` runs at submission
  (suite in `newSuites`, policy revision equals current) and inside the release transaction (suite
  in `newSuites` or `legacySuites`, keys active or legitimately retired, key-to-device binding,
  ML-DSA-65 provider signature) for **every** schema version. Removing the classical suite from
  `newSuites` stops new classical objects; removing it from `legacySuites` holds old ones.
- **Signatures.** v3 requires both the P-256 device identity signature and the ML-DSA-65
  provider signature (conjunction). The claim response returns the sender's registered public
  descriptor; the recipient checks it against the signed `senderCryptoKeyId`.
- **Wrap v2.** HKDF-SHA256 `info` = canonical `{domain: SIEPMU_PROVIDER_KEY_WRAP_V2, providerId,
suiteId, recipientKeyId, contextDigest}`; the full context is authenticated as AES-GCM AAD.
  Packet `schemaVersion` 2; v1 and unknown versions are rejected. No v1 wrap was ever persisted.
- **Evidence.** Release and retry evidence carry `details.crypto` (provider, suite, key IDs, policy
  revisions and digest). `decisionEvidence` refuses a v3 release without valid provenance; the
  independent verifier requires provenance exactly when `objectSchemaVersion` is 3 and uses its own
  suite table.
- **Endpoint.** `packages/pqc-lab/envelope.mjs` composes existing primitives only (see its header).
  Lab code stays excluded from release artefacts (ADR-008); the browser endpoint remains classical.

## Consequences

Evidence: `tests/pqc/end-to-end.test.mjs` (ML-KEM-768) and the X-Wing case in
`packages/pqc-lab/laboratory.check.mjs`. This is laboratory engineering evidence only. The
composition requires independent cryptographic review (`research/cryptographic-standards/INDEPENDENT_REVIEW.md`);
RFC 9180 HPKE with PQ KEMs is the standards-track alternative to evaluate. No SAG grading,
validation or approval is implied.
