# 06 — SYNTRIASS Secure Exchange Protocol (SSEP) specification, draft 1

Status: **architecture specification consolidating what is implemented, with gaps marked.** The normative
wire formats remain `docs/protocols/IMPLEMENTATION_CONTRACT.md`, `spec/SIEPMU-CJSON-v1.md`,
`spec/SIEPMU-EVIDENCE-v1.md`, `spec/SIEPMU-EVIDENCE-RANGE-v1.md` and ADR-010/011/014. Where this document and
those disagree, those win. No new cryptographic primitive is defined; only reviewed constructions are composed.

## 1. Parties and trust

| Party              | Holds                                               | Must never hold                              |
| ------------------ | --------------------------------------------------- | -------------------------------------------- |
| Sender endpoint    | Plaintext, own signing key, recipient public keys   | Recipient private keys                       |
| Recipient endpoint | Own private keys, plaintext after release           | —                                            |
| Relay              | Ciphertext, digests, routing metadata               | Plaintext, any private key, wrapped keys     |
| Authority          | Policy state, opaque wrapped content keys, evidence | Plaintext, recipient private keys            |
| Custodian          | Anchor (head + state digest), custodian key         | Records beyond what it verifies, any content |
| Verifier (offline) | Authority public key, retained checkpoint           | Anything secret                              |

## 2. Message flow (implemented)

1. **Grant.** Authenticated, device-bound sender obtains a signed creation grant (unit, mission, destination,
   expiry, epoch).
2. **Seal.** Sender generates a random content key K, encrypts payload with AES-256-GCM (AAD = canonical
   context), wraps K for each recipient key (ephemeral P-256 ECDH → HKDF-SHA256 → AES-256-GCM; lab v3: ML-KEM
   - wrap v2), and signs the envelope (P-256 ECDSA; lab v3: + ML-DSA-65).
3. **Submit.** Ciphertext to the relay; envelope and wrapped keys to the authority, which validates schema,
   suite policy, signatures and grant, and stores wrapped keys opaquely.
4. **Claim (Trust Before Release).** Recipient requests release. One authority transaction re-validates
   current user, device, role, duty, unit/mission policy, destination, grant expiry, epoch, FLASH dual
   control and crypto policy; then either issues the wrapped key and writes `RELEASE_ISSUED`, or writes a
   `HELD` decision. Revocation committed first ⇒ no issuance.
5. **Custody.** No response carrying a key leaves the authority until the custodian has anchored the head
   that contains the decision (lease, ADR-014).
6. **Open.** Recipient fetches ciphertext, unwraps K, verifies signature, digest, context binding and AEAD.
7. **Acknowledge / verify.** Signed receipts; independent verification by Node or Rust verifier.

## 3. Required properties and where each is enforced

| Property                          | Mechanism                                                                  | Test evidence                                             |
| --------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------- |
| Endpoint confidentiality          | AEAD at endpoint; relay/authority never see K unwrapped                    | `tests/crypto.test.mjs`, mission step 18                  |
| Authenticated sender/recipient    | Device-bound signing keys; key IDs in signed context                       | `tests/crypto.test.mjs`, `authority.test.mjs`             |
| Current-policy-controlled release | Single release transaction (ADR-003), TLA+ `IssueRequiresCurrentAuthority` | `trust-before-release.test.mjs`, `formal/`                |
| Explicit suite selection          | `suiteId` in signed context and AAD; registry allow-list                   | `tests/crypto-provider.test.mjs`, `tests/pqc/`            |
| Downgrade rejection               | Unknown/disabled suite or provider fails closed; no fallback               | `tests/crypto-agility/`                                   |
| Replay resistance                 | Nonces, operation proofs, TOTP replay floor, receipt replay store          | `tests/auth-routing.test.mjs`, `verifier-replay.test.mjs` |
| Idempotency                       | Object IDs; same issuance returned on retry                                | `tests/network-failure/`, Demo 4                          |
| Offline recovery                  | Encrypted endpoint queue; fresh authentication before submission           | `apps/unit-client/vault-store.test.mjs`                   |
| Signed evidence                   | Hash-chained signed records, same transaction as state change              | `tests/authority.test.mjs`                                |
| Independent verification          | Node + Rust verifiers, frozen vectors                                      | `tests/native/`, `native/evidence-verify/tests`           |
| Rollback/fork detection           | Incremental custody (ADR-014)                                              | `tests/incremental-custody*.test.mjs`                     |

## 4. Versioning rules

- Every signed structure carries an explicit version; unknown versions, extra members or unknown suites
  fail closed. A changed encoding requires a new version and an ADR; never silently under the same version.
- Envelope schema 1/2 classical; 3 laboratory PQC (disabled unless `SIEPMU_ALLOW_PQC_LAB=1` and listed by
  crypto policy). Wrap v2 in use; HPKE base mode reserved as wrap v3 (ADR-011).
- Custody protocol 1 (full chain) and 2 (range) coexist on one anchor (ADR-014).

## 5. Known gaps (not to be claimed)

| Gap                                          | Consequence                                        | Path                                           |
| -------------------------------------------- | -------------------------------------------------- | ---------------------------------------------- |
| No forward secrecy (static recipient keys)   | Recipient key compromise exposes past wrapped keys | Prekey/epoch keys (MLS/PQXDH-style), needs ADR |
| Metadata visible (identities, sizes, timing) | Traffic analysis possible                          | Padding, batching; sponsor requirement needed  |
| No disconnected peer-to-peer delivery        | Exchange needs the authority to release            | By design (Trust Before Release)               |
| Issued key cannot be recalled                | Revocation is not retroactive                      | By design; stated in every claim               |
| No hardware key custody                      | Endpoint compromise exposes keys                   | TPM/PKCS#11 provider (`08-…`)                  |

## 6. Language-neutral contracts and vectors

Implemented: SIEPMU-CJSON-v1 (16 vectors), SIEPMU-EVIDENCE-v1 (63), SIEPMU-EVIDENCE-RANGE-v1 (25), all
generated by executing the Node reference and passed by the Rust implementation. Next contracts to freeze
(P2, in this order, because a second implementation depends on them): envelope v2 verification (recipient
side), release-receipt strict mode, custody request/lease/anchor messages (currently specified by ADR-014
and `incremental.mjs` tests only).
