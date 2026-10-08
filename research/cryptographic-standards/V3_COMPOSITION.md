# Schema-v3 laboratory composition: specification for independent review

Status: **laboratory composition, unreviewed.** This document states exactly what the code does so
an independent assessor can analyse it. It does not claim the composition is secure. Review gate:
[INDEPENDENT_REVIEW.md](INDEPENDENT_REVIEW.md). Decision record: ADR-010, ADR-011.

Source of truth (any disagreement with this text is a defect in this text):

| Step                                 | File                                                                    |
| ------------------------------------ | ----------------------------------------------------------------------- |
| Endpoint seal / open                 | `packages/pqc-lab/envelope.mjs`                                         |
| KEM → HKDF → AES-GCM key wrap        | `packages/crypto-provider/engine.mjs` (`wrapKey`, `unwrapKey`)          |
| Wrap key derivation                  | `packages/crypto-provider/primitives.mjs` (`deriveWrapKey`)             |
| Authority structural + policy checks | `services/crypto-policy/registry.mjs` (`validatePqcEnvelope`, `reason`) |
| Suite identifiers and encoded sizes  | `packages/crypto-provider/pqc-identifiers.mjs`                          |
| Canonical encoding (SIEPMU-CJSON-v1) | `packages/protocol/canonical.mjs`                                       |

## 1. Notation and encoding

- `C(x)`: SIEPMU-CJSON-v1 of `x`, UTF-8. Object members sorted by UTF-16 code unit order, no
  whitespace, strings by `JSON.stringify`, numbers restricted to safe integers (no floats, no
  `-0`), plain objects only, depth ≤ 64. This is a project encoding, **not** RFC 8785 (JCS).
  For the ASCII-only member names and values used here it coincides with sorted-key compact JSON.
- `H(x)`: SHA-256, lowercase hex. `b64u`: base64url without padding, canonical (re-encoding must
  reproduce the input).
- `HKDF`: HKDF-SHA256 (RFC 5869), output 32 bytes. `AEAD`: AES-256-GCM, 12-byte nonce from the
  platform CSPRNG, 16-byte tag (WebCrypto `AES-GCM`, `tagLength: 128`).

## 2. Suites

| Suite ID                               | Provider ID            | KEM                        | `enc` bytes | `pk` bytes | Signature |
| -------------------------------------- | ---------------------- | -------------------------- | ----------- | ---------- | --------- |
| `ML-KEM-768-ML-DSA-65-AES-256-GCM-v1`  | `node-openssl-pqc-lab` | ML-KEM-768 (FIPS 203)      | 1088        | 1184       | ML-DSA-65 |
| `ML-KEM-1024-ML-DSA-65-AES-256-GCM-v1` | `node-openssl-pqc-lab` | ML-KEM-1024 (FIPS 203)     | 1568        | 1568       | ML-DSA-65 |
| `X-WING-ML-DSA-65-AES-256-GCM-v1`      | `noble-xwing-lab`      | X-Wing (ML-KEM-768+X25519) | 1120        | 1216       | ML-DSA-65 |

ML-DSA-65 (FIPS 204): public key 1952 bytes, signature 3309 bytes, pure mode, empty context
string (`crypto.sign(null, data, key)` with no context option), always via Node 24 / OpenSSL 3.5,
including in the X-Wing suite. ML-KEM uses Node 24 / OpenSSL 3.5; the X-Wing KEM uses
`@noble/post-quantum` 0.7.1 (`ml_kem768_x25519`, unaudited JavaScript, no constant-time claim). The KEM shared secret is
32 bytes for all three. Sizes match the HPKE-PQ and X-Wing IANA tables (see
[HPKE_PQ_EVALUATION.md](HPKE_PQ_EVALUATION.md)).

## 3. Keys and identifiers

Each endpoint device generates, inside its own `CryptoEngine`, one ML-DSA-65 signing key and one
KEM decapsulation key for the selected suite. Only the public descriptor leaves the endpoint:

```text
descriptor = {keyId, providerId, suiteId, purpose ∈ {sign, encapsulate},
              publicKey: {algorithm, format: "raw-public", bytes: b64u}}
keyId      = H(C(descriptor without keyId))
```

The device registers the descriptor with a signed operation proof (`crypto-key:register`); it is
`pending` until an administrator activates it. Status changes advance the global policy epoch.
The authority checks length and (for ML-KEM / ML-DSA) parses the key with OpenSSL; it does **not**
parse X-Wing public keys beyond length (open item R5).

## 4. Seal (sender endpoint)

Inputs: validated v3 context `ctx` (exact member set; see `validateProviderContext`), payload,
recipient `encapsulate` descriptor, sender `sign` descriptor, P-256 identity signing key.

1. Bind descriptors: sender `keyId = ctx.senderCryptoKeyId`, recipient `keyId = ctx.recipientKeyId`,
   both with `providerId = ctx.providerId`, `suiteId = ctx.cryptoSuite`, correct purpose.
2. `CEK ← 32 random bytes`.
3. `ct ← AEAD(CEK, nonce_c, pt = C(payload), aad = C({domain: "SIEPMU_PROVIDER_CONTENT_AAD_V3", context: ctx}))`;
   `|ct| ≤ 1 MiB + 16`.
4. `ciphertextHash ← H(ct)`; `wctx ← ctx ∪ {ciphertextHash}`.
5. Wrap (engine, wrap schema 2):
   - `(ss, enc) ← KEM.Encap(pk_R)`; `salt ← 32 random bytes`.
   - `info ← C({domain: "SIEPMU_PROVIDER_KEY_WRAP_V2", providerId, suiteId, recipientKeyId, contextDigest: H(C(wctx))})`.
   - `KEK ← HKDF(ikm = ss, salt, info, L = 32)`.
   - `meta ← {schemaVersion: 2, providerId, suiteId, recipientKeyId, encapsulation: {algorithm, ciphertext: b64u(enc)}, salt: b64u(salt)}`.
   - `wrapped ← meta ∪ AEAD(KEK, nonce_w, pt = CEK, aad = C({domain: "SIEPMU_PROVIDER_KEY_WRAP_AAD_V2", context: wctx, packet: meta}))`.
6. `unsigned ← ctx ∪ {ciphertextHash, nonce: nonce_c, wrappedKey: wrapped}`.
7. `providerSignature ← ML-DSA-65.Sign(sk_S, C(unsigned))`.
8. `envelope ← unsigned ∪ {providerSignature}`; `signature ← ECDSA-P256-SHA256(identity, C(envelope))`.
9. `CEK`, `ss`, `KEK` buffers are zeroed in `finally` blocks (best effort in a GC runtime).

Submission is `{envelope, signature, ciphertext}`. The relay stores `ct`; the authority stores the
envelope (including the opaque `wrappedKey`) and never holds a decapsulation key.

## 5. Authority checks (no secret material)

At submission (`creation = true`) and again inside the release transaction (`creation = false`):

- Structural: exact wrap member set; wrap fields equal envelope fields; `encapsulation.algorithm`
  matches the suite; exact `enc`, salt (32), nonce (12) and wrapped-CEK (48) lengths;
  `providerSignature` exactly 3309 bytes.
- Policy: suite listed in `newSuites` (creation) or `newSuites ∪ legacySuites` (release); creation
  requires `suitePolicyRevision` equal to the current revision; release refuses a revision newer
  than the current one; `SIEPMU_ALLOW_PQC_LAB=1` required.
- Keys: both key IDs registered, bound to the envelope's sender/recipient device, correct purpose,
  provider and suite; `revoked` refuses; `active`, or `retired` only at release under a legacy suite.
- Signatures: P-256 identity signature over `C(envelope)`; ML-DSA-65 over
  `C(envelope without providerSignature)` with the **registered** sender key.
- The same transaction re-checks users, devices, roles, duty, mission policy, grant expiry, epoch
  and FLASH approval, and writes signed evidence carrying `details.crypto` (provider, suite, key
  IDs, creation/current policy revision, policy digest).

## 6. Open (recipient endpoint)

Validate `ctx`; optional expected-suite pin; verify the identity signature; check the sender
descriptor returned by the claim against `ctx.senderCryptoKeyId`, provider and suite; verify
ML-DSA-65; check `|ct|` and `H(ct) = ciphertextHash`; check `wrappedKey.recipientKeyId`; unwrap
(re-derive `wctx`, decapsulate, HKDF, AEAD-open with the same AAD); AEAD-open content; parse and
validate the payload. Any failure throws; no partial output.

## 7. Properties the construction is intended to provide (claims for the assessor to test)

| ID  | Intended property                                                                                      | Mechanism                                                                                   |
| --- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| P1  | Confidentiality of `pt` against relay/authority and network, assuming KEM IND-CCA and AES-GCM security | KEM-DEM; CEK and KEK single-use (fresh CEK, fresh `enc`, fresh salt per object)             |
| P2  | Wrapped CEK usable only for this object, suite, recipient key and ciphertext                           | `info` binds provider, suite, recipient key ID, `H(C(wctx))`; AAD repeats `wctx` and `meta` |
| P3  | No suite/provider substitution or downgrade by an on-path party                                        | Suite in signed envelope, in `info` and AAD; policy re-check at release; recipient pin      |
| P4  | Sender authentication requires both classical and PQ signatures (conjunction)                          | ECDSA over the full envelope including the ML-DSA signature                                 |
| P5  | Recipient key substitution is detected                                                                 | Recipient key ID signed, registered to a device, bound in `info`                            |
| P6  | Release reflects current authority policy, not policy at creation                                      | `reason(e, false)` inside the release transaction                                           |

## 8. Questions for the assessor (not answered here)

- **R1** HKDF `info` binds the context by digest, and the `enc` bytes only through AES-GCM AAD,
  not through the KDF. HPKE also leaves `enc` out of its key schedule for these KEMs and relies on
  ML-KEM / X-Wing ciphertext binding (LEAK-BIND-K-CT). Is the AAD binding sufficient here?
- **R2** Random 32-byte HKDF salt instead of HPKE's fixed key schedule: any weakness or benefit?
- **R3** Random 96-bit GCM nonces under single-use keys: confirm no nonce-reuse exposure.
- **R4** SIEPMU-CJSON-v1 is not RFC 8785; confirm injectivity for the value space admitted by
  the validators (strings, safe integers, nested plain objects).
- **R5** X-Wing public keys are length-checked only at the authority; the ML-KEM encapsulation key
  check happens at the sender endpoint inside the upstream implementation. Acceptable?
- **R6** ML-DSA pure mode, empty context string; message is the canonical envelope (up to a few
  KiB). Should the signature use the FIPS 204 context string for domain separation instead of
  relying on the envelope's structure?
- **R7** Whether the composition should be replaced by HPKE base mode (ADR-011).

## 9. Reproducible evidence on this branch

| Evidence                                                      | What it shows                                                                                                                                                                                                                                 |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/crypto-agility/wrap-derivation.test.mjs`               | Pinned v2 derivation vector (below); every bound member changes the key; > 1024-byte contexts work; malformed inputs refused                                                                                                                  |
| `tests/pqc/end-to-end.test.mjs`                               | Full v3 path through the authority (ML-KEM-768): exact bytes, provenance verified, gate closed, key revocation, classical downgrade, suite substitution, ML-DSA forgery with valid identity signature, wrong-recipient decrypt, tamper, FLASH |
| `packages/pqc-lab/laboratory.check.mjs`                       | NIST ML-KEM / ML-DSA vectors, X-Wing author vectors, Node↔Noble ML-KEM interop, X-Wing end-to-end                                                                                                                                            |
| `tests/crypto-agility/providers.test.mjs`                     | Wrap metadata authentication, lifecycle, fail-closed provider failure                                                                                                                                                                         |
| `apps/verifier/verify.mjs` (exercised by the end-to-end test) | Independent verifier requires crypto provenance exactly for v3 release evidence                                                                                                                                                               |

### Wrap derivation v2 vector

Inputs: `ss = 00 01 … 1f`, `salt = 20 21 … 3f`, `providerId = node-openssl-pqc-lab`,
`suiteId = ML-KEM-768-ML-DSA-65-AES-256-GCM-v1`, `recipientKeyId = "11"×32`,
`wctx = {objectId: "00000000-0000-4000-8000-000000000001", ciphertextHash: "22"×32, schemaVersion: 3}`.

```text
H(C(wctx)) = f9c669dc03db1b3c6cd3b5df0df21612a1efc8bab92cd2d7247b6f526e717ff5
KEK        = f41e8d6a5e96601baa5a8f7becb4bd3a22c883d7b3caee412532ea5f0f25c985
```

Independent reproduction (Python standard library only, 2026-10-08, matched all three values):

```python
import hashlib, hmac, json
cj = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
ctx = {"objectId": "00000000-0000-4000-8000-000000000001", "ciphertextHash": "22" * 32, "schemaVersion": 3}
info = cj({"domain": "SIEPMU_PROVIDER_KEY_WRAP_V2", "providerId": "node-openssl-pqc-lab",
           "suiteId": "ML-KEM-768-ML-DSA-65-AES-256-GCM-v1", "recipientKeyId": "11" * 32,
           "contextDigest": hashlib.sha256(cj(ctx).encode()).hexdigest()})
prk = hmac.new(bytes(range(32, 64)), bytes(range(32)), hashlib.sha256).digest()
print(hmac.new(prk, info.encode() + b"\x01", hashlib.sha256).hexdigest())
```

This is a regression vector for the project's own composition. It is not a conformance vector
for any standard and does not establish security.
