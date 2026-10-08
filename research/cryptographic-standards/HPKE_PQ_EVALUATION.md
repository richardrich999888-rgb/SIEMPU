# HPKE with post-quantum KEMs as the standards-track alternative to wrap v2

Retrieved 2026-10-08. `ietf.org`, `datatracker.ietf.org` and `rfc-editor.org` are blocked by the
build environment's network policy, so the published draft revisions were **not** read here. The
facts below come from the authors' source repositories at the stated commits. Re-check against the
published revision before citing them externally.

| Source                                                               | Commit / date                         | Status as stated in source                                |
| -------------------------------------------------------------------- | ------------------------------------- | --------------------------------------------------------- |
| `github.com/hpkewg/hpke-pq`, `draft-ietf-hpke-pq.md` (editor's copy) | `6433c8fce0b8`, 2026-07-06            | IETF HPKE WG, category `std`; Barnes, Connolly            |
| `github.com/dconnolly/draft-connolly-cfrg-xwing-kem` (editor's copy) | `984c2f7a93b8`, date field 2026-09-23 | IRTF CFRG, category `info`; Connolly, Schwabe, Westerbaan |

## Verified facts

HPKE-PQ (editor's copy):

- KEM IDs: ML-KEM-512 `0x0040`, ML-KEM-768 `0x0041`, ML-KEM-1024 `0x0042` (Nsecret 32, Nsk 64;
  Nenc/Npk 1088/1184 and 1568/1568 for 768/1024); hybrids MLKEM768-P256 `0x0050`,
  MLKEM1024-P384 `0x0051`, MLKEM768-X25519 `0x647a` (Nenc 1120, Npk 1216, Nsk 32).
- Hybrids are defined by reference to `I-D.irtf-cfrg-concrete-hybrid-kems` and
  `I-D.irtf-cfrg-hybrid-kems`; the base protocol reference is `I-D.ietf-hpke-hpke`.
- Adds single-stage SHA-3 KDFs: SHAKE128 `0x0010`, SHAKE256 `0x0011`, TurboSHAKE128 `0x0012`,
  TurboSHAKE256 `0x0013`.
- None of these KEMs supports `AuthEncap`/`AuthDecap`; the draft points to PSK mode or digital
  signatures instead.
- Security considerations: IND-CCA2 for HPKE follows from an IND-CCA KEM; ML-KEM and the hybrids
  provide LEAK-BIND-K-PK and LEAK-BIND-K-CT.
- The repository contains a Rust reference implementation and 13 test-vector suites as
  (KEM, KDF, AEAD): `(0x0010,0x0010,0x0001)`, `(0x0011,0x0011,0x0002)`, `(0x0020,0x0012,0x0003)`,
  `(0x0021,0x0013,0x0003)`, `(0x0040,0x0001,0x0001)`, `(0x0041,0x0001,0x0001)`,
  `(0x0042,0x0002,0x0002)`, `(0x0042,0x0013,0x0001)`, `(0x0050,0x0001,0x0001)`,
  `(0x0050,0x0010,0x0002)`, `(0x0051,0x0002,0x0002)`, `(0x647a,0x0001,0x0003)`,
  `(0x647a,0x0011,0x0003)`. None is the exact (KEM, HKDF-SHA256 `0x0001`, AES-256-GCM `0x0002`)
  combination proposed below, so vectors for that combination would have to be generated with the
  reference implementation and cross-checked.

X-Wing (editor's copy):

- Sizes: decapsulation key 32, encapsulation key 1216, ciphertext 1120, shared secret 32 bytes.
- Combiner: `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`, `XWingLabel = 5c2e2f2f5e5c`.
- Defines HPKE use (`DeriveKeyPair` via SHAKE256; not an authenticated KEM) and requests HPKE KEM
  ID `0x647a`, the same codepoint HPKE-PQ assigns to MLKEM768-X25519.
- **Correction to an earlier search summary.** The sentence "should not be used outside of TLS"
  in the X-Wing draft refers to the different KEM `X25519Kyber768Draft00`, which assumes a TLS
  transcript. X-Wing itself is described as general-purpose and "usable outside of HPKE".

## Mapping wrap v2 onto HPKE base mode

| Wrap v2 (ADR-010)                                          | HPKE base mode, single-shot `Seal`                                                                         |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `KEM.Encap(pk_R)` → `ss`, `enc`                            | Same KEM operation; KEM ID `0x0041` / `0x0042` / `0x647a`                                                  |
| HKDF-SHA256, random 32-byte salt, project `info`           | Fixed `LabeledExtract`/`LabeledExpand` key schedule; `suite_id` binds KEM/KDF/AEAD IDs; application `info` |
| `info` binds provider, suite, recipient key ID, `H(wctx)`  | Application `info` = `C({providerId, suiteId, recipientKeyId, contextDigest})` (proposed)                  |
| AES-256-GCM, random nonce, AAD = `C({domain, wctx, meta})` | AEAD `0x0002` (AES-256-GCM), nonce from key schedule, `aad` = same canonical bytes (proposed)              |
| `enc` authenticated through AAD                            | `enc` not in the key schedule for these KEMs; relies on KEM ciphertext binding                             |
| Sender authentication by ML-DSA-65 + P-256 signatures      | Unchanged: these KEMs have no Auth mode; the draft recommends signatures                                   |

The application-level bindings (P2–P6 in [V3_COMPOSITION.md](V3_COMPOSITION.md)) carry over
unchanged. HPKE would replace only the project's own key schedule with a standardised one that has
published test vectors and security analysis.

## Implementation options checked (npm registry, 2026-10-08)

| Package                  | Latest | Published  | Licence | Runtime dependencies                                              |
| ------------------------ | ------ | ---------- | ------- | ----------------------------------------------------------------- |
| `@hpke/core`             | 1.9.0  | 2026-03-08 | MIT     | `@hpke/common`                                                    |
| `@hpke/ml-kem`           | 0.3.0  | 2026-03-08 | MIT     | `@hpke/common`, `mlkem`                                           |
| `@hpke/hybridkem-x-wing` | 0.7.0  | 2026-03-08 | MIT     | `@hpke/common`, `@hpke/dhkem-x25519`, `mlkem`                     |
| `@noble/post-quantum`    | 0.7.1  | 2026-08-27 | MIT     | `@noble/curves`, `@noble/hashes`, `@noble/ciphers` (pinned 2.4.0) |

All `@hpke/*` releases predate the 2026-07-06 editor's copy; conformance to the current codepoints
and `Nsk` values is unverified. Node 24 exposes `crypto.encapsulate`/`decapsulate` for ML-KEM but
no HPKE API. A dependency would add a second ML-KEM implementation (`mlkem`) beside OpenSSL.

## Recommendation

Do **not** switch now. Plan wrap schema 3 = HPKE base mode as above, gated on: (a) the published
HPKE-PQ revision's codepoints matching this record; (b) an implementation that passes the
`hpke-pq` test vectors for the three KEM IDs used here, in the endpoint runtime, without a second
unaudited ML-KEM implementation; (c) independent review confirming the mapping. Until then wrap v2
stays a laboratory-only composition. Rationale and gates: ADR-011.
