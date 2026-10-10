# 03 — Public prior art and technology comparison

Method per technology: **understand** (public documentation and papers), **deconstruct** (which guarantees
are essential), **reimagine** (what SIEPMU needs instead). Only public standards, papers and permissively
licensed designs were consulted. No proprietary code was read or copied. Citations are to public documents;
where a statement depends on a specific version, the version is named.

## A. Tamper-evident logs and custody (Track A)

| System / paper                                                                                  | Core mechanism                                                     | Essential guarantee                            | Replaceable for SIEPMU                                                 |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------- | ---------------------------------------------------------------------- |
| Schneier & Kelsey, "Secure audit logs…" (1999)                                                  | Hash chain + evolving MAC keys                                     | Forward integrity after logger compromise      | Evolving keys: the threat is DB rollback, not logger compromise        |
| Crosby & Wallach, "Efficient data structures for tamper-evident logging" (USENIX Security 2009) | History tree (Merkle) with O(log n) membership/incremental proofs  | Auditor checks consistency without full log    | Proof machinery: custodian sees every record anyway                    |
| Certificate Transparency, RFC 6962 / RFC 9162                                                   | Merkle tree, signed tree heads, consistency and inclusion proofs   | Append-only, gossip-detectable split views     | Gossip; consistency proof = delta for a verifier that sees all entries |
| Trillian / Sigstore Rekor (Apache-2.0)                                                          | Verifiable log service on Merkle trees, checkpoints (signed notes) | Same as CT, general-purpose                    | A full log service is far beyond need; no runtime dependency taken     |
| Database WAL + checkpoints (SQLite, PostgreSQL)                                                 | Replay only from last durable checkpoint                           | Recovery cost bounded by work since checkpoint | Not tamper-evidence: borrowed idea is "start from last verified point" |

**Deconstruction.** The custodian's job is to prevent the authority from operating on a database state that
is older than, or diverges from, the last state the custodian saw. Essential: (1) a retained, independently
held head; (2) proof that the current head extends it; (3) binding of the authorization state at that head.
Not essential for SIEPMU's custodian: proofs that avoid sending entries (it must verify each signed decision),
gossip (one custodian per authority), forward-secure MACs (signing key compromise is a separate threat).

**Reimagined (ADR-014).** Linear chain + retained anchor + range verification + state-digest binding + lease.
The minimal consistency proof for a verifier that already holds the head and must see every new record is the
delta itself. Merkle trees are kept as a candidate for a different consumer: endpoint verification of a single
release receipt's inclusion without exporting the chain.

## B. Data management (Track B)

| System                       | Essential principle borrowed                                     | Not borrowed / why                                                             |
| ---------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| SQLite                       | Single-writer serialisable transactions; WAL; `synchronous=FULL` | Already used; replacing it would discard tested atomicity                      |
| PostgreSQL                   | MVCC, replication, PITR                                          | Multi-node needs a re-proof of release/revocation linearisability (TLA+ first) |
| Append-only / event journals | Immutable records, replay                                        | Already the evidence chain; not a general state store                          |
| Object storage               | Content-addressed immutable blobs                                | Relay ciphertext store could become content-addressed (P2)                     |

See `05-STORAGE_ARCHITECTURE.md`. Decision: no new database engine.

## C. Secure exchange (Track C)

| Design                              | Borrowed principle                               | Difference in SIEPMU                                                                            |
| ----------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| HPKE (RFC 9180)                     | KEM-based single-shot encryption to a public key | Reserved as wrap v3 (ADR-011); wrap v2 in use                                                   |
| MLS (RFC 9420)                      | Group key schedule, epochs, forward secrecy      | Not adopted: SIEPMU's release gate is authority policy, not group membership; FS gap documented |
| Signal (X3DH/PQXDH, Double Ratchet) | Asynchronous FS via prekeys                      | Same: FS requires prekey infrastructure; open gap (L-2)                                         |
| S/MIME, OpenPGP                     | Signed + encrypted envelope, offline transfer    | SIEPMU adds release-time authority check and evidence                                           |
| Store-and-forward MTAs, AMQP        | Idempotent delivery, retries, acknowledgements   | Idempotency keys and acknowledgements already in protocol                                       |

**Distinguishing composition (not a novelty claim):** ciphertext moves freely; the recipient-wrapped content
key is released only inside a transaction that re-validates current policy, and the decision is a signed,
hash-chained evidence record whose head is independently custodied. Public prior art exists for each part
(envelope encryption, key escrow with policy, transparency logs); professional review must decide whether the
composition is novel (`IP_AND_ORIGINALITY.md`).

## D. Indigenous cryptographic infrastructure (Track D)

Public, verifiable starting points only. The repository records sponsor questions rather than assuming
interfaces (`research/trl56/16-iaf-clarification-register.md`, `04-sag-crypto-integration-pathway.md`).

| Item                 | What is publicly established                                | Implication                                                 |
| -------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- |
| SAG (DRDO) grading   | Grading is SAG's remit, not the applicant's                 | Only SAG/sponsor can supply graded algorithms/modules       |
| PKCS#11 v3.1 (OASIS) | Standard token/HSM API                                      | Natural provider boundary for Indian HSMs                   |
| TPM 2.0 (TCG)        | Standard platform key storage and attestation               | Endpoint key custody, measured boot                         |
| C-DAC, C-DOT         | Public work on secure systems and Indian-developed products | Candidate providers; interfaces to be obtained, not assumed |

## E. Air-gapped operation (Track E)

Principles from public guidance on offline enclaves (signed offline updates, one-way transfer, media
sanitisation) are applied in `07-AIR_GAP_ARCHITECTURE.md`. No classified-boundary mechanism is implemented
or assumed.

## F. Systems software (Track F) — language choice evidence

ADR-012 measured the Rust verifier against Node: 1.6–5.7× lower peak RSS, 0.54–0.89× Node speed (pure-Rust
P-256 verification is about 2× slower than OpenSSL). Rust therefore adds **independence and memory safety**,
not speed, for this workload. The range verifier added on this branch follows the same rule: accepted only
by conformance with vectors generated from the Node reference.
