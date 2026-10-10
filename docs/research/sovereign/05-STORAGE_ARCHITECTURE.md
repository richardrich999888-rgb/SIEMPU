# 05 — Storage architecture specification (Track B)

Status: **specification only.** No code on this branch implements the ports below except where an existing
module is named. Decision: **keep SQLite** for the authority until a replacement proves equivalent
transactional release/revocation semantics (TLA+ model plus the negative tests). Building a general-purpose
database engine is out of scope and would be a credibility risk, not an asset.

## 1. Why the current design is correct for one authority host

The release invariant (ADR-003) needs: revocation and issuance serialise; the decision evidence commits in the
same transaction as the state change. SQLite `BEGIN IMMEDIATE` gives a single serial order on one host, WAL
gives durability with `synchronous=FULL`, and the custodian anchor (ADR-014) detects rollback of the file.
Moving to a multi-node store breaks the single-writer argument; it needs a linearisable commit (e.g. a
consensus log) and a re-proof, not a driver swap.

## 2. Seven storage domains, separated by trust and lifetime

| #   | Domain                        | Writer       | Confidentiality                  | Integrity mechanism                        | Retention / deletion                                             | Today                       |
| --- | ----------------------------- | ------------ | -------------------------------- | ------------------------------------------ | ---------------------------------------------------------------- | --------------------------- |
| 1   | Authorization state           | Authority tx | Metadata (identities, roles)     | Same tx as evidence; custody state digest  | Current state; history via evidence                              | `control.sqlite`            |
| 2   | Identity and device records   | Authority tx | Secrets encrypted (TOTP seeds)   | Same as 1                                  | Revocation is a state change, never delete                       | `control.sqlite`            |
| 3   | Encrypted information objects | Relay        | Ciphertext only                  | AEAD at endpoint; digest bound in evidence | Operator policy; deletion by digest                              | Relay ciphertext DB         |
| 4   | Key-release metadata          | Authority tx | Opaque wrapped keys              | Release tx + evidence                      | Wrapped key purged after release/expiry (gap: not yet automated) | `control.sqlite`            |
| 5   | Signed audit evidence         | Authority tx | Metadata                         | Hash chain, signatures, custody anchor     | Append-only; archive by checkpoint range                         | `control.sqlite` `evidence` |
| 6   | Security telemetry            | Collector    | Redacted metadata                | Signed batches                             | Rolling window                                                   | Collector DB                |
| 7   | Offline endpoint data         | Endpoint     | Encrypted vault (PBKDF2+AES-GCM) | AEAD, parameters bound as AAD              | Device lifetime; wipe on revoke (endpoint-trusted)               | Browser IndexedDB vault     |

Separation rule: no domain may hold plaintext or recipient private keys except 7, and 7 lives only at the
endpoint.

## 3. Ports (vendor-neutral contracts)

Each port is a narrow interface the core calls; adapters implement it per backend. Core logic never imports a
driver. Proposed signatures (TypeScript-style, synchronous where the backend transaction must stay
synchronous to keep the single-writer argument):

```ts
interface AuthorityStore {
  // domains 1, 2, 4, 5 — one transactional unit
  transact<T>(fn: (tx: AuthorityTx) => T): T; // serialisable; throws => rollback
}
interface AuthorityTx {
  epoch(): Epoch;
  user(id: UserId): User | null;
  device(id: DeviceId): Device | null;
  policy(from: Unit, to: Unit, mission: MissionId): Policy | null;
  appendEvidence(payload: EvidencePayload): SignedRecord; // sequence/previousHash assigned here
  evidenceRange(after: Seq, until: Seq): SignedRecord[]; // O(until - after)
  head(): { sequence: Seq; headHash: Hex64 };
  issue(objectId: ObjectId, recipient: DeviceId): WrappedKey; // only inside a release decision
}
interface CiphertextStore {
  // domain 3 — no transaction shared with the authority
  put(digest: Hex64, bytes: Uint8Array): void;
  get(digest: Hex64): Uint8Array | null;
  delete(digest: Hex64): void;
}
interface AnchorStore {
  // custodian — independent host, independent key
  compareAndSet(expected: Anchor | null, next: Anchor): void; // atomic
  current(): Anchor | null;
}
interface TelemetryStore {
  appendBatch(signed: SignedBatch): void;
  window(from: Time): SignedBatch[];
}
```

`AnchorStore.compareAndSet` is exactly what `CheckpointCustodian.#anchor` does today inside
`BEGIN IMMEDIATE`; `evidenceRange` is `authorityRange` in `services/evidence/custody.mjs`.

## 4. Backend options (decision rules, not a shopping list)

| Domain     | Default          | Acceptable alternative                                                  | Gate before switching                                  |
| ---------- | ---------------- | ----------------------------------------------------------------------- | ------------------------------------------------------ |
| 1, 2, 4, 5 | SQLite (bundled) | PostgreSQL single primary, `SERIALIZABLE`                               | All authority/custody negative tests + TLA+ refinement |
| 3          | SQLite           | Filesystem or S3-compatible self-hosted object store, content-addressed | Relay tests; digest verification on read               |
| Anchor     | SQLite           | Hardware-backed monotonic counter (TPM NV) + signed anchor              | ADR; rollback test with counter                        |
| 6          | SQLite           | Any append store                                                        | Monitoring tests                                       |

## 5. Backup, restore and rollback

Encrypted backup/restore exists (`scripts/backup.mjs`, `tests/recovery.test.mjs`). A restored authority is
**quarantined** until the custodian confirms its head extends the anchor; a restore to an older state is
rejected (rollback). Operational procedure for a legitimate restore-to-older-state (disaster recovery) needs
an explicit, dual-controlled anchor reset with signed evidence. **Not implemented**; listed as a gap.

## 6. Prototype work justified next (P2)

1. Extract `AuthorityStore`/`AnchorStore` ports in code without changing the backend (pure refactor,
   measured by the existing tests).
2. Content-addressed ciphertext store (domain 3) — small, isolated, improves deduplication and integrity
   checks on read.
3. Archive evidence by checkpoint range (domain 5 growth) — possible now that custody no longer needs history.
