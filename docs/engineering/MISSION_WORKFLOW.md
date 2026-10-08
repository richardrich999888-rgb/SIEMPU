# SIEPMU Core Mission Workflow — executable acceptance scenario

Script: `scripts/mission-workflow.mjs` (`npm run build:native && npm run test:mission`).
Output: `artifacts/mission-workflow/report.json`, `report.md`. CI: job `rust-native`, artefact
`rust-native-evidence`. All identities and content are synthetic.

The scenario runs the 18 steps of the continuation directive (§9) on the real five-process secure
stack (TLS 1.3 gateway, control authority, ciphertext relay, checkpoint custodian, telemetry
collector; mTLS between services), once per cryptographic profile:

- `classical`: schema v2 objects (mission priority and domain labels) sealed and opened by the
  browser endpoint module `packages/crypto` (WebCrypto P-256 ECDH, AES-256-GCM); PQC lab gate closed.
- `pqc-lab`: schema v3 objects using the laboratory ML-KEM-768 + ML-DSA-65 composition; lab gate
  opened for that run only.

Select one profile with `SIEPMU_MISSION_PROFILES=classical` (or `pqc-lab`).

## Steps

|   # | Step                       | Establishes                                                                                                                                                                                                | Does not establish                                   |
| --: | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
|   1 | Provision and start stack  | Synthetic units, users, devices; five separate processes                                                                                                                                                   | Separate hosts                                       |
|   2 | Enrol endpoint             | Admin creation, device enrolment with signed challenge, approval                                                                                                                                           | Identity proofing                                    |
|   3 | Authenticate               | Password + TOTP + device-key challenge for Units A, B, C; endpoint keys generated locally                                                                                                                  | Hardware authenticators                              |
|   4 | Apply policy               | A→B mission edge set; epoch advances on change                                                                                                                                                             | Sponsor policy content                               |
|   5 | Create objects             | Text and 64 KiB file encrypted at the sender endpoint                                                                                                                                                      | Large-file streaming                                 |
|   6 | Submit over TLS            | Gateway submission; Unit C gets 404; Unit B decrypts exact text and file                                                                                                                                   | —                                                    |
|   7 | Interruption               | Fault proxy cuts Unit A; objects sealed with a cached grant; submission fails                                                                                                                              | Radio/WAN behaviour                                  |
|   8 | Change authorisation       | Recipient revoked while sender offline; epoch advances                                                                                                                                                     | —                                                    |
|   9 | Restore connectivity       | Queued objects submitted                                                                                                                                                                                   | —                                                    |
|  10 | Revalidate                 | Revoked recipient's object HELD `USER_REVOKED`; eligible one READY                                                                                                                                         | —                                                    |
|  11 | Deny stale release         | Revoked user refused (`401 USER_REVOKED`); stale expected epoch fenced (`409 EPOCH_MISMATCH`, no key material)                                                                                             | Recall of earlier issuance                           |
|  12 | Legitimate delivery        | Second recipient obtains release at current epoch                                                                                                                                                          | —                                                    |
|  13 | Exact-byte decryption      | Bytes, name and media type match                                                                                                                                                                           | —                                                    |
|  14 | Signed decisions           | HELD and RELEASED decisions verify; altered decision fails; re-signed metadata tampering refused                                                                                                           | —                                                    |
|  15 | Independent verification   | Strict receipt + replay rejection; chain with saved checkpoint; Node and Rust verifiers byte-identical                                                                                                     | Custody on separate infrastructure                   |
|  16 | Snapshot restore           | Pre-revocation DB restored → `503 RECOVERY_QUARANTINED` for every request, including the revoked user; reinstating current state resumes with the same single issuance                                     | Operator procedure for choosing the correct snapshot |
|  17 | Signed update              | Offline bundle installs; installed runtime verifies evidence; wrong key, rollback and same-size tamper rejected                                                                                            | OS image integrity, secure boot                      |
|  18 | Monitoring confidentiality | Collector and relay stores free of plaintext, private keys, TOTP secrets, passwords, tokens (and the classical wrapped key); control free of plaintext; positive controls prove the scan reads live stores | Side channels, logs outside these stores             |

## Defect found by this workflow

Step 18's positive control (`RELEASE_ISSUED` must reach the collector) failed on both profiles.
Root cause: `redactSecurityEvents` stamped alert events with the epoch current **at export time**,
so after any alert followed by any epoch change the same `eventId` arrived with a new digest and the
collector rejected every later batch (`TELEMETRY_CONFLICT`). Monitoring silently stayed degraded.
Fixed by recording the epoch with each alert (`database/migrations/006-alert-epoch.sql`, legacy
rows backfilled once) and exporting the stored value; regression tests in `tests/monitoring.test.mjs`.

## Recorded local result

Commit with this document, Node 24.21.0, 4-vCPU Linux container: both profiles 18/18 PASS, about
20 s for both. Hosted results per SHA: `docs/engineering/CURRENT_STATE.md`.

## Interpretation limits

One host; all zones share a kernel and clock; fault injection is a userspace proxy. Software keys
only. The PQC profile is a laboratory composition without independent review. This is engineering
evidence, not a relevant-environment trial, independent assessment, SAG grading or TRL decision.
