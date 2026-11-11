# P0 044 bounded control/relay recovery

Branch `codex/p0-044-recovery-bounds`, based on PR #43 at
`07ab59762f5a086152835709ea5df60d07890e74`. Synthetic applicant laboratory work.

## Reproduced defect and correction

The previous restore authenticated the six archive files and checked control evidence,
checkpoint ancestry and the authorization seal, but did not inspect the relay snapshot.
Six negative cases published a destination: missing referenced ciphertext, altered bytes,
false stored length, malformed blob digest, missing relay table and altered control object
binding. A complete snapshot remained decryptable by its synthetic recipient. The original
four recovery tests passed; these results do not establish full disaster recovery.

Restore now opens staged relay state read-only with trusted schema disabled, checks SQLite
structure and the required tables, verifies each blob's type/size/time/hash and checks all
stored objects with the existing envelope-integrity validator. Every stored object must
have a matching blob. No repaired or reconstructed data is signed or published. Exceptions
remove staging and leave the destination unpublished. Existing checkpoint, authorization-seal
and key checks remain mandatory. The check does not authorize a release.

Intact unreferenced blobs are preserved: upload precedes the control transaction, so an
interrupted submission can leave one legitimately. This is not a retention/deletion policy.
Archives with objects whose current stored signing key no longer verifies their envelope are
conservatively rejected, as the runtime also requires stored-object integrity.

## Resource boundary and compatibility

The whole-archive JSON format now supports at most **64 MiB encrypted input**, **32 MiB total
decoded files** and **16 KiB per credential/metadata file**. These are implementation limits,
not service capacity or IAF acceptance criteria. Same-descriptor regular-file reads reject
symlinks, special files, oversize input and observed modification. Buffer inputs receive the
same archive cap. Decoded lengths are checked before base64 allocation; creation applies the
same decoded/metadata limits and fails before writing an archive when they are exceeded.

Existing larger archives are deliberately unsupported by this reader. Preserve them and use
a separately reviewed streaming migration/recovery design; never truncate files or prune
policy/evidence to obtain a pass. Temporary SQLite snapshot disk usage still needs operator
quotas. Multiple parsing/crypto copies mean peak RSS is greater than the input limit.

## Reproduction and source binding

```sh
node --test --test-concurrency=1 tests/recovery.test.mjs tests/recovery-stores.test.mjs tests/legacy-migration.test.mjs
node assurance/bench/recovery-growth.mjs /new/path/recovery-growth.json
npm run validate
npm run test:e2e
npm run test:adversarial -- artifacts/p0-044-adversarial
```

The growth drill runs 0, 20 and 60 synthetic 4 KiB objects, authenticates/submits through the
existing API, stops writes, backs up/restores, and decrypts every restored object at the
recipient fixture. It records raw submission latency, backup/restore duration, CPU, peak RSS,
archive/database sizes and exact clean commit/tree/fingerprint. It is excluded from deployed
application/offline bundles with other assurance tools. Generated results are authoritative;
do not copy predecessor counts to a changed revision.

Retain initial fixture failures (incorrect grant/decryption helper use), the baseline's six
actual missing-rejection failures, and a subsequent missing test-import failure. Those harness
mistakes were corrected without weakening the six negative assertions.

## Remaining requirements

This is a maintenance restore of control/relay state. Checkpoint custodians, writer credentials,
monitoring, endpoint outboxes, HSM/token state, deployment PKI and third-party identity state
are not restored. Services must stay stopped during sequential snapshots. No new startup,
failover, activation or production interface is enabled. Independently current policy/custody
must be reconciled before service restart. A local rename does not establish power-loss
durability; physical crash testing, all-store RPO/RTO and separate administration remain open.
All 19 qualification gaps remain open or partial; IAF-G08/G10 gain laboratory evidence only.
Provisional internal TRL 4 is unchanged.

SAG grading is not established.

TRL 5 qualification and IAF operational approval are not established.

Technical references reviewed 11 November 2026: SQLite PRAGMA documentation
(https://www.sqlite.org/pragma.html) distinguishes structural quick checks from foreign-key
checks; neither proves ciphertext completeness. Node 24 filesystem documentation
(https://nodejs.org/docs/latest-v24.x/api/fs.html) describes descriptor reads and open flags.
The application adds its own semantic checks and byte limits. No new dependency or licence.
