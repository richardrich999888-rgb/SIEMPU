# Encrypted backup and restore

Actual utility: [scripts/backup.mjs](../scripts/backup.mjs); regression: [tests/recovery.test.mjs](../tests/recovery.test.mjs). It snapshots both SQLite databases with `VACUUM INTO`, binds file hashes in a server-signed manifest and encrypts the archive with scrypt-derived AES-256-GCM. Included: authority database, relay database, signing/master/relay keys and public verification key. Browser vaults and demo provisioning profiles are not included.

Stop all three services first: sequential database snapshots are not a distributed live-backup transaction. Set `SIEPMU_BACKUP_PASSPHRASE` securely in the process environment (minimum 16 characters); never commit or print it. Then:

```sh
SIEPMU_MAINTENANCE_CONFIRMED=1 node scripts/backup.mjs create .data /protected/siepmu-backup.json
node scripts/backup.mjs restore /protected/siepmu-backup.json /protected/empty-restore trusted-public-key.json trusted-checkpoint.json
```

The archive must not already exist; restore destination must be absent or an empty real directory. Both the CLI and module API require an independently retained authority public key and signed checkpoint. Omitted, null, malformed, newer and conflicting anchors fail closed. This intentionally removes the old unanchored module API. Restore authenticates strict archive/manifest/file schemas and digests, checks the restored signing identity, and verifies every signed evidence link from genesis. The hash at the retained checkpoint's exact sequence must match; a higher sequence alone never proves extension. Stored SQLite sequence/hash columns and the manifest head must agree with the verified records.

Restore stages files with private permissions in a sibling directory, opens the staged authority database read-only, and publishes by rename only after verification. A handled write/verification failure removes staging without populating the destination. Use an operator-controlled parent directory and exclusive offline maintenance; this is not protection against a hostile process with the same OS account. A hard kill can leave a private `.siepmu-restore-*` directory for operator inspection/removal. Atomic publication is not a power-loss durability or whole-system RPO/RTO guarantee. The full JSON evidence-export limit remains unchanged; recovery streams rows and does not inherit its 100,000-record limit.

Tests restore identities, revocations, schema and evidence; reject divergent earlier checkpoints, bad signatures, hash-column corruption, missing records, false manifest heads, ambiguous filenames, noncanonical encodings and key substitution. They retain tamper, wrong-passphrase, stale-checkpoint and migration regressions, and inject a local disk-write failure followed by a successful retry. These are synthetic tests, not geographically replicated DR. An authentic history does not validate arbitrary authorization-table contents, unwitnessed post-anchor facts or present personnel/device policy. Revalidate current custody and policy before enabling release. Custodian/monitoring stores, separate endpoint queues, fleet keys and all-service coordinated recovery remain outside this six-file archive. Keep archive passphrase, backup and independent verification root/checkpoint under separate approved custody.

## Explicit synthetic legacy migration prototype

Ordinary restore still rejects missing authorization seals. A separate, source-only
[guarded legacy migration prototype](qualification/GUARDED_LEGACY_MIGRATION.md) builds a
new candidate only when independently retained full-snapshot evidence, an exact checkpoint,
legacy custody evidence and separately signed operator review establish the state. It does
not activate services or mutate source/custody stores. Checkpoint-only and limited-digest-only
legacy states remain refused; no production migration is authorized by this prototype.
Its separate `verify` command checks the generated candidate against the original
evidence and an independently retained plan hash, using no signing private key. It
also verifies every preserved logical row and the exact handover parameters. Successful
verification leaves the candidate quarantined; custody freshness, writer transfer and
any activation remain separate decisions. An expired review or missing evidence is
a refusal, including after an interrupted or uncertain publication.
