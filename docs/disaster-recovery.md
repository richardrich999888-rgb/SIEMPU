# Encrypted backup and restore

Actual utility: [scripts/backup.mjs](../scripts/backup.mjs); regression: [tests/recovery.test.mjs](../tests/recovery.test.mjs). It snapshots both SQLite databases with `VACUUM INTO`, binds file hashes in a server-signed manifest and encrypts the archive with scrypt-derived AES-256-GCM. Included: authority database, relay database, signing/master/relay keys and public verification key. Browser vaults and demo provisioning profiles are not included.

Stop all three services first: sequential database snapshots are not a distributed live-backup transaction. Set `SIEPMU_BACKUP_PASSPHRASE` securely in the process environment (minimum 16 characters); never commit or print it. Then:

```sh
SIEPMU_MAINTENANCE_CONFIRMED=1 node scripts/backup.mjs create .data /protected/siepmu-backup.json
node scripts/backup.mjs restore /protected/siepmu-backup.json /protected/empty-restore trusted-public-key.json
```

The archive must not already exist; restore destination must be empty. Restore authenticates archive, manifest, allowed filenames and file digests, and creates restrictive permissions. The module API additionally accepts an independently retained checkpoint and rejects backups predating/conflicting with it. The CLI currently requires the trusted public key but does not accept that optional checkpoint: use the module workflow or review the saved epoch/checkpoint before restarting authority.

Tests restore identities, revocations, schema and evidence; reject archive tampering and stale checkpoint; test migration upgrade/checksum rejection. This is measured synthetic recovery, not geographically replicated DR. Revalidate current user/device/policy authority before enabling release from an older snapshot. Local counters do not prevent adversarial rollback of the entire database. Keep archive passphrase, backup and independent verification root/checkpoint under separate approved custody.
