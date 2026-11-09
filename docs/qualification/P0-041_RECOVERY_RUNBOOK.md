# P0 041 Recovery and writer handover runbook

This is an applicant laboratory procedure for synthetic data. It is not an approved IAF
operating procedure or a claim of complete disaster recovery. Provisional TRL 4 is unchanged.

## Before recovery

Record the exact commit/tree, runtime, configuration and operator identities. Stop admissions
and isolate the previous authority. Preserve its database, WAL and unacknowledged records for
reconciliation. Do not copy its writer credential onto another live node. The independent
custodian operator retains the newest signed checkpoint, authorization digest, writer handover
receipt and generation outside the failed authority. If any is missing or inconsistent, keep
release disabled. Custodian loss is not solved by restoring the authority database.

Use the existing encrypted maintenance backup only after stopping all relevant services.
Recover the archive passphrase and authority master/signing keys through the agreed custody
procedure; no such operational escrow or hardware procedure is established here. The archive
contains sensitive software keys, requires restricted handling, and does not include independent
custody/monitoring stores or a new writer identity. It is not a full-system recovery image.

```sh
SIEPMU_MAINTENANCE_CONFIRMED=1 node scripts/backup.mjs create DATA_DIR ARCHIVE
node scripts/backup.mjs restore ARCHIVE EMPTY_RECOVERY_DIR AUTHORITY_PUBLIC_KEY RETAINED_CHECKPOINT
```

Supply `SIEPMU_BACKUP_PASSPHRASE` through the authorised local secret mechanism, not command
arguments, logs or this repository. Restore verifies encrypted contents, signatures, exact
ancestry, database/evidence bindings and the signed authorization commit before atomic directory
publication. A partial restore is removed. This is tested error handling, not a physical disk
power-loss qualification. The default classical profile is supported; old sealless or differently
configured archives remain blocked pending a reviewed migration.

## Handover

The restored candidate must extend the independently retained anchor and match its state when
at the same head. Preserve current revocations and the policy epoch. Generate a fresh writer
key locally on the replacement; transfer only its public JWK through the authorised operator
channel. Provision the private credential as `{ "generation": NEXT, "key": PRIVATE_JWK }`
with owner-only permissions. Do not reuse either authority or custodian keys as writer keys.

Prepare a local request JSON with exactly `writerKey`, `expectedGeneration`, `expectedAnchor`
(`sequence`, `headHash`, `stateDigest`) and `authority` (`epoch`, `revocationVersion`). These
values must come from the reviewed retained custody record, not the failed node. Run on the
custodian's controlled maintenance host:

```sh
node scripts/authority-handover.mjs CUSTODY_DB AUTHORITY_PUBLIC_KEY CUSTODIAN_PRIVATE_KEY REQUEST_JSON > NEW_SIGNED_RECEIPT
```

The database must already exist in an operator-owned directory (0700), with database and private
key files restricted to that operator (0600). JSON inputs are limited to 16 KiB and read through
one validated descriptor; final symlinks are rejected. This maintenance boundary does not resist
a hostile process with the same OS identity. Preserve that administration boundary during handover.

The compare-and-swap fails if another handover or checkpoint won. Do not retry automatically
with newly read values. Reconcile and review first. Retain and independently verify the signed
receipt. Start the replacement with the new credential, pinned mTLS, the same custodian and
`SIEPMU_CUSTODY_REQUIRE_FENCING=1`; the authority uses `SIEPMU_WRITER_CREDENTIAL`.
Confirm the prior writer is denied, old revoked recipients are denied, and a synthetic authorised
exchange verifies before resuming any approved workload. Keep production use disabled pending
review. No government endpoint or real personnel account is needed for this drill.

## RPO and RTO interpretation

For a successfully returned guarded release, the final evidence head was accepted by custody.
That does not guarantee a complete replica of ciphertext, key material, endpoint outboxes or
monitoring data. Backup lag and missing ciphertext can prevent recovery. Measure object loss,
unacknowledged decisions, backup age and all stores separately; no general zero-RPO claim.

Measure detection, operator decision, restore, handover and first successful authorised exchange
as separate times. Automated local test durations exclude human decisions and host replacement.
The network campaign records outage duration and time from restored connectivity to success;
those are not complete disaster-recovery RTO. Required RPO/RTO and retention are IAF inputs.

## Retained blockers

Independent hosts/administrators, replicated custodian availability, production key recovery,
physical storage failures, secure old-format migration, retention/compaction and operational
reconciliation remain open. Owners: SYNTRIASS engineering, IAF hosting/crypto owners and the
nominated evaluator. Next executable work is a witnessed drill after those inputs are supplied.
