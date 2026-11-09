# Guarded legacy migration prototype

This is an offline, synthetic-data candidate builder stacked on PR #41 at
`64cce099f1729b899c6da702c85d438c22162a06`. PR #40 at
`62b8e6634cc6ba2a634b3170654fc21a34c8c0b4` supplies the legacy custody digest and
independent recovery checkpoint contract. It does not migrate production stores,
activate a service, advance custody, reset a writer generation or deploy a migration.
Provisional TRL 4 is unchanged. SAG grading is not established.
TRL 5 qualification and IAF operational approval are not established.

## Evidence boundary and eligibility

PR #40's custody digest commits authority epoch/revocation version, selected user
fields, device keys/status and unit/mission policy. It omits credentials, MFA floor,
sessions, challenges, crypto policy/keys, FLASH approvals and the runtime PQC gate.
Neither an authentic signed event chain nor that digest can establish the omitted
state. PR #41 correctly refuses missing seals. This prototype does not infer or
reconstruct those facts from incomplete logs.

The additional independent evidence accepted here is an **original, separately
retained, authority-signed SIEPMU_BACKUP_V1 manifest and its SHA-256 pin**, captured
when the complete snapshot was trusted. The manifest hashes the entire database,
including fields omitted by legacy custody. The pin means SHA-256 of the canonical
signed packet, including its signature. A manifest obtained solely from the suspect
archive, or newly signed over the suspect database, is not independent evidence.
The migration tool does not create a historical manifest or generate reviewer approval.

| Legacy state/evidence                                                                                                                                                                         | Prototype outcome                              | Reason / additional evidence needed                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Exact control.sqlite member of a trusted backup, schema 001–006, original manifest/pin, matching independently retained signed checkpoint and legacy custody receipt, approved current policy | Eligible for a separate candidate              | Complete bytes and exact history position are independently committed                                          |
| Same evidence with migration 007 already applied but its seal table empty                                                                                                                     | Eligible for a separate candidate              | Exact expected schema and absence of a seal are checked; no runtime backfill                                   |
| Encrypted legacy backup satisfying the same conditions                                                                                                                                        | Eligible for a control-database candidate only | Existing AEAD, file-hash, manifest signature and identity checks run first; archive remains untouched          |
| Checkpoint/legacy custody receipt only                                                                                                                                                        | Refused                                        | Missing full-state witness cannot establish credentials, MFA, sessions, challenges, crypto policy or approvals |
| Signed backup whose manifest/pin was not independently retained from trusted capture                                                                                                          | Refused by procedure                           | A new signature cannot distinguish legitimate state from attacker-restored state                               |
| Older snapshot below the latest retained checkpoint, fork, or valid chain with an unwitnessed tail                                                                                            | Refused                                        | Exact snapshot/head equality is mandatory; ancestry alone is insufficient for full authorization state         |
| Selectively rolled-back policy/session/MFA/challenge/approval/key rows                                                                                                                        | Refused                                        | Whole database hash must match the independent manifest before any SQLite mutation                             |
| Policy inconsistent with independently reviewed crypto policy or current authorization requirements                                                                                           | Refused                                        | Policy digest and signed reviewer attestation must agree; no policy repair occurs                              |
| Existing valid or invalid authorization seal                                                                                                                                                  | Refused                                        | This is not a seal replacement/repair tool                                                                     |
| Earlier/unknown schema, extra trigger/view/index, altered migration, laboratory PQC state or crypto key registry entries                                                                      | Refused                                        | Unsupported profiles require separate design and evidence; no best-effort conversion                           |
| Live/WAL-backed database, bare arbitrary database copy without a matching snapshot hash                                                                                                       | Refused                                        | Use an independently witnessed offline snapshot; do not snapshot a suspect live store to manufacture evidence  |
| Existing fenced custodian or custody that advanced after the retained receipt                                                                                                                 | No activation                                  | Generated generation-zero handover request loses the existing exact-anchor/generation CAS                      |

Cryptography verifies bindings, not administrative independence, chronology of capture,
absence of later policy changes, or truth of an operator's statements. Separately pin
and administer the authority, custodian and reviewer public keys. The independent
reviewer must check original evidence provenance, confirm the latest custodian head,
and approve the complete current authorization state. If that cannot be done, stop.
An expired historical custody receipt can identify a prior state; it is never treated
as a fresh serving lease. No historical uncertainty is upgraded into verified current
policy merely by signing an approval. Loss of both the full-state witness and trustworthy
independent policy records makes safe migration impossible with this evidence model.

## Explicit operator procedure (synthetic laboratory only)

1. Stop the synthetic authority, relay and custody writers. Preserve originals and the
   independent evidence. Work in a new owner-only real directory (mode 0700). Inputs must
   be owner-held regular files, mode 0600, without hard links or final symlinks. SQLite
   inputs must have no `-wal`, `-shm` or `-journal` sidecar. The tool never opens source
   databases with SQLite; it validates private copies. The 64 MiB source limit is a
   prototype resource bound, not a supported deployment sizing claim.
2. Obtain the independently retained manifest/pin, signed authority checkpoint and
   custodian-signed legacy lease for the **same exact head**. Establish that no newer
   checkpoint, revocation, personnel/device change or policy supersedes it. Provide the
   approved current crypto-policy digest. Keep the archive passphrase separate.
3. Supply a fresh public writer key distinct from authority, custodian and reviewer keys.
   Its private key stays separately held. The existing custodian must still be unfenced;
   this builder does not inspect/mutate a live custodian or authorize overriding one.
4. Inspect and review the plan. The source hash, trust-file hash, destination, schema,
   old/full state digests, policy, writer identity and authority floors are bound into
   `planDigest`. Read the private source policy and authorization records as part of
   review; a digest alone is not a human-readable policy assessment. Retain the returned
   `planDigest` independently, with the reviewed request and original evidence.
5. A separate reviewer signs the exact approval payload below using its independently
   pinned P-256 key. Do not have a script automatically confirm the four assertions.
   Re-run inspection/review if any input, key or destination changes.
6. Apply once. The builder re-verifies all inputs and the approval, adds migration 007
   if needed, appends `LEGACY_AUTHORIZATION_MIGRATED` and seals the unchanged authorization
   state in one private SQLite transaction. It verifies the history and seal, fsyncs the
   candidate and publishes a new directory by rename. No existing directory is replaced.
7. Retain `receipt.json`, `plan.json`, `approval.json` and the original evidence separately.
   Run the public-key-only `verify` command below with the independently retained plan
   digest. It rechecks the original evidence, candidate file digest, signed receipt,
   approval, new checkpoint, exact migration event and writer handover request.
   The output is only `control.sqlite` and four JSON records: it contains no service,
   master, relay or writer private key. It is not a complete restored service directory.
8. Activation is a separate maintenance decision, outside this prototype. The supplied
   `handover-request.json` proposes generation **0 → 1** against the exact old anchor and
   unchanged floors through the existing local handover tool. A changed anchor/generation
   must fail; never clear/reset custody or enable bootstrap to make it pass. Retain the
   resulting handover receipt independently. A properly configured synthetic authority
   then needs a fresh fenced custody lease for its new V2 state before serving. Keep
   fencing required. Existing runtime quarantine, signatures and monotonic floors remain
   unchanged. Tests exercise this sequence only on synthetic custody.

Commands (Node >=24.19.0 <25):

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run test:legacy-migration
node scripts/legacy-migration.mjs inspect /private/lab/request.json
# Independent operator review and approval signing happen between these commands.
node scripts/legacy-migration.mjs apply /private/lab/request.json /private/lab/approval.json /private/lab/authority-private.json
# Supply the 64-character digest retained at inspection, not one read from the candidate.
node scripts/legacy-migration.mjs verify /private/lab/request.json "$RETAINED_PLAN_SHA256"
```

For encrypted backups provide `SIEPMU_BACKUP_PASSPHRASE` securely in the environment.
No passphrase or private reviewer key is accepted as a command-line value. The tool
has no network interface, approval-signing command, force option or startup hook.
It is excluded from `dist`/container and signed offline release packages.

`request.json` has exactly these members:

```json
{
  "sourceType": "database",
  "source": "/private/lab/legacy.sqlite",
  "destination": "/private/lab/new-candidate",
  "trust": "/private/lab/independent-trust.json",
  "writerPublicKey": "/private/lab/fresh-writer-public.json"
}
```

Use `"sourceType": "backup"` and the encrypted archive path for backup input.
`independent-trust.json` has exactly `version: 1`, `scope: "SYNTHETIC_ONLY"`,
`authorityKey`, `custodianKey`, `reviewerKey` (public P-256 JWKs), `checkpoint`, `lease`,
`manifest` (the original signed packets), `retainedManifestSha256`,
`expectedPolicyDigest` (SHA-256 of canonical approved crypto policy) and
`allowPqcLab: false`. No keys are taken from the candidate as trust roots.

`approval.json` is a standard existing `{payload, signature, keyId}` packet signed by
the separate reviewer. Its payload has exactly:

```json
{
  "version": 1,
  "kind": "LEGACY_MIGRATION_APPROVAL",
  "planDigest": "<SHA-256 returned by inspect>",
  "stateDigest": "<complete V2 state digest reviewed in the plan>",
  "reviewer": "<accountable laboratory operator>",
  "scope": "SYNTHETIC_ONLY",
  "independentSnapshotConfirmed": true,
  "latestCheckpointConfirmed": true,
  "currentPolicyConfirmed": true,
  "maintenanceConfirmed": true,
  "expiresAt": 0
}
```

Replace `expiresAt` with the independently chosen future expiry in integer milliseconds.
The displayed zero is intentionally invalid. Use the existing `packet` implementation
from `services/control/primitives.mjs` in a separately controlled signing environment.
Test fixture signing is a synthetic example, not evidence of real operator review.

## Candidate verification before any separate handover

`verify REQUEST RETAINED_PLAN_SHA256` needs the original source snapshot/archive,
independent trust file and writer public key referenced by the reviewed request, and
the candidate at that request's exact destination. Verification accepts no signing
private key. Backup verification still needs its passphrase. It opens only bounded,
private copies with SQLite, leaves the source and candidate bytes unchanged, and
removes its private staging on success or handled failure.

The returned status is `VERIFIED_QUARANTINED`. It proves the checked artifact bindings
under the supplied independent roots and retained plan pin; it is not a serving lease,
custody freshness check, activation approval or independent assessor's finding. The
verifier shares existing validation primitives and is not a second implementation.
It never advances custody or performs writer handover. A later mutation requires
verification again; exclusive maintenance remains required through separate handover.

The verifier requires exactly the five expected candidate files, without SQLite
sidecars, symlinks, hard links or private keys. It reconstructs the approved plan from
the original evidence and compares the retained digest. It verifies both signatures,
the receipt's exact file hash and new checkpoint, complete history from genesis and
the original anchor, the V2 seal, and the unchanged authorization digest. It compares
**all original logical table rows**, including non-authorization metadata, counters
and historical migration records. Only migration 007 (when originally absent), one
explicit signed migration event and its authorization seal may be added. The event
must bind the exact approval, plan, original manifest and reviewed state. The handover
request must match the reviewed writer, generation zero, anchor and policy floors.
The builder now also checks preservation of all original logical table rows before
publication; the existing seal check keeps precedence for authorization corruption.

Expired approval is a refusal even if the candidate was built earlier. Do not modify
or re-sign the existing candidate to make it pass. A renewed review must confirm the
evidence and current policy again, then use a new destination and new bound approval.
This verifier does not provide historical-audit acceptance for expired approvals, nor
can it supply lost evidence or establish that no newer custodian head exists.

## Failure and recovery semantics

All source/archive reads are bounded through one descriptor with NOFOLLOW/NONBLOCK.
Input schema includes exact table/index definitions and checked migration checksums;
unknown objects, invalid foreign keys and invalid evidence row/hash bindings fail closed.
The history verifier starts at genesis and requires the retained exact head; authority
epoch history, old custody digest and reviewed crypto policy must match. No existing
history row is rewritten and no authorization-table value is repaired or reset.

Handled verification, disk-write or publication failure cleans private staging and does
not publish the destination. SIGKILL can leave a private `.siepmu-migration-*` directory;
it is never automatically resumed, trusted or activated. Preserve it if investigating,
then explicitly remove it during maintenance. A retry starts from the original independent
inputs and a still-valid reviewed approval. A failure after rename/fsync is an uncertain
publication outcome: inspect the destination and receipt, do not overwrite or blindly retry.
The `verify` command makes that inspection executable, while keeping the candidate
quarantined. An injected parent-directory fsync failure after rename exercises this
case: the candidate can be verified, a repeat `apply` refuses the existing destination,
and custody remains unchanged. This does not establish physical power-loss durability.
A crash during later custody handover is governed by the existing transactional handover
and independent-receipt procedure. This is not a multi-store atomic disaster recovery
protocol or physical power-loss qualification.

The filesystem boundary assumes exclusive maintenance and an operator-controlled parent;
a hostile process with the same OS identity, compromised trust roots, compromised reviewer,
cloned current writer credentials and custodian rollback/compromise remain outside the
proven boundary. The synthetic-only marker is an explicit API/profile restriction, not
an automatic detector of production data. This task executes only freshly generated fixtures.

## Executable validation and observed evidence

`tests/legacy-migration.test.mjs` covers database and encrypted backup candidates, both
supported schema forms, source immutability, historical record preservation, normal-restore
rejection, custody handover and quarantine. Adversarial subtests cover divergent/newer/older
checkpoints, missing independent evidence, forged signatures/state, selective authorization
rollback, changed inputs/approval/keys/destination, unsupported schema/policy, interrupted
writes, three actual SIGKILL boundaries, failed publication, post-write corruption, missing
custody and custody advancement. `tests/helpers/legacy-migration-fixture.mjs` generates
legacy-shaped synthetic data using existing provisioning, removes only the new seal/schema,
and uses the pinned PR #40 limited digest. It does not claim an independently collected
historical production dataset.

Development run before expanded session/challenge/approval cases: the migration + existing
recovery + authorization-state + writer-fencing suites passed **85/85** on Node 24.22.1/Linux
x64. The first development run retained 50 passes/7 failures (including one failed parent):
quarantine assertions incorrectly expected a return instead of the existing thrown 503,
and the corruption fixture initially left SQLite foreign keys enabled. Correcting the test
harness preserved the production behavior; no security assertion was removed.

First frozen implementation `0793fb1108f59f7cf0c4d4630289ef88fbbd475d` ran 571 tests:
569 passed and two failed. The exact crypto-inventory source/test allowlist needed the
new migration files; the line-scoped claims audit required qualification negation on
the same line. All 68 migration tests passed; the other nine native gates passed.
The follow-up updates that exact inventory assertion and clarifies wording, without
changing migration/runtime behavior or weakening gates. The first report/logs are retained
locally at `artifacts/validation-0793fb1-failed/`.

The final exact commit, full validation/adversarial counts and hosted workflow outcomes
belong in the draft PR and `artifacts/validation/report.json`, not inferred from these earlier
counts. Reproduce with `npm run validate`, `npm run test:e2e`,
`npm run test:adversarial -- artifacts/legacy-migration-adversarial` (use a new destination) and
`npm run test:legacy-migration`. Counts overlap and must not be added.
These tests do not establish independent assessment or sponsor acceptance.
SAG grading and operational qualification are not established by these tests.

The verification follow-up adds receipt/checkpoint substitution, writer/generation/floor
tampering, extra/missing files, validly re-signed selective rollback and metadata changes,
wrong/extra migration events, expired review, missing/invalid seals, and uncertain
publication recovery tests. It also runs the real CLI after deleting the synthetic
authority private-key file. First focused development run: 106/107 passed; the added
row-preservation check initially preceded the established seal-error check. Restoring
that existing error precedence retained both checks. The next run passed 111/113,
including a failed parent: one new assertion expected `Invalid signature` instead of
the existing verifier's exact `Invalid P1363 signature` message. Only that expectation
was corrected. Final frozen-source results are recorded in the PR and generated reports;
these intermediate counts are retained for traceability.
