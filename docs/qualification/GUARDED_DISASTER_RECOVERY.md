# Guarded synthetic disaster-recovery rehearsal

This source-only prototype extends PR #42's verified legacy candidates with a
reviewed recovery of control, ciphertext relay and monitoring, explicit writer
handover and a fresh custody lease. The independent custodian is preserved, never
restored from a service backup. No production database, merge or deployment is
performed. Existing runtime authorization, crypto and applied SQL are unchanged.

Provisional TRL 4 remains unchanged. TRL 5 qualification is not established.
SAG grading and IAF operational approval are not established. All 19 qualification
gaps remain open; this is additional applicant laboratory evidence.

## Execute and inspect evidence

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run test:guarded-recovery
npm run validate
npm run test:e2e
npm run test:adversarial -- artifacts/NEW_ADVERSARIAL_DIRECTORY
npm run rehearse:recovery -- artifacts/NEW_RECOVERY_DIRECTORY
```

Use Node 24. The last two commands require a clean committed tree and absent output
directory. The rehearsal accepts only an artifact destination: it generates fresh
synthetic fixtures, runs sealed and migrated-then-fenced profiles and removes the
private fixture stores/keys. Public evidence, trust packets, plan, approval and
handover are retained with source commit/tree/fingerprint and SHA-256 manifest.
CI uploads `guarded-recovery-evidence`; ADV-07, DEMO-3 and security regression also
run these tests. Counts overlap. The recovery scripts are excluded from application,
container and signed offline packages. No startup migration or network admin route
is added. The full operator driver is a test helper, not a production recovery CLI.

## Eligibility

| Requirement           | Evidence required before staging                                                                                                                                                                                                                                |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Control/relay archive | Existing authenticated encrypted backup; independently pinned signed full manifest; original authority public key; exact matching signed checkpoint; complete verified ancestry and valid authorization seal.                                                   |
| Authorization         | Signed historical fenced custody lease at that exact head, full state digest, epoch/revocation floors, existing nonzero generation and distinct successor writer. Historical expiry does not confer a live lease.                                               |
| Monitoring            | Separate collector-signed `SYNTHETIC_MONITOR_RECOVERY_SNAPSHOT`, independently retained witness hash, exact authority/head and database hash. Complete redacted events reconcile with control; event acknowledgements and detection record/ack bindings verify. |
| Policy/schema         | Exact control migrations 001–007/checksums and schemas; relay/collector schemas; SQLite/FK integrity; runtime crypto-policy validation; classical production policy with no alternate registered keys. Unknown suites/profiles fail closed.                     |
| Current custody       | Existing independently administered store/key, bootstrap disabled, fencing enabled; exact reviewed anchor/generation/floors. Lost, conflicting or advanced custody cannot be reset by recovery.                                                                 |
| Separate review       | Pinned reviewer key, unexpired signed complete plan approval, current policy/latest custody/independent snapshots/stopped-writer attestations.                                                                                                                  |
| Files                 | Private bounded regular inputs, private real parent, absent destination, offline collector snapshot without sidecars. Source files remain unchanged.                                                                                                            |

Authority, custodian, collector and reviewer public roots must be distinct. The
new writer must differ from those roots and the previous writer. Custodian,
collector, reviewer and writer private keys remain outside the recovered service
set. The existing encrypted archive contains authority/master/relay software keys;
hardware custody is not demonstrated.

The independent manifest/witness/checkpoint and public roots must have been retained
through a trusted procedure. Computing a new pin from suspect incident data does
not establish history. A valid old lease cannot prove it is latest: current custody
CAS and the operator's freshness decision remain necessary. Compromised or rolled
back custody and hostile same-UID processes are outside the existing trust boundary.

The migrated profile first executes PR #42 inspect/apply/public-key verify against
synthetic historical full-snapshot evidence and separate review, performs explicit
legacy-to-sealed handover, obtains a fresh fenced lease, and captures a **new** sealed
recovery set and monitoring witness. It never makes unwitnessed legacy state safe.
See [legacy migration eligibility](GUARDED_LEGACY_MIGRATION.md).

## Explicit review and upgrade procedure

1. Stop writers; preserve independent custody and original evidence. Establish current
   policy and trusted public roots. Select a new private synthetic recovery directory.
2. `inspectGuardedRecovery(request, { passphrase })` verifies private temporary copies
   using ordinary strict restore. Exact request fields: `version: 1`,
   `scope: "SYNTHETIC_ONLY"`, `archive`, `monitor`, `trust`, `writerPublicKey`,
   `destination`. It returns `plan` and canonical SHA-256 `planDigest`.
3. Independently retain that digest. Review hashes, policy, original head/state/floors,
   previous/proposed writers, generation and destination. Sign the following payload
   with the separate reviewer, using the existing P-256 packet format:

   ```json
   {
     "version": 1,
     "kind": "SYNTHETIC_RECOVERY_APPROVAL",
     "planDigest": "independently retained plan hash",
     "reviewer": "identified operator",
     "currentPolicyConfirmed": true,
     "latestCustodyConfirmed": true,
     "independentSnapshotsConfirmed": true,
     "writersStoppedConfirmed": true,
     "expiresAt": 0
   }
   ```

   This illustrative expiry cannot authorize anything. Choose a reviewed future
   expiry. Exact trust/witness schemas are enforced in `prepare()`; the fixture is
   an executable example. Fixture signatures are not real human approval.

4. `stageGuardedRecovery(request, { passphrase, approval })` revalidates all inputs
   and expiry, synchronizes files/directories and renames a new private service set:
   six archive files plus `monitor/collector.sqlite` and two review records. Published
   means quarantined. Staging does not change custody or activate a service.
5. At the existing custodian, explicitly invoke `reconcileRecoveryHandover(custody,
plan, approval, trust, { perform: true })`. It checks the original writer and
   exact anchor/generation/floors, uses the existing atomic transfer, and verifies
   the signed receipt. Retain that receipt independently. Expiry cannot elect a
   writer; recovery never resets generations or policy floors.
6. Reverify the working set and start with the new writer credential and existing
   recovery guard. It begins quarantined. Require a fresh custodian lease before
   protected requests. The synthetic driver then opens a loopback control listener,
   verifies the previously acknowledged object/receipt, sends/decrypts/acknowledges
   a new encrypted message, checks revoked device/inactive user denial, reconciles
   telemetry and runs old/new writer requests concurrently (old refused).

Only the synthetic fixture automates all steps. A deployed operator interface and
production activation procedure remain unimplemented.

## Interrupted recovery

Resume reconstructs the plan from original independent inputs plus the externally
retained plan hash and same valid approval. Local journals are not trust roots.
Database comparisons cover all logical rows, with typed BLOB encoding: SQLite
journal layout may legitimately change without changing the approved logical state.

| Boundary                                            | Required response                                                                                                                                                                                              |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Failure before publication                          | No activation or custody change; orphan private staging is ignored. Explicitly retry into an absent destination after revalidation.                                                                            |
| Publication before handover                         | Resume refuses automatic transfer; separate reviewed custodian handover is required.                                                                                                                           |
| Lost handover response                              | Retrieve only the exact signed receipt already in existing atomic custody history, matching writer/generation/anchor/floors. Never perform a second transfer to guess success. Missing/forged history refuses. |
| Fresh lease, no protected state advancement         | Reconstruct/review inputs and all logical rows; reconcile existing handover and obtain a new live lease. Cached flags/leases cannot activate.                                                                  |
| Protected state advanced, including acknowledgement | Old review is superseded. Preserve new state; capture a newly consistent recovery set with independently current evidence and new review. Automatic recapture is unimplemented.                                |
| Custody unavailable or verification fails           | Stay quarantined. Never bootstrap/reset custody, bypass seals, lower floors or remove conflicting history.                                                                                                     |

Actual SIGKILL tests cover verified staging, publication, committed handover, retained
receipt, fresh lease, before new message and after acknowledgement. These test process
crashes; fsync calls and SIGKILL do not qualify physical power-loss durability.

## Measurements and limits

`recoveryMs` starts before validation/staging and ends at a fresh lease plus listening
control server. `totalMs` includes encrypted exchange, revocation and stale-writer
checks. Setup, backup creation and human decision time are excluded. One sample per
profile is not a percentile, capacity measurement or RTO guarantee. Each profile has
one acknowledged pre-snapshot object; zero observed loss is not a fleet RPO promise.

Control and relay use real loopback HTTP. Custody and monitoring use the existing
implementations in-process with separate stores/keys. Crash workers are child
processes. All share one host/administrator: independent organizational custody and
multi-host mTLS recovery are not demonstrated. Monitoring supports complete signed
replay/dedup of at most 1000 evidence records and 1000 alerts, not exporter-cursor
recovery or arbitrary retention policies. Collector witnesses attest stored bytes;
this is not an independent recomputation of every historical detector judgement.
Endpoint keys/queues, connector state, full-site DR, quorum HA, hardware custody and
sponsor-directed relevant-environment validation remain outside this profile.

The 10 November unpublished workspace reset before publication; its test logs and
commit objects were lost. This source was reconstructed on 11 November and revalidated
from scratch. Earlier 682-test and focused counts are not claimed for this source.
The reconstruction includes typed BLOB digests, full runtime policy validation and
explicit detection record/ack row bindings. Consult final source-bound reports and
PR workflow URLs for actual observations; interrupted runs are not passes.

## States that still require additional independent evidence

- Legacy states with only a checkpoint, signatures or limited custody digest, without
  trusted historical full-snapshot and policy evidence, remain refused.
- Unknown ancestry, selective rollback, divergent history, missing seals, conflicting
  independent evidence or unverifiable policy cannot be repaired by new signatures.
- A six-file backup without a separately trusted matching collector snapshot cannot
  establish this three-store recovery profile; endpoint/connector evidence is not implied.
- Lost latest independent custody cannot be reconstructed from a service backup or
  recovery journal. Conflicting/newer custody requires fresh evidence and review.
- After protected state advances, old approval cannot authorize restart. Unknown
  schemas, crypto/retention profiles and all-service recovery require additional
  design and evidence; they are never silently converted or resealed.

Reconstruction development: 67/67 focused recovery tests and 12/12 packaging tests
passed. The first full run was interrupted after format-check rejected one chained
call layout in a test. Formatting was corrected without changing assertions; source
bindings were refreshed. Final full-source results are recorded separately.

The first frozen adversarial campaign on local `1c3cb081855f69a6b949b37d67ab3bbefa9deed9`
failed: ADV-04 exceeded its fixed 180-second batch limit (180.055 seconds, terminated;
55,869-byte log, below the 1 MiB output cap). The eight other families passed.
The 67-test recovery suite moved to the smaller ADV-07 offline-recovery family.
The test-path multiset, nine families, every assertion and the 180-second/1 MiB
limits are unchanged. This is a scheduling correction, not a successful interrupted
run or relaxed gate. Native validation on that source passed 683/683 and E2E 3/3;
all final-source results are recorded separately in the draft PR and CI artifacts.
