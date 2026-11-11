# P0-046 unified recovery assurance candidate

SYNTRIASS Labs Pvt. Ltd. | AIRON–SIEPMU | DISC-14 PS-69 | 11 November 2026

This source consolidates PR #44 at 9dab1a71121df09e51cc139727577600638a6bb6 and PR #45 at
6ac57e5e6e561c73525de08b09950263d2fe7dee. The pinned ancestry and every shared-file resolution
are in P0-046_RECONCILIATION.md. Exact commit/tree, environment, commands, pass/fail counts,
benchmarks and artifact hashes belong to the generated evidence manifest for the frozen source;
pre-freeze observations do not validate that revision.

## Architecture and authority

The sender encrypts and signs at the endpoint. The relay stores ciphertext. The control authority
rechecks current identity, device, role, mission, crypto policy, grant expiry and policy epoch inside
the release transaction. The signed evidence head and authorization-state seal bind that decision.
An independently keyed custodian retains the anchor, writer generation and monotonic policy floors.
A separate monitoring witness and reviewer pin the synthetic recovery inputs. All local fixtures
share one host and administrator; distinct keys alone do not establish independent custody.

The unified offline reader checks bounded archive authentication, retained checkpoint ancestry,
state seal, control object envelopes and relay digests/references before publishing a candidate.
Guarded recovery additionally checks exact control/relay/monitor schemas, pinned monitoring rows,
logical state digests, reviewer approval and unchanged pre-serving state. It never resets custody.
Handover uses the existing exact-anchor/generation comparison and retained receipt; retry after a
lost acknowledgement reconciles the committed transfer. Fresh live custody is still required for
protected operations; an old generation is fenced.

| State                 | Meaning                                                                               | Authority consequence                                             |
| --------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| QUARANTINED           | Candidate files staged and reviewed for offline inspection                            | activationAuthorised=false; no service startup or writer transfer |
| VERIFIED              | Read-only retained-plan, approval, working-set and expiry checks pass at this instant | activationAuthorised=false; no new lease or transfer              |
| ACTIVATION-AUTHORISED | Separate operational procedure and nominated authority permit activation              | Not emitted or implemented by this laboratory verifier            |

`verifyQuarantinedRecovery` rechecks approval expiry after database verification. A VERIFIED result
is not a durable authorization token, a current custody lease or proof that policy has not changed
elsewhere. The source-only synthetic rehearsal explicitly demonstrates a reviewed handover and
fresh lease; it is excluded from application and offline release bundles.

## Adversarial coverage and oracles

| Required family                                                                 | Reproduction surface                                                           | Refusal / evidence oracle                                                              |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| Divergent history, missing checkpoints, substituted seal and selective rollback | guarded-recovery, recovery, authority-state-custody and legacy-migration tests | No publication/reseal on invalid history; retained anchor and state must agree         |
| Stale custody, lower epoch, two writers, handover races and lost response       | writer-fencing and guarded-recovery tests                                      | Atomic generation/anchor checks; one winner; old writer refused; no duplicate transfer |
| Missing/corrupt ciphertext, wrong length, rows/schema, monitoring corruption    | recovery-stores and guarded-recovery tests                                     | Staging fails; no usable recovered authority or missing rows reconstructed             |
| Termination and interrupted publication                                         | guarded-recovery SIGKILL cases; unified-recovery write/fsync faults            | Quarantine or explicit pre-serving resume; no automatic serving                        |
| Storage capacity                                                                | unified-recovery actual SQLite max_page_count failure                          | SQLITE_FULL aborts handover; prior generation/history and issuance count unchanged     |
| Network/custody outage and renewal                                              | incremental-custody, guarded-recovery, network-failure suites; hosted netem    | Protected operations fail closed; resumed work requires fresh custody                  |
| Revoked user/device, mission removal, changed duty role, expired session        | unified-recovery tests                                                         | Exact denial status; no new issuance for the target object and no wrapped key response |
| Expired review, missing approval and altered candidate                          | guarded-recovery and unified-recovery tests                                    | No activation, issuance or silently substituted plan                                   |

Expiry of sponsor-issued device certificates is an external identity integration requirement; the
current regression exercises session expiry and explicit device revocation. Injected ENOSPC/EIO
and actual SQLite capacity exhaustion are not a physical full-disk or power-loss qualification.
Existing negative tests preserve their original oracles; new refusal cases explicitly inspect
issuance/fence state. A committed release cannot retract previously disclosed content.

## Reproduction and measurements

From the frozen clean checkout with Node 24 and locked development dependencies:

```sh
npm ci --ignore-scripts
npm run validate
npm run test:e2e
npm run test:adversarial -- artifacts/p0-046-adversarial
npm run test:guarded-recovery
npm run rehearse:recovery -- artifacts/p0-046-rehearsal
npm run kat
mkdir -p artifacts/p0-046
node assurance/bench/unified-recovery.mjs maintenance artifacts/p0-046/maintenance.json
node assurance/bench/unified-recovery.mjs guarded artifacts/p0-046/guarded.json
```

Run the same absolute-path benchmark driver from each clean pinned baseline directory in fresh
processes. Rotate baseline/candidate order. Maintenance compares all three revisions with twenty
4 KiB objects. Guarded recovery compares PR #44 and the unified candidate; PR #45 lacks that driver
and is NOT_APPLICABLE for that profile. Three repetitions are a preliminary sample, not an SLA.
Each guarded repetition includes 100 protected requests; report empirical percentiles with sample
counts and retain raw samples. Stage, working-set verification, handover, live lease, key release,
checkpoint verification, CPU, peak RSS and main/WAL sizes are measured separately. Testbed traffic
and network impairment use the existing hosted profiles; criteria remain applicant-defined.

## Limits and review

64 MiB encrypted archive; 32 MiB aggregate decoded control/relay files; 16 KiB credential/metadata
files. Guarded monitoring input is separately bounded; complete telemetry replay is limited to
1000 evidence records and 1000 alerts. Quiescent sequential snapshots only. Endpoint queues/keys,
exporter cursors, connectors, HSM/token state, deployment PKI and personnel federation remain outside
this recovery set. No automatic failover, quorum replication or full-site recovery is established.

No algorithm, runtime dependency, SQL migration or security threshold changed. CR-19 inventory
binds the combined recovery source/tests; provider boundaries and known-answer suites are retained.
The optional Codex Security review service was unavailable in this session (no scan/preflight tools
and unresolved reference resource). Manual diff review and hosted CodeQL are separate evidence;
independent security/cryptographic evaluation remains required.

Provisional TRL 4 is unchanged. SAG grading is not established.
TRL 5 qualification and IAF operational approval are not established.
All 19 gaps remain open or partial; see P0-046_GAPS.md. No production merge or deployment.

## Public technical sources checked 11 November 2026

- SQLite atomic commit: https://www.sqlite.org/atomiccommit.html — crash behavior depends on
  filesystem/flush assumptions; database transactions do not prove multi-service recovery.
- SQLite PRAGMAs: https://www.sqlite.org/pragma.html — structural and foreign-key checks are
  distinct; application digests and cross-store semantics remain additional checks.
- DRDO industry support: https://www.drdo.gov.in/drdo/sites/default/files/inline-files/Support-to-Indian-Industry_1.pdf
  — SAG support is service-requested; sponsorship for this candidate is not established.
- PS-69 indexed official challenge: https://idex.gov.in//challenges-cpt/2507 — public requirements
  include E2EE/MFA, granular permissions, protocols/monitoring and integration.
  SAG grading is required but not established for this candidate.
  Direct retrieval redirected to the home page; indexed content was available.
- MoD revised testing SOP announcement, 7 October 2026:
  https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=2320195&lang=2&reg=48
  — qualifying development projects may receive testing-charge relief. Exact project/activity
  applicability and SAG fees require written confirmation; no waiver is assumed.
