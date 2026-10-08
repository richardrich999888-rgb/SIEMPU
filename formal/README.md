# Formal model: release, revocation and recovery

`ReleaseAuthority.tla` models the control authority's release state machine as implemented in
`services/control/core.mjs` and the recovery guard in `services/evidence/custody.mjs`. TLC checks
it on the finite instance in `MCReleaseAuthority.tla`.

```sh
# Java 11+; the jar is the TLA+ tools release v1.8.0 asset, verified by SHA-256 in CI.
SIEPMU_TLA2TOOLS=/path/to/tla2tools.jar npm run formal:check   # writes artifacts/formal/report.json
```

## What is checked

| Property                        | Kind      | Statement                                                                                                                                                                                                                          |
| ------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IssueRequiresCurrentAuthority` | action    | A first issuance commits only if, in the committing state, the recipient is authorised, a FLASH object has an approval for the current epoch, and the client's expected epoch is current (stale grant / stale observation fenced). |
| `EvidenceMatchesIssuance`       | invariant | In every reachable database, issuance and `RELEASE_ISSUED` evidence are one-to-one.                                                                                                                                                |
| `DeliveredImpliesAnchored`      | invariant | A key-bearing response reaches a recipient only after the custodian has saved the evidence of that decision.                                                                                                                       |
| `AnchorMonotone`                | action    | The custodian's saved evidence prefix never regresses or forks.                                                                                                                                                                    |
| `AckedRevocationHolds`          | action    | After a revocation is acknowledged to the administrator, no key for that recipient is issued or re-sent unless a later re-authorisation is in the same history, across any number of crashes and database restores.                |
| `TypeOK`                        | invariant | Well-typed state.                                                                                                                                                                                                                  |

## Non-vacuity: broken designs that must fail

| Config      | Change                                                                | Required result                          | Counterexample found (6 states)                                           |
| ----------- | --------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------- |
| `faithful`  | none                                                                  | no error                                 | —                                                                         |
| `nonatomic` | policy check and issuance commit are separate steps                   | `IssueRequiresCurrentAuthority` violated | submit → check passes → revocation commits → issuance commits unchecked   |
| `unguarded` | no independent custodian; responses sent at commit; restore unchecked | `AckedRevocationHolds` violated          | submit → backup → revocation acknowledged → restore backup → claim issues |

The `unguarded` trace shows why epoch fencing alone is insufficient: after restore, the authority
epoch returns to a value the client already holds, so a stale client epoch matches again. Only the
independent, monotone checkpoint prevents the restored database from serving requests.

## Result (local, 4 vCPU, OpenJDK 21.0.12, TLC2 2026.10.06 rev 94d0c50 from release v1.8.0)

`faithful`: 3,837,180 distinct states, diameter 29, no error, about 55 s. Both mutants rejected with
the expected property. Hosted results per SHA: CI job `formal`, artefact `formal-evidence`.

## Instance bounds

One recipient; two objects (one normal, one FLASH); epoch ≤ 3; evidence length ≤ 5; one retained
backup. A two-recipient instance with evidence ≤ 7 exceeded 48 million states without finishing
in 10 minutes and was not used. Bounded model checking establishes the properties for this
instance only; it is not a proof for all sizes.

## Abstractions (judge these before relying on the result)

- `authorityReason` (users, devices, roles, duty roles, units, missions, policy edge, crypto
  policy, grant scope) is a single boolean per recipient. Every change bumps the epoch, as
  `Authority.change` does. Grant expiry and wall-clock time are not modelled.
- SQLite `BEGIN IMMEDIATE` transactions are atomic and serialisable; each action is one transaction.
- Signatures and hash chaining are abstracted to exact sequence equality.
- Lease expiry, network loss and process death are one `Crash` action that drops unsent responses.
- Restore replaces the whole authority database with a retained snapshot; the custodian's store
  is independent and is never restored with it (the deployment must keep it so).

## Limits that remain true of the real system

- A revocation that committed but was never acknowledged (crash before the post-request
  checkpoint) can be lost by a restore. The administrator must treat an unacknowledged change as
  not done and repeat it.
- A key released before revocation committed cannot be recalled (consistent with ADR-003).
- Conformance of `core.mjs` to this model is argued from the code, not mechanically verified.
