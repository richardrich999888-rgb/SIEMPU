# Policy interface

The policy boundary runs in [`Authority`](../control/core.mjs), using the same
SQLite transaction as admission and release. No remote policy decision service
or separately cached authorization result is introduced by this directory.

## Public contract

| HTTP route                | Request                                   | Response / access                                                                |
| ------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------- |
| `GET /api/control`        | None                                      | Signed `{epoch,revocationVersion,policyDigest,issuedAt,expiresAt}`; bound device |
| `POST /api/grants`        | `{proof}` for operation `grant`           | Signed creation-grant packet; bound operator                                     |
| `PUT /api/admin/policies` | `{fromUnit,toUnit,missionId,allow,proof}` | `{policy:{fromUnit,toUnit,missionId,allow}}`; bound administrator                |
| `GET /api/admin/overview` | None                                      | Includes current policies, epoch and revocationVersion; bound admin/auditor      |

A signed packet is `{payload,signature,keyId}`. Control snapshots expire after
60 seconds. Grant payloads are `{grantId,userId,deviceId,unitId,missionIds,
creationEpoch,policyDigest,issuedAt,expiresAt,maxSensitivity:'DEMO'}` and expire
after one hour. A grant permits object creation within its scope; release still
requires a current authorization decision.

Policy updates require existing source/destination units, a boolean `allow`, and
`missionId` matching `[A-Za-z0-9._:-]{1,80}`. The proof operation is
`admin:PUT:/api/admin/policies`. Missing policy edges deny access.

## Internal interface and decision inputs

`epoch()` reads the singleton authority row. `policyDigest()` hashes the canonical
array returned by `SELECT * FROM policies ORDER BY from_unit,to_unit,mission_id`;
it uses stored column names and integer allow values. `grant(session)` rechecks an
approved device binding and operator role before signing the creation scope.

`authorityReason(objectRow)` returns `null` for an eligible object or a reason
code. Its current-authority checks include the signed grant and validity interval,
object expiry, active sender/recipient, approved devices and ownership, operator
sender, operator/viewer recipient, unchanged units, both users' mission membership,
grant scope, recipient encryption-key identity and an explicit allow edge. An old
creation epoch alone does not grant current access; current policy is evaluated.
See [exchange](../exchange/README.md) for immutable object checks and release.

`change(session, mutation, eventType)` rechecks bound administrator authority and
executes the mutation, increments both global epoch and revocation version, then
appends evidence and an alert inside `BEGIN IMMEDIATE`. This shared wrapper is
also used for identity/device/session administration. The version therefore
advances on all such authority changes, not only explicit revocations.

`prepare()` and `claim()` call authorization inside their own `BEGIN IMMEDIATE`
transactions. `claim()` additionally requires the recipient's `expectedEpoch` to
equal the current epoch before issuance or redisclosure. SQLite write
serialization makes a preceding policy change visible to release; a subsequent
change cannot recall an already committed capability. There is no general ABAC
language or classified-data guard in this DEMO policy profile.

Tables owned by this boundary are `policies` and `authority`; identities and
devices remain authoritative inputs from their respective boundaries. See
[`docs/policy.md`](../../docs/policy.md) and the policy/race cases in
[`tests/authority.test.mjs`](../../tests/authority.test.mjs).
