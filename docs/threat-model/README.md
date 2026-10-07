# Threat model: lab release baseline

Scope: authorised human users exchanging synthetic text and files through an untrusted internet bearer and a ciphertext relay. This is a defensive information-exchange system, not a weapon/C2 system. Controls below are requirements or implementation review obligations; the claims register and executed tests determine their achieved status.

## Assets and trust boundaries

- **Endpoint:** plaintext, content keys, signing/decryption keys, encrypted outbox and accepted receipts. The user/OS can expose plaintext after decryption.
- **Identity authority:** password/MFA state, user/unit/role membership, sessions, enrolled device keys. Its compromise can create false identities.
- **Policy/release authority:** current policy and revocation epoch; final release transaction. This is a trusted enforcement component, not an adversarial blind relay.
- **Relay/store:** ciphertext and routing metadata. It should never receive endpoint private keys or plaintext content keys. It can still drop or delay traffic.
- **Evidence signer/store:** decision records and checkpoints. The trusted verification key must arrive independently of an untrusted evidence bundle.
- **Administrator/build chain:** can change policy, software and trust roots. A signer or root-admin compromise is outside the narrow release invariant unless independently constrained.

An enrolled software key proves possession, not device health. TLS protects the transport connection; object encryption protects stored/forwarded content. Neither protects an authorised compromised reader. A malicious relay that already holds recipient-decryptable ciphertext can bypass policy by copying it: release enforcement must keep the usable payload/key material behind the trusted gate until the committed release. See ADR-002/003 for the actual prototype boundary.

## Threat-control ledger

| ID  | Threat / attack surface                                    | Impact                                            | Required control and test                                                                    | Residual risk                                                                                    |
| --- | ---------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| T01 | Interception/MITM; internet/DNS/bootstrap                  | Disclosure or key substitution                    | TLS service authentication, endpoint payload encryption, controlled peer keys                | DNS/routing can deny service; malicious authority can substitute keys without an independent pin |
| T02 | Stolen credentials; login/session                          | Account takeover                                  | Password verification, mandatory MFA, request/device binding, session expiry/revocation      | TOTP is not phishing resistant; recovery is an attack path                                       |
| T03 | Stolen device; local store                                 | Plaintext/key disclosure                          | Encrypted local vault, lock state, bounded authority, device revoke                          | Unlocked device and copied private keys remain dangerous; remote wipe cannot act offline         |
| T04 | Endpoint compromise; client/OS                             | Keys and plaintext stolen                         | Minimise key residency; integrity checks; managed-device pilot                               | E2EE does not solve this; no blanket protection claim                                            |
| T05 | Insider with valid rights                                  | Permitted content exfiltration                    | Least privilege, current destination checks, decision evidence                               | Screenshots, copying and memorisation cannot be cryptographically recalled                       |
| T06 | Malicious administrator; roots/policy                      | False users, altered policy, forged assertions    | Separate duties and signer custody; pinned peer roots; external checkpoints                  | Prototype administrator remains trusted; signatures do not prove truth                           |
| T07 | Wrong role/unit or guessed object ID; direct API           | Unauthorised disclosure/mutation                  | Final object/action/unit/destination checks; negative direct-API tests                       | UI hiding is insufficient                                                                        |
| T08 | Privilege escalation/confused deputy; adapter/admin routes | Broader authority through another service         | Least privilege, explicit actor context, no caller-selected identity                         | A trusted service with broad credentials remains high impact                                     |
| T09 | Replay; requests/objects/receipts                          | Duplicate side effects or stale authority         | Signed context, fresh nonce, durable uniqueness and idempotent acknowledgements              | Duplicate transport may occur; no universal exactly-once network guarantee                       |
| T10 | Tampering; ciphertext/metadata                             | Content or destination substitution               | AEAD and signature covering every authority-relevant field; strict version/schema            | Correct signature can accompany false origin assertions                                          |
| T11 | Policy/revocation race; queued release                     | Stale authority releases content                  | Re-evaluate/fence at release linearisation point in same transaction as evidence             | Revocation after committed release cannot recall plaintext/capability                            |
| T12 | Stale authority/rollback; reconnect                        | Old permission accepted                           | Monotonic authoritative epoch, no blind outbox drain, HOLD on uncertainty                    | Malicious full DB rollback requires external checkpoint/anti-rollback protection                 |
| T13 | Clock rollback; endpoint/server leases                     | Expired rights extended                           | Validate time bounds and monotonic floor; HOLD uncertain local grants                        | Trusted server clock is a prototype assumption unless measured protection exists                 |
| T14 | Malicious file; parser/preview                             | Execution or exfiltration                         | Size/type bounds, no active preview, endpoint scan/sandbox before opening                    | Ciphertext relay cannot content-scan without changing E2EE boundary                              |
| T15 | Compromised relay/workload; store/backups                  | Delete/withhold/alter or bypass gate              | Authentication, least privilege, ciphertext integrity, no public-store bypass                | A fully compromised trusted release service can violate its own policy                           |
| T16 | Evidence edit/reorder/delete/truncate                      | Misleading audit                                  | Signed hash-linked records; externally anchored sequence/checkpoint; negative verifier tests | A chain alone cannot detect a valid suffix removed without a trusted expected endpoint           |
| T17 | Metadata/traffic analysis; headers/logs                    | Infer unit relations, size, timing                | Minimise metadata, access-control logs and retention                                         | This prototype is not anonymous or traffic-analysis resistant                                    |
| T18 | Denial of service; CPU/storage/link                        | Cannot deliver or refresh authority               | Request limits, bounded queues, rate controls, fail closed                                   | Upstream saturation and single-node outages remain                                               |
| T19 | Supply chain; dependencies/build/update                    | Backdoor endpoints/services                       | Pinned dependency provenance, review, reproducible commands, signed release process          | SBOM is inventory, not proof of absence of vulnerabilities                                       |
| T20 | Identity/policy authority unavailable                      | Login/release blocked                             | Durable encrypted pending work; no new permission without authority                          | Availability is deliberately reduced to preserve release safety                                  |
| T21 | Process/DB crash; persistence boundaries                   | Missing evidence, stale state or duplicate effect | Atomic decision/evidence/release transaction, rollback, restart/dedup tests                  | Corrupt disks, backup loss and disaster recovery require separate exercises                      |

## Four mandatory abuse cases

1. An unauthorised principal directly requests a valid object's identifier: deny without returning usable content/key material.
2. A device revoked during isolation returns with an authentic backlog: reject its authority; preserve pending data without release.
3. A relay modifies or replays a signed object: altered context fails; retry cannot create a second application effect.
4. Policy changes after admission but before release: invalidate the stale decision and re-evaluate or hold; no stale release record.

Tests must exercise the actual mutation/release API. A mock that asserts a helper returned `false` is not sufficient integration evidence.

## Failure semantics

Unknown/revoked identity or device → DENY. Unknown policy or unavailable authority → HOLD. Old epoch → re-evaluate/HOLD. Invalid signature/context → REJECT. Network outage → encrypted PENDING. Restart → recover durable state and recheck unsent release. Clock uncertainty → suspend affected grants. No exception may silently become ALLOW to improve a demonstration.

## Review and external assurance

Record configuration, attacker capability, expected result, actual result and evidence for every test. Distinguish simulated network faults from real bearer tests and software possession from hardware attestation. Production review must cover TLS provisioning, OS hardening, backup/restore, operator access, dependency vulnerabilities, key rotation/recovery, malicious-file handling, independent audit and the sponsor's SAG/QA route.
