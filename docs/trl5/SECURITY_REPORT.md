# TRL 5 advancement security report

Run `1348b86` (clean), three-namespace environment. This is an applicant self-assessment, not a
penetration test, independent assessment or accreditation.

## Properties exercised across host boundaries

| Property                                                 | Tests            | Result | Evidence                                                                                     |
| -------------------------------------------------------- | ---------------- | ------ | -------------------------------------------------------------------------------------------- |
| Mutual authentication: password + TOTP + device proof    | T1.1, T1.2       | Held   | Wrong OTP 401                                                                                |
| TLS trust anchoring and hostname verification            | T1.3             | Held   | Foreign CA refused; every client verified `DNS:web` against the lab CA                       |
| Plaintext only at endpoints                              | T1.6             | Held   | 0 of 101 Host B files contain any 64-byte window of either plaintext, raw, hex or base64     |
| Concealment from unauthorised parties                    | T1.5             | Held   | 404 `OBJECT_NOT_FOUND`                                                                       |
| Release only under current policy                        | T2.1, T2.4       | Held   | 409 `POLICY_DENIED` with signed HELD; stale epoch 409 `EPOCH_MISMATCH`                       |
| Revocation committed first blocks issuance               | T2.2, T2.3, T6.2 | Held   | 0 issuances at a withdrawn epoch in 20 races (both commit orders observed); revoked user 401 |
| Idempotent, non-duplicating submission                   | T2.5, T4.2, T4.6 | Held   | Exactly one `SUBMITTED` per object                                                           |
| Interface integrity: replay, destination, source pinning | T4.3–T4.5        | Held   | 409; `ADAPTER_REJECTED`; `SOURCE_NOT_AUTHENTICATED`                                          |
| Independent, content-free security telemetry             | T5.1, T5.2       | Held   | 4 event kinds at the collector in 377 ms; operator-only access (403 otherwise)               |
| Fail closed on relay loss, no partial state              | T5.3             | Held   | 503 `RELAY_UNAVAILABLE`, object count unchanged                                              |
| Tamper-evident evidence, two independent verifiers       | T5.4, T7.3       | Held   | Node and Rust ACCEPT the genuine chain and REJECT a tampered one, offline on Host C          |
| Rollback detection                                       | T6.1             | Held   | Older DB: 503 `RECOVERY_QUARANTINED` on every protected request                              |
| Signed, tamper-evident installation                      | T7.2             | Held   | Appended and same-length tampers both refused                                                |
| No external dependency at run time                       | T7.1             | Held   | No host can reach the outside network; the full workflow ran                                 |

## Isolation checks in the topology

- **Unit hosts reach only the gateway.** They have no address on, or route to, Host B's loopback,
  where control, relay, custodian and collector listen.
- **A and C share no link.** Host A has no link to Host C, and C has no link to A.
- **Location of private keys.** Recipient private keys exist only in Host C's state; sender private
  keys only in Host A's.
- **Logs.** Service logs carry request IDs, methods, status and latency only
  (`evidence/1348b86/logs/`). They were scanned for JWK private members, PEM keys, TOTP secrets,
  passwords and bearer tokens, with no match.

## Findings

| ID      | Severity (applicant)  | Finding                                                                                                                                                                                                                                                                                | Status                            |
| ------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| P-1     | Low                   | Relay unavailability returned HTTP 500. The behaviour failed closed, but it signalled an internal fault rather than a retryable condition                                                                                                                                              | Fixed (503), with regression test |
| D-T5-01 | Medium (availability) | Custody authorisation cost is linear in chain length and serialised (`PERFORMANCE_REPORT.md`). An adversary able to generate evidence, for example with repeated failed requests that create denial records, accelerates the degradation. The rate limits bound but do not remove this | Open; gate G2                     |
| E-1     | Info (environment)    | Profiles were provisioned by the conductor into host state directories, instead of being enrolled on each device                                                                                                                                                                       | Open; gate G6                     |
| E-2     | Info (environment)    | Hosts share one kernel. Kernel-level isolation, side channels and clock independence were not tested                                                                                                                                                                                   | Open; gate G3                     |

The denial-record amplification in D-T5-01 is an inference from the mechanism. It was not
measured as an attack.

## Scans on this branch

| Check                                               | Result on the branch            | Where                                              |
| --------------------------------------------------- | ------------------------------- | -------------------------------------------------- |
| `npm run validate` (incl. lint, security, coverage) | PASS locally before each commit | `artifacts/validation/report.json` (not committed) |
| `npm run test:security`                             | 124/124 locally on e05e1c8 tree | Command output                                     |
| Secret scan (gitleaks), CodeQL, dependency review   | Hosted `Security` workflow      | Reported in the PR for the exact head revision     |

No finding was suppressed, no threshold lowered, and no negative test removed or weakened. Two
assertions were made **stricter** (T1.6 and T6.2).
