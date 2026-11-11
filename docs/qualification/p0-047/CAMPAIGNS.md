# D3–D5: predeclared experiment and failure-injection protocol

All workloads use synthetic, non-classified accounts and documents. Source is frozen before
measurement. Each report binds commit/tree, runtime, scenario and raw samples. Overall
P0-047 independent-host validation is blocked if hosts or mandatory experiments are missing.
Local support for a hypothesis never changes an unexecuted external result to PASS.

Common controls: same source/lockfile, P-256/HKDF-SHA256/AES256-GCM profile, TLS 1.3,
fixed node placement, single concurrent exchange, dedicated synthetic state, no production
keys. Repeat each security scenario on three fresh deployments for external acceptance.
The current local runner executes functional scenarios once and NET-10 three times;
this distinction must remain in the report. Every exception records a FAIL and later
campaigns continue where safe; prerequisite failure is recorded as a runner failure.

| Campaign / hypothesis                                         | Variable and workload                                                                            | Acceptance / method                                                                                        | Current automation and missing evidence                                                                                     |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| NET-01: intended recipient decrypts authentic content         | 64-byte text, A→E through B/C                                                                    | Exact hash, authority-signed release and delivery ACK; zero mismatches                                     | Actual SDK campaign; full managed companion and distinct-host repetitions required                                          |
| NET-02: encrypted supported file survives transport           | 256 KiB synthetic binary                                                                         | Exact bytes/hash and ACK; no plaintext on relay                                                            | Actual SDK campaign; native inspection is a separate required profile                                                       |
| NET-03: revocation precedes a denied fresh release            | Submit ciphertext, prepare claim proof, await recipient-device revocation response, submit claim | 401/403 denial; record request/response times and reason                                                   | Actual current-policy path. Prior plaintext and released keys cannot be recalled                                            |
| NET-04: relay role lacks decryption inputs                    | Controlled C filesystem/schema/ciphertext copy                                                   | Verify blob hashes; inspect role allowlist and absence of endpoint/master keys                             | Local mount inspection only. Absence of a canary is not cryptographic proof; root/admin and metadata are outside this claim |
| NET-05: queue survives interruption without duplicate objects | Existing encrypted ManagedOutbox; endpoint process restart; duplicate submit                     | Original object/hash retained; identical retry returns original receipt and only one object; bounded retry | Local queue/restart/idempotent retry test; CORE/Mininet link outage passed on the recorded predecessor; exact-head results retained separately                              |
| NET-06: authority outage denies unsafe work                   | Stop B control, try queued submit and protected access                                           | 503 refusal; no claim of automatic HA; manually restart and recheck                                        | Local process hook; remote operator/host failure evidence missing                                                           |
| NET-07: conflicting writers cannot release                    | Partition B/F, attempt old/new generation operations                                             | At most approved current writer succeeds; preserve denial and custody receipts                             | Existing `writer-fencing.test.mjs`/guarded recovery are local; independent-host split-brain BLOCKED                         |
| NET-08: unsafe recovery cannot activate                       | Valid/corrupt/divergent/missing-checkpoint/stale-policy/altered-ciphertext snapshots             | Reject before activation; valid reviewed snapshot obtains fresh lease                                      | Existing `recovery-stores`, `legacy-migration`, `guarded-recovery` suites and rehearsal; multi-host recovery BLOCKED        |
| NET-09: a separate reviewer verifies evidence                 | Source package, signed event chain and independent checkpoint                                    | All hashes, signatures, continuity and source bindings pass using independent trust roots                  | Existing Node verifier and package verifier available; external custodian/evaluator BLOCKED                                 |
| NET-10: overhead is measured under fixed work                 | 3 repetitions × 10 × 4 KiB; concurrency 1                                                        | All 30 exchanges/ACKs succeed; zero mismatches; retain every duration/error/resource sample                | Short applicant measurement only; sustained-load/endurance BLOCKED                                                          |
| NET-11: hardware lifecycle preserves guarantees               | Physical token removal/reboot/expiry/rollover/loss                                               | Declared denial/recovery outcomes on named serial/device/firmware                                          | Native driver uses real provider; physical token and approved lifecycle profile BLOCKED                                     |
| NET-12: evaluator independently reproduces                    | Frozen source on independently administered environment                                          | Evaluator-signed result plus raw deviations and separately retained digest                                 | Instructions available; evaluator allocation BLOCKED                                                                        |

## Statistical and endurance discipline

`benchmarkProtocol` is committed before measurement. Timings use a monotonic clock from
sender process start to recipient ACK process exit, including subprocess overhead; SSH
adds control-plane overhead on remote runs. Report individual repetition throughput and
all raw samples. p50 is descriptive; p95 requires at least 20 samples; p99 is suppressed
below 1000 samples. Three repetitions within one deployment are not three independent
environments. There is no equivalent-hardware comparator yet, no confidence interval for
tails and no production latency/RTO claim. Do not combine emulation and local timings.

Before an authorised endurance trial, approve a new immutable profile: 60 minutes at
0.5 objects/s, 4 KiB, concurrency 1, three fresh trials; collect queue/disk/CPU/RSS every
10 seconds, failures and rate-limit refusals as outcomes. The maintenance archive is
bounded to 32 MiB decoded, so project full-state growth before selecting a longer run.
Stop before 80% of dedicated disk or repeated resource-limit violations. Do not evict
unacknowledged objects or raise bounds merely to pass. This profile is proposed and not
implemented as a successful endurance run in this increment.

## Adversarial coverage and exact residuals

| Family                                                                              | Reused actual tests / adapter                                           | External requirement                                                                             |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Loss, jitter, duplication, reordering, outage                                       | CORE/Mininet netem profiles and observed counters                       | Privileged dedicated host; confirm applied qdisc and nonzero counters                            |
| DNS failure / TLS failure / certificate expiry                                      | Existing transport/routing tests; no live DNS manipulation here         | Authorised isolated resolver and certificate rotation experiment                                 |
| Expired session / revoked device / credentials / role / mission                     | Authority, renewal, filed-mission and adversarial families              | Sponsor identity policy and representative endpoint                                              |
| Stale/concurrent writer / lost handover reply / rollback / lost custody             | Writer-fencing, authority-state-custody and guarded-recovery suites     | Independent storage and manual custody operator; clone protection remains outside software fence |
| Corrupt database / incomplete backup / missing ciphertext / interrupted publication | Recovery-stores and guarded recovery, including real SIGKILL boundaries | Host/storage failure and power-loss experiments                                                  |
| Disk exhaustion / clock skew / host reboot / partial recovery                       | Existing bounded-store/clock-denial tests where present                 | PR46 adds real SQLite capacity exhaustion and injected ENOSPC/EIO tests; physical disk exhaustion, skewed host clock and host reboot remain blocked               |

Original failing reproduction: merge candidate `f26cbe9`, unchanged recovery tests.
Two error-name mismatches caused a failing family. Fix commit `11f53a6` preserves early
rejection and all assertions. No cryptographic algorithm, release policy, dependency,
timeout or acceptance threshold was relaxed. Additional hardware, privileged namespace,
external-evaluator and independent-host failures are BLOCKED dependencies, not passes.
