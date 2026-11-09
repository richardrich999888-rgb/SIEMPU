# P0 041 Evaluation environment and observer instructions

The current executable environment is an applicant laboratory. Separate processes, containers
and Linux network namespaces share a kernel and operator; they do not establish independent
custody or a representative IAF installation. The target below requires nominated hosts and
administrators. No classified data, live government APIs or paid services are used.

| Location                                                    | Required functions                                                                           | Custody and acceptance limit                                                                                            |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Host A                                                      | Sender authentication, local encryption, encrypted outbox, device provider                   | Endpoint controls and permitted hardware/OS must be agreed                                                              |
| Host B                                                      | Policy authority, ciphertext relay, key-release service, telemetry exporter                  | Explicit writer credential; pinned service mTLS; no unrestricted connector plaintext                                    |
| Host C                                                      | Recipient decryption, offline verification, retained audit exports                           | Recipient key separate from A/B; verifier roots/checkpoints independently obtained                                      |
| Independent custody host or separately administered service | Checkpoint anchor, writer generation/floors, signed handover receipts and monitoring custody | Separate administrator and storage required for independent-custody claims; colocating on B is only a lab approximation |

The fourth trust boundary need not mean purchasing a fourth computer: a sponsor-controlled
existing host/service may provide it. Neither tenancy nor administrative independence is available
in this execution session. Actual host identifiers, ownership, patch level, clock service, key
ceremony and network ACL evidence must be added by the testbed owner before witnessed evaluation.

## Reproduction on the frozen candidate

Record `git rev-parse HEAD`, `git rev-parse HEAD^{tree}`, `git status --porcelain`, Node/OpenSSL,
kernel, CPU/RAM and every configuration. Start from a clean checkout, Node 24 and the lockfile.

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run validate
npm run test:e2e
node scripts/interop-assurance.mjs artifacts/interop-assurance
node assurance/iaf/run.mjs artifacts/iaf-adversarial
npm run test:qualification
node assurance/sag/package.mjs artifacts/sag-evaluation
```

Retain the package receipt separately. Run `node assurance/sag/verify.mjs PACKAGE EXPECTED_DIGEST`
using the independently retained manifest digest, then execute the tests from `PACKAGE/source`.
Do not accept a manifest digest obtained only from the archive being checked. Passing integrity
checks authenticate bytes relative to that digest, not the evaluator or an agency decision.

`assurance/qualification/run.mjs` records commands, expected outcomes, actual TAP counts and
all failures for the five demonstrations. Its manifest binds files to commit/tree and SHA-256.
The same-run comparisons use 20 synthetic 4 KiB objects, one serial sender and identical
primitives. The pre-delivered-key reference is a deliberately limited negative control, not
Sandes, SAMVAD or Signal. Additional custody overhead is measured separately. Hardware protection,
maximum throughput, forward secrecy and superiority over those products are not established.

## Network and load campaign

Use the existing `deployment/relevant-env` harness and `npm run trl5:validate` on an isolated
Linux runner with iproute2, namespace permissions, native verifier and kernel netem. Follow
`docs/trl5/ACCEPTANCE_MATRIX.md` and the pinned CI workflow. Namespace names and routing changes
are reserved for this lab; do not run on a production host. The harness records latency/jitter,
1 and 2 Mbit/s profiles, 20-second outage/recovery, concurrency, service interruption, resource
consumption and the unchanged 30-second T8.1 gate: four senders, two workers each, 650 ms offered
interval per session, zero refusals/mismatches/failures and all accepted objects delivered.
Hosted netem adds 1% and 3% packet-loss profiles. Missing kernel support is reported as missing
coverage; a userspace latency proxy does not emulate packet loss.

These are applicant-defined laboratory criteria. IAF workload, scale, end-to-end latency,
availability and recovery thresholds are unknown. A 30-second phase is not a long-duration soak.
Record every refusal; never retry it away, reduce offered traffic silently or loosen thresholds.
Compare only matching source/runtime/workload scopes. Run benchmarks without concurrent local
test campaigns, record sample count and raw data, and retain both failing and passing attempts.

## Observer decision boundary

Review configuration and trust assumptions, reproduce all five demonstrations, inspect the
19-gap register and agree subsequent thresholds. Passing this package supports an engineering
review; TRL 5, SAG grading and operational accreditation require separate documentary decisions.
