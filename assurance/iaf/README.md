# IAF qualification preparation and adversarial laboratory campaign

Target: TRL 8. Current repository self-assessment remains provisional TRL 4; formal
qualification, sponsor acceptance and operational authorization are not established.
This is an applicant test plan for synthetic data, not an IAF-prescribed test profile.

`plan.json` maps nine adversarial test families to all twelve PS-69 requirements and
records nineteen open implementation/design/evaluation gaps with owners and exit evidence.
The definitive human review plan is [TRL8_QUALIFICATION.md](../../docs/trl/TRL8_QUALIFICATION.md).

On a clean committed candidate:

```sh
npm ci --ignore-scripts
npm run validate
npm run test:e2e
npm run test:adversarial -- artifacts/iaf-adversarial
```

Use a new output directory on every execution. The runner executes the named test files
sequentially in isolated child processes; it does not infer results from prior CI. Each
family has an expected security result, actual test counts, exit status, timestamps and
a redacted log hash. Failed, cancelled, skipped, missing or duplicate test summaries fail
the campaign. A per-family 180-second deadline and 1 MiB log bound terminate that family;
on Linux, termination targets its own child process group. A failed family does not
suppress the remaining tests. Source changes during execution fail the campaign.

`report.json` identifies the actual Git commit/tree and full-source fingerprint. Keep it
with the corresponding source/build package and exact-candidate hosted browser, container,
Rust/NEXORA, formal and network artifacts. The report is applicant-authored, unsigned
execution evidence. Its `outcome` is the test outcome; `qualification` always remains
`NOT_ESTABLISHED` and `assignedTrl` remains null. Filling references or obtaining green
software tests cannot establish an external qualification decision.

Tests use synthetic credentials and temporary local services only. They do not attack an
IAF host or collect operational information. Log redaction is limited pattern filtering;
review all artifacts and follow the agreed handling channel before external handover.

## Implemented adapter protections

- Default maximum pending submissions: 32, including the active request. Operator override
  `SIEPMU_ADAPTER_MAX_PENDING` accepts integers 1–1024. These are laboratory defaults,
  not an IAF capacity specification. Excess traffic receives HTTP 503 `ADAPTER_BUSY`
  with `Retry-After: 1`; replay records are never evicted to free capacity.
- Queued requests are snapshotted after validation and freshness is rechecked before
  sealing. Failure releases the queue slot while retaining ambiguous durable work.
- `GET /ready` requires the adapter's permitted mTLS source identity, a usable database,
  spare queue capacity and a fresh verified authority response for the current session.
  Expired/revoked credentials or an unavailable authority yield 503, never healthy status.
- Failed SDK authentication clears previous and partially created local session state.
- Startup diagnostics contain only a known stage, allowlisted code and numeric HTTP status.
  The lab supervisor verifies the readiness contract, bounds probes/logs, retains the safe
  diagnostic on failure and bounds shutdown. It never echoes the upstream exception body.

## Boundary that remains open

The synthetic document adapter is a managed encryption endpoint: it receives plaintext
from the source DMS and owns that sender's software credentials and keys. The source DMS
outbox also persists its plaintext request. This differs from an untrusted connector that
forwards ciphertext only. `ADV-ADAPTER-11` deliberately observes this boundary and leaves
`IAF-G05` open. Put this demonstrator only inside a synthetic trusted endpoint zone.
A production integration must use the sponsor-defined interface and endpoint placement;
if the connector is untrusted, sealing and key custody must move to the originating system.

Availability after credential expiry, aggregate connection quotas, actual hardware custody,
HA/failover and independent qualification remain explicit work. The old unexplained
`ADAPTER_EXITED` observation is not declared fixed merely because new diagnostics exist.
