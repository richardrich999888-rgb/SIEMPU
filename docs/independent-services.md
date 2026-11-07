# Independent services and trust boundaries

The checkpoint custodian, monitoring collector, and synthetic integration adapter are separate processes with separate databases and identity material.

The checkpoint custodian accepts only a signed authority evidence chain and authorization-state digest over mutual TLS. It retains a monotonic head and refuses a validly signed but older or forked database. The control service enters recovery quarantine when the custodian cannot establish a current lease.

The collector accepts an allowlisted signed event schema. Events contain event type, time, epoch, correlation digest and a bounded reason. It does not receive object plaintext, private keys, passwords, TOTP seeds, ciphertext or wrapped keys. Batch replay is idempotent, conflicts are rejected, retention is bounded, and acknowledgements are signed.

The adapter is an independent synthetic endpoint. It authenticates to the platform, validates a versioned request, binds the sender and destination to its own configured identities, rejects stale or duplicate requests, encrypts content through the platform provider, and stores only its own request/result record. It does not represent an IAF legacy protocol or a military network integration.

## Adapter availability and boundary

The synthetic adapter is a trusted plaintext encryption endpoint; its source outbox
retains plaintext requests. It is not a ciphertext-only intermediary. Production
endpoint placement remains an open design decision (IAF-G05).

Pending submissions are bounded (default 32; `SIEPMU_ADAPTER_MAX_PENDING` 1–1024).
Overflow returns 503 `ADAPTER_BUSY` and `Retry-After: 1`. Durable idempotency records
are never evicted for capacity. Queued request bytes are snapshotted and their freshness
is rechecked before sealing. `GET /ready` is protected by the same mTLS source pin
and returns 200 only when database, queue and freshly authenticated authority state
are usable; failure yields 503. This does not qualify the service for any IAF SLA.

Startup failures emit a redacted `ADAPTER_STARTUP_FAILED` stage/code/status record.
The lab helper rejects ordinary 404/503 responses as readiness and bounds shutdown.
Session expiration withdraws readiness; supervised credential renewal remains open.

## Threat-signal detection

The independent collector now correlates distinct authenticated failure records into
persistent signed detections, with fixed laboratory thresholds, bounded storage and
operator-only acknowledgement. Open investigations are retained; exhausted capacity
rejects the complete ingest transaction. See [behavior and limits](monitoring-detections.md)
and the [collector API extension](monitoring.openapi.json). No content inspection or
authorization decision is delegated to the detector.
