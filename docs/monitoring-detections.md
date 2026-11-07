# Signed threat-signal detections

These applicant laboratory rules support PS-69 R6. They are implemented in
`services/monitoring/detections.mjs` inside the independent collector. They do not
inspect message plaintext or decide authorization, and cannot change key-release policy.

Only events from a correctly signed, schema-checked source batch reach the detector.
The collector deduplicates event IDs before correlation. Event insertion, counter changes
and detection creation share one SQLite transaction; a conflict or capacity failure rolls
back all three. The sender receives rejection and its exporter reports degraded delivery.

| Rule                   | Source event   |          Threshold | Window                            |
| ---------------------- | -------------- | -----------------: | --------------------------------- |
| AUTH_FAILURE_SIGNALS   | AUTH_FAILURE   | 5 distinct records | Fixed 60-second event-time bucket |
| ACCESS_DENIAL_SIGNALS  | ACCESS_DENIED  | 3 distinct records | Fixed 60-second event-time bucket |
| RELEASE_DENIAL_SIGNALS | RELEASE_DENIED | 3 distinct records | Fixed 60-second event-time bucket |

Thresholds are proposed laboratory defaults, not IAF incident policy. Windows do not
slide or combine across a boundary. A distributed low-rate attack can evade these rules.
Counts are signals, not unique attempts, people or incidents: the current authority emits
both an evidence record and an alert for one failed login. No identity attribution is inferred.
An authenticated source can still report false facts. These rules cannot detect arbitrary
malware, unknown threats or traffic that never produced or delivered an event.

Each source/rule/window produces at most one immutable signed detection. It records
rule version, threshold, signal count at trigger, event-time range, trigger-event digest,
source-key digest and collector detection time. It does not include credentials, user
identifiers, content or free-form exception text. A signature proves origin and integrity,
not completeness or correctness of the underlying events. The event count is not updated
after emission; later signals still update the durable bucket.

Default ceilings are 32,768 buckets and 10,000 detections. Bucket state survives restarts.
The database is bound to the authority source-key digest and exact rule/window profile.
Changing either, or losing that configuration while stored state remains, refuses startup.
A source-key rotation or rule change requires an explicit reviewed migration; it cannot
silently reuse old counters under a new identity or threshold.
Open and INVESTIGATING detections are retained even past the event retention interval.
Only RESOLVED or FALSE_POSITIVE detections older than that interval are pruned during
ingestion. Full storage rejects the entire new batch; it never silently evicts an open
detection. Old window state is pruned only after the whole window is outside the retention
interval. The existing event retention, export truncation and polling limitations still apply.

The collector's HTTPS/mTLS API adds:

- `GET /v1/detections`: operator identity only; at most 2,000 rows, unacknowledged first,
  then oldest first. Each row contains a signed `detection` and optional signed `ack`.
- `POST /v1/detections/ack`: operator identity only, exact body
  `{detectionId, disposition}`; allowed dispositions are INVESTIGATING, RESOLVED and
  FALSE_POSITIVE. The signed response attributes the action to the authenticated certificate
  fingerprint. A source identity cannot read or acknowledge detections.

The existing `/v1/events` and `/v1/ack` contracts remain unchanged. These are collector
routes, not public gateway routes. See [monitoring.openapi.json](monitoring.openapi.json).
Operators must verify the signed packets using the independently supplied collector key.
This bounded list is not a completeness proof; external SOC integration and full archival
export remain open work. No new alert is an instruction to grant or revoke authority.

`tests/threat-detections.test.mjs` covers real authority failures, threshold boundaries,
forgery/time rejection, replay, restart, transaction rollback, both capacity limits, open
incident retention, signed acknowledgement and actual mTLS access controls. It records
the elapsed synthetic loopback ingest-to-read time with a declared 5-second test budget.
That observation is not an IAF latency SLA or an Internet end-to-end measurement.

Run `npm run test:engineering` or `npm run test:adversarial -- artifacts/NEW_DIRECTORY`.
Full native and hosted results must be associated with the tested commit; no earlier
result is carried forward by this document.
