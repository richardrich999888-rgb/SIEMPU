# Known limitations and release gates

Current status is **PROTOTYPE with measured engineering tests**, not production-ready or externally assured.

- No SAG grading, IAF acceptance/deployment, classified-data authorisation, live AFNET integration, independent penetration test or patentability conclusion.
- Three processes share one host; SQLite authority has one serialised writer. No horizontal HA, multi-region consistency or proven fleet-scale capacity.
- Default local HTTP is not internet-ready TLS. Approved ingress, certificate lifecycle, service TLS and operational hosting remain deployment work.
- Software device keys are not hardware attestation/custody. Compromised endpoints, trusted authority, key directory or client distribution can defeat controls. Static recipient keys lack forward secrecy.
- Released keys/plaintext cannot be recalled. Revocation protects subsequent issuance/redisclosure; it does not make disconnected endpoints instantly aware.
- Identity/routing metadata remain visible; the directory exposes active users/devices to bound users. Traffic-analysis resistance is not implemented.
- No production IdP/PKI adapter, endpoint key rotation/escrow, self-service recovery, approved military duty-role matrix or multi-admin approval ceremony. Offline administrator password/MFA recovery is implemented and tested.
- File validation is not malware scanning/sanitisation. The browser file-download journey remains outside the recorded run; a subsequent actual browser run exercised fresh enrollment/approval, substituted enrollment-key rejection and stale-tab concurrency.
- No offline peer delivery, air-gap media transfer, cross-domain guard, tactical cloud, AI detector, PQC suite or Kafka dependency.
- Restore is tested on synthetic local state; whole-database anti-rollback needs independent checkpoints and authority revalidation. Historic storage retention/compaction and disaster recovery require an operator policy.
- Type checking currently covers relay authentication/client modules; full JavaScript source is syntax/lint checked but not all statically typed.
- Observability has structured logs, alerts and counters; no distributed-trace collector, SIEM integration or measured anomaly-model efficacy.
- The sequential loopback benchmark does not establish WAN performance, maximum capacity, large files/fanout or server resource cost. No professional prior-art/FTO review.

Current CI, container and scan execution evidence is separate from source configuration. Consult the exact commit's Actions run and [evidence index](hpsc/evidence-index.md); a pending/failed job is not a pass.
