# TRL 5/6 verification matrix

Generated from `trl5-test-matrix.csv` by `python3 research/trl56/validate.py --write-views`. Edit the CSV, then regenerate this view.

Only CI-01 records observed frozen prototype evidence. Every other row remains planned, unengaged or externally blocked. Numerical thresholds are provisional lab targets, not IAF SLAs. A row mapping to R9 cannot replace SAG-01's external approval.

| Test   | Requirements | CTEs                                                  | Owner role                      | Work packages            | Status                    |
| ------ | ------------ | ----------------------------------------------------- | ------------------------------- | ------------------------ | ------------------------- |
| T5-01  | R1 R2 R5 R7  | CTE01 CTE02 CTE03 CTE04                               | Crypto and endpoint QA          | WP07 WP14                | PLANNED                   |
| T5-02  | R2 R10       | CTE03 CTE05                                           | Network QA                      | WP09 WP14                | PLANNED                   |
| T5-03  | R5 R7        | CTE02 CTE03                                           | Security QA                     | WP14                     | PLANNED                   |
| T5-04  | R6           | CTE07                                                 | SOC QA                          | WP17                     | PLANNED                   |
| T5-05  | R2 R5 R10    | CTE01 CTE02 CTE05                                     | Endpoint QA                     | WP14 WP15                | PLANNED                   |
| T5-06  | R8           | CTE08                                                 | Integration QA                  | WP16                     | PLANNED                   |
| T5-07  | R2 R10 R12   | CTE06                                                 | Evidence QA                     | WP12 WP13                | PLANNED                   |
| T5-08  | R6 R12       | CTE01 CTE02 CTE03 CTE04 CTE05 CTE06 CTE07 CTE08 CTE09 | Independent assessor            | WP06 WP20 WP22           | NOT_ENGAGED               |
| TLS-01 | R1 R5 R6     | CTE02 CTE04                                           | Deployment security             | WP07                     | PLANNED                   |
| SAG-01 | R9           | CTE09                                                 | Sponsor cryptographic authority | WP05 WP11 WP20           | EXTERNAL_BLOCKED          |
| CI-01  | R12          | CTE01 CTE02 CTE03 CTE04 CTE05 CTE06 CTE07 CTE08 CTE09 | DevSecOps                       | WP01 WP02 WP03 WP04 WP19 | EVIDENCED_FROZEN_BASELINE |
| T5-09  | R3           | CTE04 CTE05                                           | Performance QA                  | WP09 WP18                | PLANNED                   |
| T5-10  | R4           | CTE04                                                 | Systems QA                      | WP08 WP18 WP19           | PLANNED                   |
| T5-11  | R11          | CTE03 CTE04 CTE05                                     | Performance QA                  | WP09 WP18                | PLANNED                   |
| T5-12  | R2 R5 R9 R10 | CTE01 CTE02 CTE09                                     | Crypto QA                       | WP10 WP15                | PLANNED                   |
| T5-13  | R7           | CTE02 CTE03                                           | Authorization QA                | WP05 WP21                | PLANNED                   |
| INT-01 | R2 R5 R7 R12 | CTE01 CTE02 CTE03 CTE06                               | Integration security QA         | WP23                     | PLANNED                   |

## T5-01 — Multi-unit E2EE

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Two unit zones; third unauthorised principal; text and file exchange; capture relay/transport; tamper context and recipient.

Acceptance: 30 authorised text/file pairs per run x 3 runs: exact digests; 30 denied/tampered cases per run: zero new key issuances or plaintext delivery; inspected wire/storage contains no seeded plaintext.

Required evidence: Captures; plaintext-canary scan; ciphertext digests; issuance receipts; endpoint verification.

## T5-02 — WAN outage and retry

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: N0-N5 and N8; 30-minute isolation within configured lease; 100 repeated requests for each tested issuance ID; restart during queued transfer.

Acceptance: 3 repetitions/profile; zero duplicate issuance/evidence; exact file bytes after allowed reconnect; zero new release while authority unavailable; queue limits and HOLD reason visible.

Required evidence: qdisc/settings and observations; retry IDs; queue/vault records; exact bytes and receipts.

## T5-03 — Revocation at release boundary

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Revoke before commit; race revoke with issue; revoke after successful commit; reconnect with stale grant.

Acceptance: 100 schedules/order x 3 runs; zero issuance when revocation commits first; concurrent outcome matches transaction order; post-issue plaintext recall explicitly unsupported.

Required evidence: Epoch/grant/transaction order and signed receipts; no secrets.

## T5-04 — Defensive alert and redaction

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: 20 events each: failed MFA, replay and wrong-role request; independently consume allowlisted events; inject secret/plaintext canaries.

Acceptance: All 60 seeded events observable; p95 alert delivery <=5 s under N0; zero seeded secrets/plaintext in exported logs; operator records response.

Required evidence: Event timestamps; sink capture; redaction scan; triage record.

## T5-05 — Endpoint lock and recovery

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Lock/reload offline; wrong unlock secret; local credential loss; device revoke; two browser tabs; later optional hardware removal.

Acceptance: 10 repetitions/scenario; locked vault exposes no plaintext via application; persistent outbox survives restart; fresh server authentication before new issuance; explain that already-issued keys remain usable by compromised unlocked endpoint.

Required evidence: Browser/OS inventory; vault inspection; loss/recovery transcript; hardware tests conditional.

## T5-06 — Independent mock connector

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Independent process/keys; authorised valid request then wrong-source, bad schema/signature, stale grant and duplicate request.

Acceptance: 30 valid envelopes accepted once; 30/case invalid inputs rejected without new issuance; duplicates idempotent; connector cannot self-authorise.

Required evidence: Contract version; separate process/network manifest; auth/schema/replay results.

## T5-07 — Checkpoint and rollback recovery

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Export checkpoint to separate custodian; revoke, independently retain the post-revocation checkpoint, then restore older DB; corrupt receipt; remove checkpoint; isolate verifier.

Acceptance: 10 repetitions/case; tampering rejected; restored state behind trusted checkpoint quarantined before new issuance; missing checkpoint fails closed; checkpoint-age blind interval documented.

Required evidence: Independent checkpoint/root; verifier outputs; restore transaction trace; custodian receipt.

## T5-08 — Independent defensive assessment

Basis: **ASSESSOR_AND_SPONSOR_DECISION**. Status: **NOT_ENGAGED**.

Procedure: Authorised scope and relevant environment agreed; review protocol, clients, services and evidence; remediation retest.

Acceptance: Signed scoped findings; zero unresolved HIGH/CRITICAL findings for advancement; scope omissions remain BLOCKED; sponsor acceptance recorded separately.

Required evidence: Engagement scope; signed report; remediation evidence; sponsor decision.

## TLS-01 — TLS and service identity

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: TLS ingress and mTLS internal untrusted hops; wrong CA/hostname/client identity, expired/revoked cert; certificate rotation; DNS redirect.

Acceptance: 20 attempts/negative case rejected before credentials or new wrapped key; 20 authorised exchanges before/after rotation pass; no HTTP downgrade; TLS minimum/version policy logged.

Required evidence: Certificate chain inventory; handshake logs; captures; rotation/revocation and fallback outcomes.

## SAG-01 — Graded cryptographic approval

Basis: **EXTERNAL_APPROVAL**. Status: **EXTERNAL_BLOCKED**.

Procedure: Confirm exact algorithm, provider, configuration, lifecycle and evaluation path with authorised authority.

Acceptance: Attributable approval record covers exact deployed configuration and permitted use; software KAT pass alone cannot close this row.

Required evidence: Private authority record; public decision identifier/status only.

## CI-01 — Frozen candidate CI gate

Basis: **OBSERVED_FROZEN_BUILD**. Status: **EVIDENCED_FROZEN_BASELINE**.

Procedure: Run native/browser/container/secrets/CodeQL and gated packager at immutable candidate; bind reports to source digest.

Acceptance: Six jobs success at frozen baseline; 87 native tests, 9 demo stages, 15 browser checks and 14 source-bound claims; future candidate must rerun; no TRL/CTE09 approval implied.

Required evidence: baseline-evidence.json and E004; new candidate hosted artifacts required.

## T5-09 — Connected latency

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Timestamp send to verified recipient availability using one measurement driver clock; 1000 4KiB objects under N0 and N1; record polling and ACK semantics.

Acceptance: 3 runs/profile; provisional p95 <=5 s N0 and <=10 s N1; report p50/p95/p99 and errors; no omitted timeouts; failure prompts redesign or sponsor-approved target revision.

Required evidence: Raw monotonic timings; workload definition; percentile script; machine/link/polling inventory.

## T5-10 — Deployment isolation

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Separate gateway/control/relay processes and independent storage; control/relay on separate nodes; isolate admin; restart each; later offline installation.

Acceptance: 3 clean deployments; interfaces authenticate; 10 restarts/service produce no unauthorised issuance or silent corruption; independent-node inventory; offline install requires WP19 completion.

Required evidence: Build and configuration hashes; topology; health and restart logs; offline install transcript when implemented.

## T5-11 — Capacity and bounds

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: 10/50/100 concurrent synthetic sessions, 15 min each x3; 4KiB texts and 256KiB attachments; fixed 4vCPU/8GiB service node budget recorded; oversize and queue exhaustion tests.

Acceptance: N0 provisional successful authorised requests >=99%, p95 <=5 s at 50 sessions; max service RSS <=75% host RAM; no silent loss/unauthorised issuance; report saturation at 100 even if failing; bounds return explicit errors.

Required evidence: Raw load/error/CPU/RSS/queue records; payload and fanout distribution; actual hardware; limit responses.

## T5-12 — Provider conformance without grading claim

Basis: **PROVISIONAL_LAB_TARGET**. Status: **PLANNED**.

Procedure: Conformance vectors and independent implementation comparison; wrong suite/downgrade/absent key/provider outage; optional software token comparison.

Acceptance: All declared vectors agree and all negative cases reject; private handles obey configured export rules; zero fallback on provider failure; SoftHSM is software-only and SAG-01 stays separate.

Required evidence: Versioned provider contract; vectors and results; mechanism/export matrix.

## T5-13 — Filed roles and priority constraints

Basis: **APPLICANT_SCOPE_PENDING_SPONSOR**. Status: **PLANNED**.

Procedure: Freeze owner-approved six-role/four-priority matrix; exercise every pair via direct API; cross-unit, role change and revoke after enqueue.

Acceptance: All 24 role-priority pairs match matrix for each applicable action; unspecified grants deny; UI hiding alone never passes; no new issuance after committed role removal; audit-reader rights do not imply unrestricted content decryption; highest-priority release requires separately defined authorization action, not just write eligibility.

Required evidence: Approved matrix; direct API and issue-time tests; privilege-review record.

## INT-01 — Combined branch security regression

Basis: **ENGINEERING_INTEGRATION_GATE**. Status: **PLANNED**.

Procedure: Combine versioned priority context with strict persisted-envelope revalidation, richer decision evidence, verifier and replacement CI; exercise both versions and role-change-at-release cases.

Acceptance: Valid authorised v1/v2 cases pass; signed-field mutation, stored DB substitution and version downgrade reject; priority-denied metadata probes reject; epoch/issuance/evidence atomicity unchanged; all combined native/browser/container/security/research gates pass on one SHA.

Required evidence: Combined tree/source digests; v1/v2 compatibility matrix; negative outcomes; full hosted jobs; migration/recovery results.

## Review sequence

Engineer records actual outcome and hashes; test lead verifies repeatability; independent reviewer assesses scope and findings; sponsor or authorised agency makes the acceptance/readiness decision. No unexecuted row may be labelled PASS.
