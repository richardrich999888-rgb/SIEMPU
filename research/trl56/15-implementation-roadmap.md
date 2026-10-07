# Roadmap tied to the filed proposal

Reviewed 8 October 2026. P001 proposes **12 months** and four phases; P003 confirms the 12-month duration. No signed commencement date, grant agreement, approved budget or revised milestone baseline was supplied. Months below are relative project months, not dates computed from the submission receipt. Open Challenge 19's schedule and budget do not apply.

## Preserve commitments and expose dependencies

| Filed window | Applicant-proposed work, paraphrased                                                                         | Engineering packages                                                   | Acceptance boundary                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Months 1–3   | Foundation audit/hardening, cryptographic evaluation preparation, security/threat review                     | WP05–WP14, WP17, WP21; current CI baseline WP01–WP04 already evidenced | Current claims corrected; reproducible lab and scoped evidence; evaluation preparation is not approval       |
| Months 4–6   | Communication adapters, offline deployment, identity federation and compatibility testing                    | WP10, WP15, WP16, WP18, WP19                                           | Independent mock first; actual interfaces, classification boundary and federation depend on sponsor contract |
| Months 7–9   | Nominated field trial, external certification/testing, defensive assessment and operational-load measurement | WP06, WP11, WP20, WP22                                                 | Site, agency, data and acceptance scope must be authorised; no station or assessor presumed available        |
| Months 10–12 | Rollout, training, technical/source handover and support activation                                          | WP19, WP22, after WP20 decision                                        | Sponsor acceptance, licence/support terms, trained operators and funded operations required                  |

The submitted annexure names STQC/BIS activities and a subsequent support period. Those are applicant proposals, not proof that either certification scheme applies or that an agency has accepted the work. Confirm exact scheme, scope, authority and support obligations privately. The technical documents do not establish an approved financial amount.

## Engineering sequence

| Phase                           | Entry and work                                                                           | Rough elapsed planning range               | Exit                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------ | ---------------------------------------------------------------- |
| P0 — baseline and decisions     | Frozen code, proposal reconciliation, CTE/SAG questions                                  | 1–2 weeks; baseline CI work already closed | Reviewed claim register and external-decision log                |
| P1 — relevant laboratory        | TLS/mTLS, unit zones, netem, independent redacted sink                                   | 2–4 weeks                                  | Repeatable authenticated testbed and measured impairment         |
| P2 — CTE experiments            | Checkpoint/rollback, reconnect, provider/roles/mock integration, latency/load            | 3–6 weeks                                  | T5-01–13/TLS-01 evidence with deviations; not self-declared TRL5 |
| P3 — representative engineering | Multi-host operation, conditional hardware, signed offline release and handover planning | 6–12+ weeks                                | Integrated representative candidate; external blockers visible   |
| P4 — witnessed evaluation       | Independent assessment, approved matrix, repeatability and evidence review               | 2–4 weeks plus assessor access             | Signed findings and separate sponsor readiness decision          |
| P5 — qualification/rollout      | Approved grading, interfaces, pilot and operations                                       | External schedule, not estimated here      | Actual acceptance records, not a planning claim                  |

P0–P4 ranges total **14–28+ sequential engineering weeks** before external delays. They assume multiple appropriate engineering roles; they are not an estimate for a single founder doing all work. The [backlog](integration-backlog.csv) instead records rough **person-days per package**. Do not add person-days to elapsed weeks or present either as a funded staffing commitment. Where a field-trial milestone depends on unavailable agency access, raise a schedule change; do not quietly relabel a synthetic demo as a field trial.

## Immediate execution order

1. WP05: use the reviewed annexures to correct the HPSC capability table and obtain owner decisions on differences. Keep originals unchanged.
2. WP06/WP11: prepare sponsor questions in parallel with engineering because approval and interface access can dominate lead time. No messages have been sent by this work.
3. WP07 → WP08 → WP09: implement secure transport, separate trust zones and reproducible impairment.
4. WP12 → WP13 → WP14: prove independent evidence custody, safe restore and controlled reconnect.
5. WP16/WP17/WP21 and then WP18: qualify integration, monitoring, role policy and the measured workload.
6. WP19 → WP20, with WP15 conditional: create the reviewable representative candidate and seek witnessed acceptance.

The current ten-minute prototype demonstration remains evidence of its recorded capabilities. It does not have to wait for every proposed TRL5/6 work package, and it must not be presented as their completed result.
