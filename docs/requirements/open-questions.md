# External decisions still required

These do not prevent a synthetic lab demonstration. They gate operational deployment or external claims.

| ID  | Question                                                                                   | Decision owner                     | Current engineering posture                                                                               |
| --- | ------------------------------------------------------------------------------------------ | ---------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Q01 | Which classifications and releasability rules may cross this service?                      | IAF sponsor/security authority     | Synthetic, non-operational content only                                                                   |
| Q02 | Which users, units, roles, OSs and communication modes are required?                       | IAF sponsor                        | Generic lab roles; text and file workflows                                                                |
| Q03 | Which hosting, administration and support-access model is approved?                        | IAF/hosting authority              | Operator-controlled lab deployment                                                                        |
| Q04 | Which SAG grading route, provider interface and approved suites apply?                     | Sponsor/cryptographic authority    | Standard library provider; no SAG claim                                                                   |
| Q05 | Which identity, PKI, recovery and device-management interfaces apply?                      | IAF identity authority             | Locally enrolled demonstration identities                                                                 |
| Q06 | Which existing military endpoint/schema is available for integration?                      | Integration owner                  | Authenticated synthetic adapter only                                                                      |
| Q07 | Which concurrency, latency, file-size, retention and outage envelope must pass?            | Sponsor/QA authority               | Measured lab profile; no official SLA claimed                                                             |
| Q08 | Is offline creation/viewing allowed; for how long and under whose delegation?              | Information owner                  | Bounded local operation; fresh server release required                                                    |
| Q09 | Is server-side plaintext inspection mandatory?                                             | Security authority                 | Endpoint E2EE; introducing an inspection endpoint changes the boundary                                    |
| Q10 | What is the exact filed AIRON role/component/budget commitment?                            | SYNTRIASS proposal owner           | Annexures reviewed; filed scope deviations, portal record and budget still need owner/sponsor decisions   |
| Q11 | Which QA agencies, evidence formats and certification gates apply?                         | Sponsor/QA authority               | Reproducible engineering evidence only                                                                    |
| Q12 | Which assets can be public; who owns imported code and inventions?                         | SYNTRIASS ownership/legal decision | Clean implementation; no private source import                                                            |
| Q13 | What exact HPSC slot, deadline, budget and matching-funds evidence apply?                  | SYNTRIASS and HPSC coordinator     | HPSC presentation fixed by the founder for Tuesday 13 October 2026; financial evidence remains open       |
| Q14 | What relevant environment (network, outage, interfaces, scale, acceptance) defines TRL 5?  | IAF sponsor/QA authority           | No element claimed above provisional TRL 4 (`docs/trl/TRL_ASSESSMENT.md`)                                 |
| Q15 | How is SAG grading requested, by whom, against which configuration, and on what timeline?  | Sponsor/DRDO SAG                   | No official public procedure found (search 2026-10-08, `research/hpsc/idex-grant-rules.md`)               |
| Q16 | Which Indian cryptographic provider and interface (PKCS#11, SDK, appliance) is acceptable? | Sponsor/cryptographic authority    | Provider port is interface-neutral; no Indian vendor publishes an integration interface (research record) |

For each resolution append: date, answer, approving authority, source reference, affected requirement/ADR, change and regression-test evidence. An engineer's assumption is not sponsor acceptance.
