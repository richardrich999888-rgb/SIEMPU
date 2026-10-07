# PS-69 requirement ledger

This repository uses **SIEPMU**, the official challenge acronym. `SIEMPU` is the repository slug. SYNTRIASS is the developer. A working demonstration is not evidence of IAF approval, SAG grading or production acceptance.

## Source hierarchy

1. [Official iDEX DISC-14 compendium](https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf), PS-69, printed pages 161–162. Page references below are printed pages. [Official challenge listing](https://idex.gov.in//challenges-cpt/2507).
2. Internal engineering decision report, _SYNTRIASS SIEPMU-69 Research and Architecture_, 7 October 2026, 64 pages; SHA-256 `4cde3ca0f7af9a67cfc0d834048f0c541f7c337b5d0c2a2b693e856f3fe83922`. Its interpretations are not new IAF requirements. The report and submitted application are not copied into this repository.
3. The implementation brief supplied on 8 October 2026 defines prototype acceptance experiments. Its test counts, architecture and outage scenarios are user engineering instructions, not official performance requirements.
4. Source, test output and a frozen commit determine implementation claims. Consult `CLAIMS_REGISTER.yaml` and generated test evidence; the table below defines obligations, not test results.

The original filed AIRON application and exact role/budget commitments require reconciliation with the authoritative submission. Recovered summaries do not establish those details. No classified operating scenario is assumed.

## Explicit published requirements

These are short paraphrases. The final three columns are engineering interpretation.

| ID  | Requirement and source                                           | Meaning / operational purpose                                     | Technical consequence                                                         | Acceptance evidence required                                                                                                  |
| --- | ---------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| R1  | Sensitive inter-unit exchange on public internet; p161           | Authorised units exchange across an untrusted bearer              | Authenticate users, devices and each action; no network-location trust        | Unit A/B text and file exchange; denied third principal                                                                       |
| R2  | Reliability, confidentiality, integrity, authenticity; p161      | Exchange remains usable without silent disclosure or substitution | Authenticated encryption, origin binding, durable pending state and retry     | Tamper tests, recovery, duplicate suppression; stated limits                                                                  |
| R3  | Real-time communication/collaboration; p161                      | Interactive sharing while connected; modalities/SLA unspecified   | Deliver online changes and expose delivery state                              | Measured connected latency; demonstration of text/file workflow                                                               |
| R4  | Cloud-based microservices; p161                                  | Flexible service architecture                                     | Bounded authenticated service interfaces; explicit deployment trust           | Runnable deployment and deployment-boundary review; module boundaries alone do not prove independently deployed microservices |
| R5  | E2EE and MFA; p161                                               | Protect content end to end and strengthen login                   | Endpoint-owned content keys, password plus second factor, defined recovery    | Relay cannot decrypt captured payload; incorrect/replayed MFA denied                                                          |
| R6  | Secure protocols and live monitoring/threat detection; pp161–162 | Protect transport and detect abuse                                | TLS deployment boundary and structured security events                        | Certificate/configuration checks, auth/replay/revocation alerts                                                               |
| R7  | Granular RBAC; p161                                              | Constrain who may perform which actions                           | User, role, unit, resource, action and destination checks at mutation/release | Direct API wrong-role, cross-unit and revoked-principal rejection                                                             |
| R8  | Existing military-system/network integration; pp161–162          | Exchange must fit approved systems                                | Versioned authenticated adapter contract                                      | Synthetic adapter/schema test; IAF interface acceptance still external                                                        |
| R9  | SAG-graded encryption algorithm; p161                            | Specified cryptographic assurance condition                       | Provider abstraction and sponsor-confirmed grading route                      | Actual grading/approval record for exact configuration; **not satisfied by ordinary primitive selection**                     |
| R10 | Secure storage; p162                                             | Protect relay, endpoint cache and backups                         | Ciphertext storage, local vault and protected keys; retention/recovery        | Plaintext absence within stated storage scope, locked-vault tests, key-custody review                                         |
| R11 | Scalability and flexibility; p162                                | Accommodate changing users/needs; numbers unspecified             | Bounded requests/queues and explicit scale profile                            | Measured workload and resource envelope; no invented IAF SLA                                                                  |
| R12 | Applicable QA/certification testing; p162                        | Agency-defined acceptance during development                      | Evidence, traceability and independent review plan                            | Sponsor/agency-approved acceptance matrix; lab tests are not certification                                                    |

The compendium's existing-solution field is not a global novelty conclusion. The public text does not specify classification, user count, file size, latency, device OS, permitted cloud, offline duration or operational C2 interfaces.

## Inferences and prototype decisions

| ID  | Assumption / source                                                 | Prototype treatment                                          | Boundary                                                   |
| --- | ------------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------- |
| I1  | Sovereign operator control; user goal                               | Owner controls deployment, roots, updates and logs           | Does not mean all dependencies are Indian-owned            |
| I2  | Managed device admission; threat-model inference                    | Enrolment, proof of key possession and revocation            | Software key binding is not hardware attestation           |
| I3  | Internet interruption; reliability inference                        | Local encrypted outbox and explicit pending/held states      | Offline creation is not offline permission to deliver      |
| I4  | Current-authority race; engineering experiment                      | Epoch-fenced release with atomic evidence                    | Local authority consistency, not instant global revocation |
| I5  | Six filed military duty-position roles; recovered summary           | Generic demonstrator roles pending authoritative role matrix | Do not invent IAF job authorities                          |
| I6  | Classified content may require stronger handling                    | Synthetic demo content only                                  | No permission to process operational/classified material   |
| I7  | Sender/recipient software and enrolled trust roots behave correctly | Explicit trusted endpoint boundary                           | Compromised reader can disclose plaintext                  |

## Out of the first demonstrator

Air-gap exchange, cross-domain guards, autonomous tactical cloud, Kafka, AI detection, blockchain, PQC as the central product, radio/SATCOM, weapons/C2 integration and a replacement military PKI are not explicit PS-69 requirements. Any later addition needs its own requirement and acceptance evidence.

## Questions requiring sponsor or founder resolution

Record answers and authority in `open-questions.md`; prototype defaults do not close them. Do not make evaluation claims about patents, budget, funding, acceptance, hardware or deployed military interfaces without evidence.
