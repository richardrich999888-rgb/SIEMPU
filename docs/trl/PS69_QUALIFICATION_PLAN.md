# AIRON–SIEPMU: PS-69 qualification path

7 November 2026. Engineering base: `09b18103268603b35a9801b2679fa589bf54160c`.
This is an execution plan. It does not assign TRL 8 or establish operational approval.

## Mission and delivery boundary

Authorized IAF personnel exchange protected messages and documents over an
untrusted public network. Endpoint encryption, approved devices, MFA, current duty
and mission permissions, controlled key release, revocation and independently
retained evidence remain central. Public Internet transport does not imply public
registration or public access to data.

Use operator-controlled gateway, authority, ciphertext relay, independent custody
and monitoring services. Keep endpoint private keys and plaintext at endpoints.
A managed service needs a sponsor-approved hosting/administration model, ingress,
PKI and operational support. A public web-hosting URL alone cannot provide these.
Offline queueing and local installation remain supported engineering goals alongside
connected operation; cross-domain/physical transfer needs its own agreed procedure.

## Exit evidence by stage

| Stage                                     | Work and acceptance evidence                                                                                                                                                                                                             | Responsible parties                             |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Baseline                                  | Freeze one source/build/configuration; run native, browser, container, security and mission workflow checks; record defects and current limits                                                                                           | SYNTRIASS                                       |
| Relevant-environment validation           | Sponsor defines representative devices, independent hosts, users, WAN conditions, outage/revocation cases and thresholds; execute and retain witnessed results                                                                           | SYNTRIASS + IAF sponsor/evaluator               |
| Integrated prototype demonstration        | Complete identity, approved crypto-provider, monitoring and required interface integrations; demonstrate the full mission workflow and recovery on representative hardware                                                               | SYNTRIASS + integration partners + sponsor      |
| Operational-environment prototype         | Authorized deployment and user trials; loss of device, personnel transfer, denied access, incident handling, backups and restore; agreed acceptance report                                                                               | IAF sponsor + operators + independent assessors |
| Final system qualification (TRL 8 target) | Complete final configuration; independent assessments and required cryptographic approvals; closed critical defects; reproducible release, user/training/maintenance documentation; documented qualification against agreed requirements | Sponsor/evaluation authority + SYNTRIASS        |

The stages are evidence requirements, not an automatic sequence of labels earned
by passing repository tests. The sponsor must confirm the applicable assessment
framework. NASA's software TRL 8 description provides a general reference for a
fully integrated system, completed documentation and completed verification and
validation: https://esto.nasa.gov/trl/ . It is not an IAF certification rule.

## Concrete remaining work

| Item                       | Required result                                                                                                     | Evidence still needed                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Personnel identity         | Sponsor-approved enrolment, federation/PKI and recovery; hardware-backed custody where required                     | Real interface specification and enrolled-device trials                   |
| Cryptography               | Agreed algorithm/provider, lifecycle, rotation and key custody; required SAG process                                | Sponsor route, provider interface and independent qualification evidence  |
| Public Internet operations | Agreed hosting, TLS trust/rotation, service isolation, abuse protection, capacity, monitoring and response          | Deployment inventory, penetration/load reports, SOC workflow and runbooks |
| Continuity                 | Separate-host custody, tested backup/restore, failure handling; availability design preserves transactional release | Witnessed rollback/fork/outage tests, RPO/RTO and capacity results        |
| Integration                | Required military workflow and document-system adapter                                                              | Sponsor-provided contract, emulator/test endpoint and acceptance          |
| Product usability          | Personnel enrolment, approvals, exchange, receipt review and accessible operator views                              | Task-based user trials and training material                              |
| Release control            | Pinned code/runtime/image, SBOM, signed update, installation and rollback rehearsal                                 | Exact candidate CI/security artifacts and deployment record               |

No provider, live IAF interface, classified-data clearance or operational approval is
invented in this change. Current tests continue to use synthetic content. Real
confidential data onboarding waits for the applicable sponsor authorization.
