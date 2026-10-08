# Executive summary: AIRON–SIEPMU for iDEX DISC-14 PS-69

**What it is.** SIEPMU is a secure information-exchange platform. Authorised military units use it
to exchange end-to-end-encrypted text and files over untrusted networks.

**What makes it different.** The key to read a message is released only inside a single authority
transaction. That transaction re-checks the **current** user, device, role, mission, destination,
policy and revocation state at the moment of release ("Trust Before Release"). A message queued
during an outage can therefore never be delivered to someone who lost authority while it waited.
A key already issued cannot be recalled, and we say so.

**What exists today (frozen build `0e8d1b9`, 8 October 2026):**

- **Services:** browser and SDK endpoints, and five independent services (TLS 1.3 / mTLS) plus an
  integration adapter.
- **Security:** MFA and device binding; granular role and mission policy; signed hash-chained
  evidence with independent Node and Rust verifiers.
- **Operations:** monitoring to an independent collector; hardened containers; signed offline
  release.
- **Research:** laboratory post-quantum suites.
- **Evidence:** 249 automated tests (97.5 % line coverage) and four reproducible demonstrations
  (9/9, 14/14, 10/10 and 11/11 steps). Hosted CI and security scans are green.

**Readiness.** Provisional **TRL 4**, internal self-assessment.

- A 33-test TRL 5 advancement matrix, declared before execution, passed on a three-host laboratory
  topology (network namespaces on one machine). The hosted run added packet loss and passed 35/35.
  Evidence: `docs/trl5/`.
- The same campaign found an open scaling defect. The custody check re-verifies the full audit
  chain on each request, which limits throughput to about 1.6 exchanges/s and degrades over time.
  The fix is designed and is the first funded task.
- TRL 4 is retained until the sponsor defines the relevant environment, the defect is fixed, and a
  witnessed multi-machine run passes. Release, relay and offline queue are TRL 5 validation
  candidates.
- There is no IAF approval, SAG grading, independent assessment or operational deployment.

**PS-69 fit.**

- Five of the eight published capabilities are tested in the laboratory.
- Threat monitoring is rule-based and under development.
- Integration with real military systems, and SAG-graded encryption, depend on sponsor decisions.

**Request.**

- SPARK grant support for a 12-month maturation plan toward TRL 5 validation and a TRL 6
  representative prototype. The engineering-estimate PDB is ≈ ₹1.62 cr, so the grant would be
  ≈ ₹0.81 cr at the 50 % rule (founder to confirm).
- Sponsor nomination of a relevant-environment definition and an interface owner.
- Guidance on the SAG grading route.

**Package index:**

| Topic                         | Documents                                             |
| ----------------------------- | ----------------------------------------------------- |
| Slides                        | `HPSC_DECK.md`                                        |
| Demonstrations                | `demo-runbook.md`                                     |
| Q&A                           | `evaluator-questions.md`                              |
| TRL assessment                | `../trl/TRL_ASSESSMENT.md`                            |
| PS-69 compliance              | `PS69_COMPLIANCE.md`                                  |
| Funding                       | `FUNDING_PLAN.md`                                     |
| Frozen baseline               | `FROZEN_BASELINE.md`                                  |
| Deployment                    | `../deployment/PROFILES.md`                           |
| Claims and external approvals | `../../CLAIMS_REGISTER.yaml`, `EXTERNAL_APPROVALS.md` |
