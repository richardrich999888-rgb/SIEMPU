# Ten-minute HPSC demonstration story

> **13 October 2026 presentation:** use [HPSC_DECK.md](HPSC_DECK.md) (12 slides) and
> [demo-runbook.md](demo-runbook.md) (four demonstrations). This ten-minute story is kept as a
> rehearsal checklist. Its rules on claims and budgets still apply.

Use synthetic text and files. Freeze the demonstrated commit, deployment configuration, trust-root fingerprint and test-evidence bundle before rehearsal. Read `CLAIMS_REGISTER.yaml` first. A live result supports only its recorded environment and tested scenario.

## Presentation allocation

| Time       | Show                                                   | Say only when supported                                                                                                                          |
| ---------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0:00–1:00  | Official PS-69 requirements and the unit exchange task | “We are building secure inter-unit information exchange over public internet.”                                                                   |
| 1:00–2:00  | Unit A/B, MFA, device enrolment and controlled roles   | Distinguish user identity, device key, unit, role and session. Software keys are not hardware attestation.                                       |
| 2:00–3:00  | A sends text/file; B receives; denied identity fails   | Show the actual object path and ciphertext at the relay. State who owns decryption keys.                                                         |
| 3:00–4:00  | Local outage; two objects queued                       | “Creation is pending. No remote delivery is claimed while disconnected.”                                                                         |
| 4:00–5:30  | Authority changes; reconnect; one release and one hold | “Current release authority is evaluated separately from creation authority.”                                                                     |
| 5:30–6:30  | Deterministic policy race, tamper and retry            | Show the old decision cannot bypass the committed release gate. Identify the linearisation point.                                                |
| 6:30–7:00  | Restart and evidence export                            | Show durable state and verifier output using an independently trusted key/checkpoint.                                                            |
| 7:00–8:00  | Closest prior art and bounded differentiator           | Secure messaging, policy-bound data and outboxes already exist. The experimental contribution is the measured release invariant, not a new name. |
| 8:00–9:00  | Integration and assurance plan                         | Synthetic adapter today; approved military interface and SAG/QA route remain external work.                                                      |
| 9:00–10:00 | Approved programme timeline, budget and request        | Use founder-approved financial figures and submission commitments. Do not generate a fictional budget.                                           |

Keep a recorded fallback only if it shows the same frozen configuration and is labelled recorded. Do not remove failed steps from the evidence packet while presenting the remaining run as a complete pass.

## Reproducible demonstration sequence

Use the repository's current documented demo command and evidence output. Record the command, commit and result in `evaluation.md`; this document does not assert a run occurred.

1. Start a fresh, isolated lab deployment. Save public verification fingerprints separately from exported evidence.
2. Enrol Unit A, Unit B, their users and software devices. Also enrol a third identity without permission to receive the chosen object.
3. Authenticate with password plus MFA. Attempt an incorrect/replayed second factor and show denial.
4. Send a unique synthetic text marker and a file from A to B. B verifies context and decrypts. Inspect only the relevant payload-storage/log scope for the marker; absence from one table is not proof about every backup or log.
5. Request the valid object through the direct API as the denied identity. Show no usable payload/key material and the associated security event.
6. Disconnect the sender's transport. Create two local pending objects: one under a grant that will remain valid; one under a grant that will be revoked. Restart the client if the implemented vault supports durable recovery.
7. Change the affected recipient/grant authority while the sender remains offline. Show the committed epoch change.
8. Reconnect. Show current authority validation before release. The still-valid object may proceed; the affected object must remain held/rejected. Explain the reason visibly.
9. Inject the deterministic race: obtain an allow/admission result, commit a policy change, then attempt dispatch/release. Show the stale decision cannot release.
10. Repeat a request and a delivery acknowledgement. Show one application effect; distinguish idempotent success from attack replay rejection.
11. Restart the relevant service/database. Show retained revocation and pending state; repeat the held request and verify it remains held.
12. Export signed decision evidence and run the detached verifier. Alter a copy and show failure. A truncation test must supply a trusted expected checkpoint/count rather than accepting a shortened self-contained chain.
13. Run the authenticated synthetic integration adapter and label it synthetic. Finish with known limitations, measured results and external qualification gates.

## Statements to avoid

Do not say SAG graded/certified, IAF approved/deployed, defence certified, unhackable, patentable, instant revocation, guaranteed delivery, secure against compromised endpoints, hardware-backed or 100% Indian IP without exact supporting evidence. “Designed for integration with service-mandated and approved cryptographic suites through the applicable qualification and assurance process” describes intent, not approval.
