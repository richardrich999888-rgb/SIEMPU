# HPSC presentation: SYNTRIASS AIRON–SIEPMU

**Presentation:** Tuesday 13 October 2026. Twelve slides with speaker notes. **Claim control:**
every factual line maps to `CLAIMS_REGISTER.yaml` (IDs in brackets).

**Status tags** (as defined in `PS69_COMPLIANCE.md`):

| Tag            | Meaning                                    |
| -------------- | ------------------------------------------ |
| **[Tested]**   | Implemented and passing tests              |
| **[Impl]**     | Code exists; not tested end to end         |
| **[Dev]**      | Under development                          |
| **[Proposed]** | Planned; no code yet                       |
| **[External]** | Requires a sponsor or third-party decision |

Fields marked **⟨FOUNDER⟩** need evidence the founder holds. Leave them out rather than fill them
without that evidence.

---

## Slide 1: SYNTRIASS — AIRON–SIEPMU

- **Secure information exchange for military units over untrusted networks**
- iDEX DISC-14 · Indian Air Force · Problem Statement 69
- SYNTRIASS Labs Private Limited · Applicant: Katta Naga Sri Ganesh
- Tested laboratory prototype · Provisional TRL 4 (self-assessed)

**Notes:** Open with what exists: a working, tested laboratory prototype. We are asking for support
to validate and mature it, not to start it. Say "laboratory prototype" and "provisional TRL 4" once,
and do not inflate either.

## Slide 2: The IAF problem (PS-69)

- Authorised units must exchange sensitive information over **public internet infrastructure**
- Published requirements:
  1. Cloud-based microservices
  2. End-to-end encryption
  3. Multi-factor authentication
  4. Secure communication protocols
  5. Real-time threat monitoring and detection
  6. Granular RBAC
  7. Integration with existing military systems
  8. SAG-graded encryption

**Notes:** Read requirement 8 aloud. It is the one we cannot satisfy ourselves (slide 8). The
problem statement does not specify classification, scale, latency or interfaces; we have listed
these as sponsor questions rather than guessing.

## Slide 3: The operational gap and our answer

- **The gap:** an encrypted message can sit in a queue while authority changes. A device is lost,
  a recipient is posted out, a mission ends. Most systems decide access when the message is
  **sent**.
- **Our answer:** SIEPMU decides at the moment of **release**.
  - The key to read a message is issued only inside one authority transaction.
  - That transaction re-checks the **current** user, device, role, mission, destination, policy and
    revocation state.
- **Our honesty:** a key already issued cannot be recalled. We never claim instant or retroactive
  revocation.

**Notes:** This is the whole product idea in one slide. Pause after "at the moment of release".

## Slide 4: Working architecture [Tested]

- Unit endpoints (browser and SDK) encrypt and decrypt. **Plaintext and private keys stay at the
  endpoints.** [C01]
- TLS 1.3 gateway → control authority (identity, policy, release, signed evidence) → ciphertext-only
  relay [C03, C06]
- Separate checkpoint custodian, telemetry collector and integration adapter, each with its own
  mTLS identity [C17]
- Independent verifiers in Node and Rust [C18]

**Notes:** Show the diagram. Each box is a separate process with its own identity and storage. The
relay never sees a key; the authority never sees plaintext.

## Slide 5: Core differentiator — Trust Before Release [Tested]

1. Unit A goes offline and keeps sealing objects locally.
2. While A is offline, a recipient is revoked.
3. A reconnects. The revoked recipient's object is **HELD**, with a signed decision; the eligible
   recipient's object is **released**.
4. If revocation commits first, the key is never issued; if issuance commits first, it stands. The
   commit order decides. [C15, C03, C04]

**Notes:** Secure messaging, queues and audit logs exist elsewhere. Our contribution is the tested
release invariant under disconnection, races and restarts, measured on our own system. We do not
claim it is novel in the world.

## Slide 6: Live demonstration and validated results

- **Demo 1, secure exchange:** MFA, device proof, encrypted text and files, unrelated unit refused
  [C01, C02]
- **Demo 2, Trust Before Release:** 14/14 steps [C15]
- **Demo 3, existing-system integration (synthetic):** 10/10 steps [C16]
- **Demo 4, monitoring and recovery:** 11/11 steps, including a defect we found and fixed [C17]
- **Frozen build:** `0e8d1b9`. 249 automated tests pass, 97.5 % line coverage; hosted CI and
  security scans green.

**Notes:** Run Demo 2 live (about 9 s), then show its report. Offer Demos 3 and 4 if time allows.
Mention the telemetry defect Demo 4 caught: monitoring stopped after a policy change. It shows the
demonstrations are real tests, not choreography.

## Slide 7: Current Technology Readiness

- **System: provisional TRL 4.** An integrated laboratory prototype with evidence on a pinned
  revision; internal self-assessment. [C20]
- **TRL 5 validation candidates:** release, relay, offline queue, evidence custody.
- **At TRL 3:** threat-detection analytics, real-interface integration, graded-provider crypto.
- **Why not TRL 5 yet:** the relevant environment is not defined. Every test is single-host or a
  simulated network. [C22]

**Notes:** Saying TRL 4 makes the claim credible. The TRL 5 gate is a definition the sponsor gives
us plus a witnessed multi-host test. Funding the second half is what we are asking for.

## Slide 8: Sovereign deployment and crypto-agility

- **Operator-controlled:** no external control plane; zero runtime npm dependencies; signed offline
  install with rollback protection [C11]
- **Connected and isolated profiles** share one security core [Tested]
- **Crypto-agility:** provider port, suite policy checked at submission **and** at release, and
  downgrade rejection. Laboratory ML-KEM/ML-DSA are disabled by default [C19]
- **SAG-graded encryption: not satisfied today** [External]. The provider port is ready for an
  approved provider; the grading route needs the sponsor. [C12]

**Notes:** Use the words "post-quantum research implementation", never "quantum-proof". We have
surveyed Indian providers. None publicly documents an integration interface or a held SAG grade,
which is why qualification is a funded work package.

## Slide 9: Existing-system interoperability

- A versioned adapter with mTLS source authentication, strict schema, freshness, destination
  scope, idempotency and capacity bounds [Tested]
- A separate synthetic document system submits, receives and acknowledges through it (Demo 3)
  [C16]
- **Not connected to AFNET, e-Office or any IAF system** [External]. We need the sponsor's interface
  specification and a test endpoint.

**Notes:** The point is architectural. A new interface is an adapter, and the security core does
not change.

## Slide 10: TRL 5/6 advancement roadmap (12 months, proposed) [Proposed]

| Milestone                  | Months | Exit evidence                                                 |
| -------------------------- | ------ | ------------------------------------------------------------- |
| M0 Baseline                | 0–1    | Frozen baseline; sponsor questions submitted                  |
| M1 TRL 5 preparation       | 1–4    | Relevant environment agreed; multi-host lab; assessor engaged |
| M2 TRL 5 validation        | 4–7    | Witnessed validation of four elements                         |
| M3 TRL 6 build             | 7–10   | Hardware-backed keys; sponsor interface adapter               |
| M4 TRL 6 demonstration     | 10–12  | Representative prototype; independent assessment closed       |
| M5 Qualification readiness | 12     | SAG evaluation dossier for the selected provider              |

These are internal milestones, to be aligned with the programme agreement. [C21]

**Notes:** Name the external dependencies as you go: the relevant environment (M2) and SAG (M5).

## Slide 11: Product Development Budget and funding model [Proposed]

- **Engineering estimate:** PDB ≈ **₹1.62 cr** over 12 months.
  - Security and crypto engineering ₹51.6 L; independent security reviews ₹18.0 L; deployment and
    documentation ₹17.4 L; relevant-environment testing ₹15.8 L; cloud and private infrastructure
    ₹13.5 L; test equipment ₹10.9 L; interoperability ₹10.8 L; UI/UX ₹9.0 L; hardware trust
    ₹8.6 L; Indian provider qualification ₹6.0 L.
- **Rules applied:** grant ≤ min(₹1.5 cr, 50 % of PDB) **⇒ request ≈ ₹0.81 cr**. Matching
  contribution ≥ ₹0.81 cr. Tranches 10/20/20/20/20/10 %.
- **⟨FOUNDER⟩** Confirm the PDB scope, the matching-contribution sources (cash, past expenditure,
  in-kind) and the quotations. A one-third share of the PDB is quote-required.

**Notes:** All figures are estimates from `docs/hpsc/budget-inputs.json`; none is a quotation. If
the founder wants the full ₹1.5 cr, the PDB must be at least ₹3.0 cr, with a matching contribution
of at least ₹1.5 cr. Decide this before the 13th.

## Slide 12: Team, traction, IP and our request

- **Team:** ⟨FOUNDER: names, roles, relevant experience⟩
- **Traction:** ⟨FOUNDER: only documented items. Advisers, incubation, filed IP application
  numbers, investor evaluations, partnerships⟩
- **What exists today:** tested prototype; 249 automated tests; four reproducible demonstrations;
  provisional TRL 4
- **Our request to HPSC:**
  1. SPARK grant support for the 12-month maturation plan
  2. Sponsor nomination of the relevant-environment definition and interface owner
  3. Guidance on the SAG grading route

**Notes:** End on the three asks. Do not imply procurement, deployment, investor commitment or IAF
endorsement. [C22]
