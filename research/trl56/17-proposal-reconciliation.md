# Filed proposal versus delivered prototype

Review date: 8 October 2026 (India). Code baseline: `49774e2111197412efb31d459317c0df23a838af`. This report corrects engineering interpretation; it does not amend the filed application, withdraw commitments or claim sponsor acceptance of changes.

## Sources and programme identity

P001 is the user-provided DISC-14 PS-69 Annexure 1: two pages, seven deliverables and a 12-month four-phase proposal. P002 is the matching detailed Annexure 2: five PDF pages, with architecture, roles and technical assertions. Both were extracted in full; P001's deliverable/timeline table was visually checked. P003 is the official receipt confirming the challenge and duration. Hashes are in [the source register](source-evidence-register.json).

The user identifies these files as submitted copies. Their exact byte identity with portal-held attachments has not been independently established. A signed grant/contract, accepted scope changes, approved financial application and the HPSC undertaking contents were not available for this review. The separate Open Challenge 19/Edge annexures and unrelated project credentials are not SIEPMU evidence.

The [claim register](proposal-claim-register.csv) contains 24 decisions, with private source page/section locators, actual code references and corrective work. Original PDFs, correspondence, personal identifiers and detailed unpublished protocol material are not copied into this public repository.

## Seven deliverables: actual disposition

| Filed deliverable category            | Current implementation                                                                 | Disposition                                                                                    |
| ------------------------------------- | -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Core exchange platform                | Three Node services, browser client, encrypted exchange and current-authority issuance | Functional prototype; differs from submitted named component/stack and protocol                |
| Graded symmetric cryptographic module | Platform-provider AES-GCM/HKDF implementation                                          | No SAG grading evidence; a self-labelled module is not approval                                |
| Proposed post-quantum protocol        | Current suite uses P-256; proposed PQC construction absent                             | Filed scope decision required; do not describe this demonstration as quantum-resistant         |
| MFA and military role module          | Password/TOTP, device proof, four generic roles                                        | MFA exercised; six-role/four-priority applicant taxonomy unimplemented                         |
| Operational dashboard                 | Native browser client/admin console                                                    | Working interface; different technology and no proposed dual-layer status                      |
| Audit ledger                          | Signed hash chain, receipts, checkpoint export and verifier                            | Tamper-evident under explicit trust assumptions; external custody/rollback work remains        |
| SDLC/source handover package          | Source, tests, threat/deployment/recovery documents and release artifacts              | Useful engineering package; independent assurance and contract-specific licensing/support open |

The 12-month proposed timeline is preserved in [the roadmap](15-implementation-roadmap.md). It includes integration, field/certification and rollout work beyond the existing demonstrator. That work must be made explicit or changed through the programme's accepted process, not silently discarded because a simpler prototype now exists.

## Corrections needed for truthful evaluation

- **SAG:** state that cryptographic grading is pending. The published PS-69 requirement is explicit; algorithm names, original application code and ordinary standards conformance do not satisfy it.
- **PQC:** current code does not implement the submitted suite. Treat it as a separately reviewed provider/scope decision. Do not hand-implement primitives or enable an unreviewed composite protocol to match a slide.
- **Roles:** the six duty roles are now verified as an applicant proposal, not an official IAF role specification. Build a reviewed action/priority matrix; separating administration, audit metadata and content access is essential. Wildcard access and hidden UI elements do not prove least privilege.
- **Transport and integration:** local HTTP tests do not prove secure public-internet deployment. Synthetic schema validation does not prove an arbitrary-format military/C2 connector or LDAP/PKI federation.
- **Audit:** hash chaining is tamper-evident only relative to trusted evidence. An issuer that controls all retained roots can rewrite or truncate its own history. Independent custody and restore checks are separate work.
- **Origin and ownership:** application source control does not remove Node, browser, cryptographic-provider, operating-system or licence dependencies. Describe actual dependencies and operator control.
- **Novelty/security:** standard TOTP, RBAC, hash chains, layered encryption and named primitive security properties do not establish universal novelty or a whole-protocol proof. No patent status or exclusivity claim is established by the reviewed files.
- **Time/performance:** TOTP tolerance does not remove clock management. Wire estimates and small loopback measurements do not prove tactical performance, unlimited scaling or low-bandwidth suitability.

## Recommended current capability statement

SYNTRIASS has a synthetic-data information-exchange prototype with endpoint encryption, MFA, device possession checks, role/unit/mission authorization, an encrypted local outbox and policy-epoch-bound wrapped-key issuance with signed evidence. The frozen build has reproducible native, browser and container checks. Secure WAN deployment, approved military interfaces, the filed role model, the proposed PQC suite, independent assessment and graded cryptographic acceptance remain development or external-decision items.

This wording reports the demonstrated system. It does not imply that the filed architecture has already been approved for replacement.

## Decisions still held by the proposal owner

Confirm the authoritative portal submission and applicant category; reconcile the company-labelled annexure with the receipt category; obtain the approved budget/matching-funds record; verify licence and support commitments; confirm the current HPSC administrative instructions; and record requested scope adjustments with the programme. The HPSC request contains a date/weekday inconsistency, so the private calendar record must be clarified. No undertaking was signed or correspondence sent by this review.
