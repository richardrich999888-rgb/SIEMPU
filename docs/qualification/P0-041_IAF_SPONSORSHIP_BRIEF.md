# AIRON SIEPMU IAF technical sponsorship brief

SYNTRIASS Labs Pvt. Ltd. | DISC-14 PS-69 | 9 November 2026

We request nomination of an IAF technical point of contact, agreement on a supervised evaluation
scope, guidance for service-sponsored SAG assessment, and consideration of an applicable funded
development pathway. We seek technical direction and evaluation access; no grant, procurement
commitment, SAG grading or operational approval is represented as established.

## Operational purpose

PS-69 calls for secure information exchange between multiple users/units over untrusted public
networks. AIRON–SIEPMU combines endpoint encryption with current-policy checks before releasing
a recipient's wrapped content key. Role, unit, mission, device status and revocation influence
release. The relay carries ciphertext. Local password/TOTP and device proofs are implemented;
integration with an IAF-nominated identity/PKI remains outstanding. Applicant-defined duty roles
are not presented as approved IAF policy.

## Engineering evidence and differentiation

The mechanism under evaluation is policy-epoch-bound cryptographic release with verifiable
decision history and separately keyed checkpoint custody. P0-041 adds explicit writer fencing,
monotonic authority floors, atomic signed state/head binding and controlled manual handover.
The intended property is denial of a new release after an effective revocation, including unsafe
restore or conflicting-writer conditions. Previously delivered keys/plaintext cannot be recalled.

PR 40 baseline `62b8e6634cc6ba2a634b3170654fc21a34c8c0b4` was freshly reproduced: 473 native,
264 adversarial and 14 IUDX/comparison tests passed; suites overlap. The downloaded evaluation
package's manifest and 18 archived-source tests were rechecked. Historical exact-tree T8.1
evidence recorded 188/188 objects delivered without failures. P0-041 results, including failures,
are separately bound to the frozen candidate in the accompanying assurance report; baseline
numbers are not transferred to it.

Five reproducible demonstrations cover ciphertext confidentiality at the declared relay boundary,
post-revocation denial, unsafe restore/fencing, network recovery and offline detection of tampered
or inconsistent evidence. Commands, expected outcomes and retained logs accompany the source.
The comparison uses the same encrypted object with a pre-delivered-key negative control. It
tests a release property and its cost, not superiority over named messaging products or patent
novelty. Encryption primitives, TLS, MFA and ordinary access control are standard technology.

## Current maturity and limits

Our internal assessment remains provisional TRL 4. Automated tests do not establish TRL 5.
The lab uses synthetic data and shared-host processes/namespaces; independent administration,
representative IAF hardware/network and a witnessed campaign remain to be established.
All 19 qualification gaps are retained with owners. Major dependencies are the approved
cryptographic module/profile, hardware key custody, identity interfaces, complete-system
recovery/availability, endpoint hardening and agreed operational acceptance thresholds.
Legacy database/archive migration is intentionally blocked pending a reviewed procedure.

IUDX compatibility is limited to a pinned public request/response contract exercised locally.
No live government API access, military integration or government endorsement is claimed.

## Proposed supervised evaluation and support

We propose sender, platform and recipient/verifier hosts, with independently administered
checkpoint custody. An initial synthetic campaign would exercise the five demonstrations,
partitions, revocation, loss/jitter/bandwidth profiles, handover and recovery. The IAF would define
permitted scope, representative conditions, acceptance criteria, observers and required evidence.

Please guide the nomination of the sponsoring authority and SAG scope, authorised algorithm/module
and SDK, selected laboratory, key-handling requirements, evaluation charges and any applicable
testing-charge waiver. We also request consideration of the attached milestone-based development
plan, subject to eligibility, co-funding, IP terms and competent approval. No purchase or deployment
is requested before the technical and security gates are agreed.

Reference: official iDEX DISC-14 compendium, PS-69 printed pp. 161–162; source repository
https://github.com/richardrich999888-rgb/SIEMPU; P0-041 assurance manifest and SAG scoping dossier.
