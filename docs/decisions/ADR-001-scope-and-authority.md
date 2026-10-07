# ADR-001: a bounded information-exchange demonstrator

Status: accepted scope constraint from the implementation brief; does not establish implementation completeness.

## Context

PS-69 requires secure public-internet inter-unit exchange and collaboration. The research does not establish that air-gap operations, a tactical data fabric or a new cryptographic primitive is needed. Existing secure messaging, policy-bound objects and durable queues are substantial prior art.

## Decision

Build text/file exchange, mandatory MFA, device enrolment, granular server-side authorisation, endpoint encryption, durable pending state, current-authority release, evidence and a synthetic integration contract. Keep identity, device, unit, role, authority and session separate.

Treat controlled reconnect release as an engineering experiment. Do not call the broad object format or a “Mission Cell” a proven invention. Compare a competent durable queue that rechecks policy against the proposed transaction, rather than an intentionally insecure sync-everything implementation.

Exclude tactical C2/weapon integration, sensor fusion, custom cross-domain guards, Kafka, blockchain, AI and PQC marketing from this vertical slice. Crypto agility is an interface requirement; approval is external.

## Consequences

The demonstrator may establish narrow tested properties. It cannot establish defence qualification, instantaneous global revocation, endpoint compromise resistance, military interoperability or a patent claim. Sponsor decisions remain in `../requirements/open-questions.md`.

Every capability claim requires a frozen source/configuration, actual command and result, evidence scope and a limitation. Failed or unexecuted checks remain visible.
