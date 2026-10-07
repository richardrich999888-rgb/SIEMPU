# ADR-005: clean source and operator-controlled deployment

Status: accepted scope and provenance constraint.

## Context

The repository has a public Apache-2.0 starting point. Prior project components differ in purpose, assurance and ownership evidence. Publication and security acceptance cannot be inferred from their existence.

## Decision

Implement cleanly. Import no private legacy source without a component-specific review and publication authorisation. Maintain `third_party/migration-ledger.csv` and dependency provenance. Document any reused idea as established practice where appropriate; naming it differently does not establish novelty.

Separate original eligible SYNTRIASS contributions, third-party open-source dependencies and any future licensed proprietary provider. Sovereign operation means the deployment authority controls hosting, trust roots, content-key recovery policy, build/signing pipeline, updates, telemetry and support access. It is not a claim of 100% Indian-origin code.

Use a cryptographic provider boundary for the service-mandated suite. Do not label the prototype SAG-graded without the actual approval evidence for its exact configuration.

## Consequences

The initial proof can be independently inspected without publishing private repositories or submission documents. Operational qualification still needs independent security/crypto review, approved hosting and key custody, supply-chain assurance and sponsor-defined QA. These are release gates, not capabilities supplied by a README or container file.
