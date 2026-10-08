# Architecture decisions

The accepted implementation contract is [protocols/IMPLEMENTATION_CONTRACT.md](../protocols/IMPLEMENTATION_CONTRACT.md). “Accepted” below means a design choice, not proof that its implementation passes tests.

| ADR                                             | Decision                                                            |
| ----------------------------------------------- | ------------------------------------------------------------------- |
| [001](ADR-001-scope-and-authority.md)           | Bounded PS-69 information exchange and authority-change experiment  |
| [002](ADR-002-endpoint-encryption.md)           | Endpoint encryption and separate wrapped-key release boundary       |
| [003](ADR-003-transactional-release.md)         | Capability issuance linearises in the authority transaction         |
| [004](ADR-004-runtime-and-services.md)          | Node 24, three processes and single-host SQLite prototype           |
| [005](ADR-005-sovereignty-and-reuse.md)         | Clean implementation, operator control and import provenance        |
| [006](ADR-006-reconciliation-base.md)           | Engineering branch is the base; Q-agile work ported selectively     |
| [007](ADR-007-browser-module-graph.md)          | Browser crypto module imports only canonical.mjs                    |
| [008](ADR-008-laboratory-code-isolation.md)     | Laboratory PQC code never enters a release artefact                 |
| [009](ADR-009-duty-concealment-after-commit.md) | Duty-role concealment after the signed decision commits             |
| [010](ADR-010-v3-laboratory-release-path.md)    | Laboratory schema-v3 objects use the normal release transaction     |
| [011](ADR-011-hpke-pq-deferred.md)              | Wrap v2 kept for the laboratory; HPKE base mode planned as wrap v3  |
| [012](ADR-012-rust-reference-components.md)     | Rust only via specified, differentially tested reference components |
| [013](ADR-013-typescript-first-ui.md)           | TypeScript-checked UI modules; no framework or build step for now   |

Changes must state the reason, trust-boundary effect, migration impact and regression evidence. Never change a cryptographic or evidence encoding silently under the same protocol version.
