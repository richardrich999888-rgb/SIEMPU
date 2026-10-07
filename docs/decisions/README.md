# Architecture decisions

The accepted implementation contract is [protocols/IMPLEMENTATION_CONTRACT.md](../protocols/IMPLEMENTATION_CONTRACT.md). “Accepted” below means a design choice, not proof that its implementation passes tests.

| ADR                                     | Decision                                                           |
| --------------------------------------- | ------------------------------------------------------------------ |
| [001](ADR-001-scope-and-authority.md)   | Bounded PS-69 information exchange and authority-change experiment |
| [002](ADR-002-endpoint-encryption.md)   | Endpoint encryption and separate wrapped-key release boundary      |
| [003](ADR-003-transactional-release.md) | Capability issuance linearises in the authority transaction        |
| [004](ADR-004-runtime-and-services.md)  | Node 24, three processes and single-host SQLite prototype          |
| [005](ADR-005-sovereignty-and-reuse.md) | Clean implementation, operator control and import provenance       |

Changes must state the reason, trust-boundary effect, migration impact and regression evidence. Never change a cryptographic or evidence encoding silently under the same protocol version.
