# Third-party and migration provenance

This clean repository must not inherit trust from a project name, previous test count or a `production` label. No private legacy source is authorised for automatic publication by the existence of this public repository.

The current legacy-source migration decision is **no code imported**. `migration-ledger.csv` records that decision. New open-source dependencies must be inventoried from the package/lock files, with version, source and licence. A dependency declaration is not ownership or security approval.

Before importing a component, record:

1. Repository, branch, immutable full commit, source path and blob digest.
2. Purpose and exact exported interface; prefer a narrow component over a platform import.
3. Licence, notices, copyright and ownership/assignment evidence.
4. Security review, dependency review and the source tests actually rerun.
5. Modifications, new tests, acceptance evidence and deciding reviewer.
6. Whether publication is authorised; keep private source and internal evidence out until resolved.

Do not describe standard-library/open-source cryptography as SYNTRIASS-owned primitives or as SAG-graded because it is wrapped in this API. Sovereign operation means the operator controls deployment, keys, updates and support; it is a separate claim from code authorship.

Production dependency assurance remains a release gate: exact locks/hashes, SBOM, vulnerability review, licence compatibility, reproducible build and signing provenance. The root licence applies to eligible original contributions; it does not erase upstream obligations.
