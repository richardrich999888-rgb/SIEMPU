# Supply-chain implementation entry point

Use [SUPPLY_CHAIN_SECURITY.md](SUPPLY_CHAIN_SECURITY.md) for exact dependency/runtime/image pins, CI permissions, SBOM and release provenance. [third_party](../third_party/README.md) records import/licence discipline; no private legacy source has been imported. [CI/CD](ci-cd.md) separates configured gates from actual hosted execution. Runtime dependencies include Node, OpenSSL, SQLite, the OS and browser even though the application has no npm runtime packages. An SBOM is an inventory, not proof that dependencies are safe.
