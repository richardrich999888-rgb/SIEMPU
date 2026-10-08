# Infrastructure contract

The current platform needs one developer host; it has no Terraform, Kubernetes, cloud
account, managed database, public DNS, or production secret store provisioned by this repository.
SQLite is embedded in the authority and relay processes, so an extra database container is
neither required nor configured.

| Resource                      | Current owner / contract                                                      | External deployment decision still required                        |
| ----------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Public ingress                | Web gateway on host loopback, port 8080                                       | Exact HTTPS origin, approved TLS termination and ingress policy    |
| Authority state               | One writer, SQLite WAL, separate protected directory or `control-data` volume | Host/storage controls, retention and recovery objectives           |
| Relay state                   | Ciphertext SQLite store and replay nonces, separate `relay-data` volume       | Storage capacity, denial-of-service limits and recovery objectives |
| Workload credential           | Bootstrap provisions a separate read-only relay credential mount              | Rotation and approved machine identity integration                 |
| Identity and signing material | Protected local files created explicitly by bootstrap                         | Production directory, key custody and HSM/KMS integration          |
| Network separation            | Internal Compose authority/ciphertext networks; gateway edge bridge           | Host firewall, egress policy and authenticated TLS across hosts    |
| Build execution               | GitHub-hosted CI runs synthetic data only                                     | Approved sovereign build runner and artifact provenance policy     |

Implement infrastructure-as-code only after those deployment inputs are agreed. The
repository's [deployment guide](../docs/deployment.md) documents the existing local boundary;
this contract does not assert operational approval or accreditation.
