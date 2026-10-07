# AIRON–SIEPMU Defence Research | 2026-10-08

STATUS: engineering proposal / evidence-based roadmap. Does not establish IAF/SAG approval, TRL progression, vendor quotation or classified access. Baseline f6d75cf6b105319ca0d6942b2bbc196750a0b230.

## Representative deployment (engineering target)
Unit-A managed endpoints and Unit-B managed endpoints on separate controlled virtual networks; each with encrypted offline vault and scoped identity; public-Internet emulator with TLS termination; gateway + control authority in management-controlled service network; ciphertext relay with isolated storage; central redacted SOC collection; separate signed-evidence checkpoint; independent synthetic legacy mock; external administration on isolated management interface. Deployment is multi-node rather than a single process. Demonstration uses synthetic content and explicit delegated authority.

| Component | TRL 6 target | Today |
|---|---|---|
| Workstation unit client | Managed Linux/Windows, browser controls, FIDO2 pilot | Browser E2EE + software keys |
| Crypto provider | Policy-checked provider API, optional PKCS#11 device, sponsor provider later | Native WebCrypto only |
| Control | durable transaction + restore, TLS service boundary | SQLite one-node writer |
| Relay | separate node, ciphertext-only, mTLS | separate process same host |
| Identity | locally issued synthetic PKI + auth gateway, optional federation | password/TOTP |
| Admin/SOC | segregated admin + event collector | internal admin console |
| Interop | independently running synthetic mock service | validation API |
| Evidence | signed detached verifier + independent checkpoint | verifier, checkpoint feature with trust owner absent |
| Release/updates | signed image + offline verification | unsigned hashes, current CI blocking |

## Architecture constraints
No system-wide claim of HA/linearizability until tested. Preserve the single transaction around epoch+issuance+receipt; horizontal scale requires a consensus/transaction redesign subject to formal modeling. Standard TLS/mTLS and sponsor-approved deployment topology are prerequisites before testing on untrusted WAN. Retain E2EE despite SIEM use: monitor actions/events, not payload plaintext. End-user hardware keys and recovery must be co-designed. Do not adopt Kafka, blockchain, tactical radios or PQC without requirements.

## Work packages
TRL6-A independently operated multi-host TLS; -B hardware binding and crypto abstraction; -C neutral mock integration; -D telemetry operator workflow; -E policy failover/recovery evidence; -F signed release and offline restore; -G independent assurance. Each must have a build digest + witnessed demo/negative tests.
