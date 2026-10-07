# AIRON–SIEPMU Defence Research | 2026-10-08

Review date: 2026-10-08 (India). Frozen implementation: `main` at `49774e2111197412efb31d459317c0df23a838af`.
Engineering plan for synthetic, authorised tests; not SAG/IAF approval or a TRL award.
Source hierarchy: official PS-69, filed-proposal copies, frozen code and execution evidence, then candidate documentation.
See [source register](source-evidence-register.json) and [proposal reconciliation](17-proposal-reconciliation.md).

## Indicative bill of materials — quote-required

| Stage         | Item                                             | Minimum planning quantity | Necessity                    | Price status / evidence               |
| ------------- | ------------------------------------------------ | ------------------------- | ---------------------------- | ------------------------------------- |
| TRL5 software | Node 24, native crypto/SQLite, npm dev tools     | source-pinned             | Existing                     | licence terms apply; price not quoted |
| TRL5 lab      | managed client workstations                      | 3                         | REQUIRED                     | reuse first / local quote             |
| TRL5 lab      | isolated L2/L3 switch/firewall + impairment host | 1 each                    | REQUIRED                     | quote-required                        |
| TRL5 lab      | evidence workstation/backup media                | 1                         | REQUIRED                     | quote-required                        |
| TRL5 lab      | FIDO2 tokens (for comparative trial)             | 2–4                       | OPTIONAL                     | quote-required                        |
| TRL5 service  | independent scoped security audit                | 1 package                 | REQUIRED for assurance plan  | RFP required                          |
| TRL6          | managed on-prem server nodes                     | 2–3                       | representative deployment    | quote-required                        |
| TRL6          | managed Linux/Windows endpoints                  | 4–6                       | representative deployment    | quote-required                        |
| TRL6          | HSM/PKCS#11 key device trial                     | 1–2                       | CONDITIONAL to approved plan | vendor RFI                            |
| TRL6          | identity/observability control servers           | 1–2                       | evidence-dependent           | self-hosted quote                     |
| TRL6          | switch, firewall, UPS, backup                    | to topology               | REQUIRED                     | itemized quote                        |
| TRL6 service  | formal cryptographic/sponsor review              | as directed               | EXTERNAL                     | IAF/SAG process and quote unknown     |
| TRL6 service  | independent network/security review              | scoped RFP                | REQUIRED as approved         | quote-required                        |
| Both          | engineering/test/systems integration labour      | estimate with role-months | REQUIRED                     | no salary estimate supplied           |

## Budget discipline

No invented INR prices. Record public vendor URL, exact config/firmware, price date, tax/GST, freight, support year, warranty, importer, rental option, country of origin, alternative, supplier lead time and approved project financing/ceiling. Use a procurement-bom.csv with quote_required=true until verified quote. Agree cap with approved SPARK/product-development budget (not established by the three reviewed annexures or receipt) before RFP.

## Decision rule

Purchase for a demonstrated CTE gap only; prioritise existing machines and open-source instruments. Commercial security hardware is optional for current software tests but may become mandatory upon sponsor acceptance criteria. Software security testing alone does not certify product.
