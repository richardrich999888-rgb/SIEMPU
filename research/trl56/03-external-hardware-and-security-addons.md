# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Research snapshot: 2026-10-08. Scope: synthetic/authorised environments only. Base: codex/siepmu-hpsc @ f6d75cf6b105319ca0d6942b2bbc196750a0b230. Prepared engineering analysis, not IAF approval, independent assurance or verified procurement quote.

Source hierarchy: official iDEX DISC-14 PS-69, printed pp. 161–162: https://idex.gov.in/uploads/challenges/1774433728_800a3a04323d011d9303.pdf ; authoritative repository code/evidence; public standards/product documentation. Submitted annexures, sponsor directives, PDS/PRU and agreements are unavailable in this research run and must be reconciled before asserting filed commitments.

## Hardware shortlist (no quotations or certifications presumed)
| Category | Candidate / lab use | Integration | Need | Procurement |
|---|---|---|---|---|
| TPM 2.0 | TPM-equipped managed Linux/Windows workstation | OS TPM stack, Linux tpm2-tools / Windows TPM APIs | TRL 6 prototype | India quote required, host attestation scope unverified |
| FIDO2 | YubiKey 5 series or equivalent authenticator | WebAuthn browser API | TRL 5 optional experiment / TRL 6 likely subject to IAF | India availability/price to confirm |
| PKCS#11 security device | Nitrokey HSM 2 class or HSM vendor loaner | PKCS#11 C_Initialize/Sign/Wrap, vendor SDK | TRL 6 key-custody experiment | Quote and supported mechanism matrix required |
| Emulator | SoftHSM2 | PKCS#11 software | TRL 5 laboratory only | Source-built; not secure hardware |
| Secure server root | on-prem x86_64 server with TPM/secure boot/verified storage | UEFI, OS crypto, controlled signing | TRL 6 | Specify only after architecture and sponsor site decision |
| Isolated test nodes | managed Linux workstations (3 or more) | Node 24/browser/netem | TRL 5 essential | Existing equipment can be reused |
| Power/network | switch, firewall/VLANs, lab UPS | controlled VLAN + logged impairment | TRL 5 test fixture | Quote required |
| Independent evidence | separate write-once/offline-verifiable checkpoint store | signatures + trusted operator | TRL 5 essential function | Can use lab-managed offline vault |

## Qualification checklist for each offered device
Manufacturer legal name/model + firmware + country-of-origin; support channel in India; OS driver; license; TPM or PKCS#11 mechanism support; secure boot state; reproducible install steps; PIN/PUK recovery; side-channel/physical threat assumptions; key zeroization; hardware removal; supply-chain integrity; e-waste end of life; export controls; price quote; delivery time; spare policy; NIST/FIPS/Common Criteria certificate *scope and version* if claimed.

## Boundaries
A FIDO2 login token does not automatically protect content-encryption keys. A PKCS#11 HSM may not support P-256 ECDH or desired envelope wrapping identically to WebCrypto; design interoperability tests before choosing a product. Commercial certification never substitutes for SAG approval. Rugged/airborne hardware is excluded absent IAF evidence.

Official references: https://developers.yubico.com/PIV/Guides/Device_setup.html ; https://github.com/tpm2-software/tpm2-tools ; https://github.com/softhsm/SoftHSMv2 . Vendor HSM model and local price require RFI.
