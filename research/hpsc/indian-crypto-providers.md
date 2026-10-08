# Indian cryptographic providers: public-source landscape (research record)

**Retrieved:** 8 October 2026.

**Method:** web search. Primary hosts were unreachable from the build environment: DNS failed or
the proxy blocked them. This covered commoncriteria-india.gov.in, stqc.gov.in, drdo.gov.in,
bel-india.in, qnulabs.com, emudhra.com and csrc.nist.gov. Values are search-index excerpts and must
be confirmed on the primary page before they appear in a filed document.

**Purpose:** planning only. SIEPMU's provider port (`packages/crypto-provider/`) stays
interface-neutral until a vendor supplies its interface specification.

| Provider / product                                    | Type                          | Public interface                         | Publicly stated assessment                                                                                                | Source (indexed)                                     |
| ----------------------------------------------------- | ----------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| C-DOT Compact Encryption Module (CEM1_1_1.23_1)       | IP/L2 encryptor appliance     | Not stated                               | IC3S Common Criteria **EAL3**, report IC3S/KOL01/EAL3/0720/0024/CR (ERTL(E) Kolkata). No SAG statement                    | commoncriteria-india.gov.in (CR-CDOT-CEM_EAL3_0.pdf) |
| C-DOT quantum product series (Q-VIKRAM and others)    | PQC/QKD link encryptors       | Not stated                               | "NIST PQC algorithms" (unnamed); TEC certification described as under way; throughput figures from secondary sources only | quantumcomputingreport.com; opengovasia.com          |
| BEL L2-L4 encryptor, IP encryptor, SMILE Mk II        | Network and link encryptors   | Physical/NMS interfaces; no software API | "Designed as per the guidelines of CPC/SAG for desired grading": a design intent, not a stated grade                      | bel-india.in product pages                           |
| QNu Labs Cryptographic Module                         | Software library              | Not stated                               | **FIPS 140-3 cert #5234, Level 1** (search extract; NIST site unreachable)                                                | csrc.nist.gov CMVP certificate 5234                  |
| QNu Labs QShield / QHSM / Armos / Tropos              | PQC platform, HSM, QKD, QRNG  | Not stated                               | Vendor claims "FIPS 203/204 compliant" (marketing); no certificate found for the HSM                                      | qnulabs.com                                          |
| eMudhra emCA                                          | PKI / certification authority | Not stated                               | Claims PQC signature support; HSM certifications claimed without model or certificate numbers                             | emudhra.com                                          |
| SecureMachines Prastaara                              | HSM (PQC + classical)         | Not stated                               | None stated                                                                                                               | pkic.org member page                                 |
| JISA Softech with IIT Kanpur; IIT Madras with LG Soft | HSM research and development  | n/a                                      | None (development stage)                                                                                                  | iitk.ac.in; cystar.iitm.ac.in                        |
| SETS Chennai                                          | PQC/QRNG research             | n/a                                      | None; "Bharat PQC algorithms" mentioned in the MCTE–SETS MoU                                                              | psa.gov.in                                           |

## Findings for planning

1. No Indian provider found publicly confirms that it **holds** a SAG grade. SAG grading is
   therefore an external gate that the sponsor must define (open questions Q04, Q15).
2. No Indian vendor found publicly documents PKCS#11, KMIP or SDK interfaces. Interfaces will
   have to come from vendors under NDA (Q16).
3. Assessment schemes:
   - **IC3S** (STQC, Common Criteria): covers EAL1–EAL4.
   - **STQC ERTL(N)**: evaluates cryptographic modules to ISO/IEC 19790. No public list of
     validated modules was found.
4. National PQC roadmap: a DST/National Quantum Mission task-force draft (February 2026) targets
   quantum-resilient critical information infrastructure by 2029. Whether a final version has been
   published is **unconfirmed**.

## Implication for the SIEPMU roadmap

Budget an Indian-provider qualification work package:

1. Request vendor interface specifications.
2. Build a provider adapter behind the existing port, with a conformance test suite.
3. Run interoperability tests against the vendor's evaluation unit.

The vendor's own certification evidence, and the SAG process, stay external dependencies.
