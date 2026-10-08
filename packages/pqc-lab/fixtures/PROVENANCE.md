# Public test-vector provenance

Retrieved 2026-10-08 from the original authors and NIST through public GitHub resources. These values are public test vectors, not production credentials.

## X-Wing

Source repository: https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem

Source revision: `984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd`

Source file: [spec/test-vectors.json](https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.json)

Original Git blob: `a179e093a854c224e06680e33230bf82c3cd30f5`; 15,177 bytes. Local `xwing.json` preserves all three seed/eseed/sk/pk/ct/ss cases, with presentation formatting allowed. Never regenerate expected outputs using the implementation under test.

The author repository's LICENSE refers to CONTRIBUTING.md, which applies BCP 78, BCP 79 and IETF Trust Legal Provisions to contributions, including the code-component Simplified BSD terms. Source attribution and the IETF notice are retained in `../THIRD-PARTY-NOTICES.txt`. The draft text is https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11 . This is work in progress, not an IETF-endorsed standard.

## NIST ACVP

Source repository: https://github.com/usnistgov/ACVP-Server

Source revision: `975de31eb83d87039ec88934fdc47d8c312b892d`

Source directories under `gen-val/json-files/`:

- [ML-KEM-keyGen-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203): join `prompt.json` and `expectedResults.json` by `tgId` and `tcId`; retain the first two cases from each ML-KEM-768 and ML-KEM-1024 group. Local file `nist-mlkem-keygen.json` retains the exact input `d`, `z` and expected `ek`. Original prompt blob `0d701155b53e0da51cfffebd81abc6deb5be4878`; expected-results blob `883e318345b68382d09df05530c5209f4e509d54`.
- [ML-DSA-keyGen-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204): join the same filenames by case/group IDs; retain the first two ML-DSA-65 cases. Local `nist-mldsa-keygen.json` retains exact `seed` and expected `pk`.

NIST identifies this repository as its cryptographic validation test-vector generation/validation code. Public U.S. Government vectors do not grant certification or endorsement. These are selected known-answer checks; a full standards validation campaign and external assessment remain outstanding.
