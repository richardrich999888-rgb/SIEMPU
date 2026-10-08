---
name: siepmu-research-and-dependencies
description: Researching public standards (NIST FIPS 203/204/205, IETF hybrid KEMs, HPKE, PKCS#11, TLS), open-source libraries, hardware security options (TPM, FIDO2, HSM), vendors, licences and software supply chain for SIEPMU, and adding or updating dependencies. Use before adding any npm package, citing a standard, recording a source, or evaluating hardware or vendor options.
---

# SIEPMU research and dependencies

## Dependency policy

- Root runtime has **zero npm dependencies**; `scripts/check.mjs` fails if `dependencies` appears
  in `package.json`. Dev tools are pinned exactly in `devDependencies` with a lockfile.
- Laboratory-only dependencies live in their own package (`packages/pqc-lab/package.json`, pinned
  `@noble/post-quantum` 0.7.1 with lockfile) and are excluded from release artefacts (ADR-008).
- New dependency checklist: need justified vs Node built-ins; exact version pin; licence compatible
  with Apache-2.0 and recorded in `THIRD-PARTY-NOTICES`; maintenance and audit status stated;
  `npm audit --audit-level=high` clean; SBOM regenerated (`npm run sbom`); install with
  `--ignore-scripts`.
- Registers: `research/trl56/software-dependency-registry.json`, `docs/SUPPLY_CHAIN_SECURITY.md`,
  `docs/supply-chain.md`.

## Source discipline

- Primary sources only: NIST CSRC (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, SP 800-227
  KEM guidance), IETF datatracker (drafts and RFCs, e.g. RFC 9180 HPKE), OpenSSL release notes,
  OASIS PKCS#11, TCG, W3C WebAuthn, vendor datasheets for vendor claims only.
- Record each source with retrieval date, revision/commit, and what it establishes. Drafts are
  "work in progress", not standards. Test vectors keep provenance (`packages/pqc-lab/fixtures/PROVENANCE.md`).
- Distinguish: specification (what conforming code must do), implementation source (inspectable,
  not evaluated by us), supplier claim, and our own executed result.
- Current records: `research/cryptographic-standards/CURRENT_STANDARDS.md`,
  `research/cryptographic-standards/INDEPENDENT_REVIEW.md`, `research/trl56/02-*`, `03-*`, `12-*`.
- Note: `research/defence-comparison/sources.json` records D04-D15 were destroyed by corrupted
  publication and are flagged; re-retrieve before relying on them.

## Hardware and custody options (study only until authorised)

TPM-backed keys, FIDO2/WebAuthn login, PKCS#11/HSM providers, attestation: see
`docs/security-assurance/key-custody-matrix.md` and `research/trl56/03-external-hardware-and-security-addons.md`.
SoftHSM/swtpm are acceptable software test doubles; they do not establish physical protection.
Purchases and classified integrations require external authorisation.

## Network access caveat

The build container's egress policy may block some hosts (observed: `idex.gov.in` DNS failure,
GitHub artefact blob storage 403). Record when a source could not be retrieved; never fill gaps
from memory as if retrieved.

## Definition of done

Source recorded with date and revision, claim type labelled, dependency checklist satisfied,
`npm run validate` and `npm run sbom` pass.
