# SAG evaluation preparation candidate

This is applicant preparation tooling for AIRON–SIEPMU / DISC-14 PS-69. It does not
issue an agency grade or authorise use of sensitive information. The required grade,
permitted crypto implementation, lab profile and acceptance criteria remain external
inputs. See the [evaluation dossier](../../docs/security-assurance/SAG_EVALUATION_DOSSIER.md).

## Build an inspectable candidate

Commit all intended changes, then execute on that clean commit:

```sh
npm ci --ignore-scripts
npm run validate
npm run test:e2e
npm run sag:package -- artifacts/sag-evaluation
```

The command prints the exact Git commit and `manifestSha256`. Use a new output
directory each time; existing directories are never overwritten. The package contains:

- The full committed source with original Git modes and SHA-256 file inventory.
- The application emitted by `npm run build`, checked against those same source bytes.
- The native-validation report and its ten fixed log files, plus the fresh application SBOM.
- A reviewed cryptographic inventory covering application, laboratory and optional tools.
- Twelve scope/authority requests and explicit unresolved qualification status.

No signing key is generated for this process. The package is unsigned applicant
evidence. Source includes laboratory PQC and NEXORA for inspection; the application
tree excludes them. Node/OS binaries, deployment images, live configuration and agency
documents are not bundled. Ignored runtime data is not copied. Common secret-bearing
paths, symlinks, submodules and special files are rejected. Filename rules are not a
content classification system: run the repository secret scan and review the candidate
before controlled handover. Historical committed reports are historical, not evidence
that a prior result applies to this candidate.

Packaging requires a clean Git tree, an exact-commit successful native-validation
report, matching execution runtime, no failed/skipped/cancelled tests, all required
gates, matching build bytes and a fresh SBOM. It also checks tracked file bytes even
when Git assume-unchanged flags hide modifications. Identical source, runtime and
captured evidence yield identical manifest bytes. This is package reproducibility,
not an independently reproduced binary-build or secure-runtime claim.

The validator report is locally authored. These checks prevent accidental stale or
inconsistent packages; they cannot prove that a dishonest producer executed tests.
Test discovery is scoped to source test directories so copied package tests are not
executed again; a regression checks coverage of all tracked `.test.mjs` files.
Other hosted jobs (browser, container, Rust, NEXORA, PQC, formal, network/testbed) have
separate evidence artifacts that the reviewer must obtain for the exact candidate.

## Verify after transfer

Deliver the manifest digest independently through the agreed channel. Use a trusted
checkout of the verifier, not executable code supplied by an untrusted package:

```sh
npm run sag:verify -- /path/to/received-package EXPECTED_64_HEX_MANIFEST_SHA256
```

The verifier runs without network access or npm runtime dependencies. It checks the
complete file set, bounds, digests, source inventory and Git tree/commit objects, built application, cryptographic
inventory and external-input report. Tampering, traversal, duplicates, symlinks,
unlisted files and self-awarded approval statuses fail. Protect the package directory
from concurrent modification while inspecting it; this is not a hostile local-kernel
or concurrent-filesystem-adversary boundary.

`MATCHES_EXPECTED_DIGEST` means only that the bytes match the supplied trust value.
Both `sagGrading` and `operationalAuthorization` remain `NOT_ESTABLISHED`.
Never use that result to issue sessions, release content keys or enable deployment.

## Review and scope inputs

`catalogue.json` is a human-reviewed inventory, not an exhaustive cryptographic scanner.
Its 14 components include password/TOTP, vault, transport and release cryptography as
well as document encryption. It binds 49 implementation/test files by hash. A change
to any bound file fails the inventory test and package builder until the inventory is
reviewed and its binding deliberately updated. Do not blindly refresh hashes to pass.
Dependency lockfiles for native, laboratory and optional components remain separate
inventories; no single SBOM here claims complete OS, firmware or browser coverage.

`requests.json` uses existing SAG/IAF clarification IDs, all pending. A supplied public reference
is always labelled `REFERENCE_SUPPLIED_UNVERIFIED`, even when every field is filled.
It never upgrades approval. Keep controlled correspondence, keys, algorithms, actual
personnel records and evaluator documents outside this public repository, using the
channel and handling rules specified by the sponsor.

The next external action is an IAF-sponsored SAG scoping request. No communication
or application is sent by these tools. Only the competent authority can establish
the applicable decision and its scope; component grading cannot be presumed to cover
an arbitrary configuration or the entire platform.
