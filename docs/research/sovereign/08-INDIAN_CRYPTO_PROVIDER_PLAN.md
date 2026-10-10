# 08 — Indian cryptographic-provider integration plan (Track D)

Status: **plan.** No Indian, graded or hardware provider is integrated. Nothing here claims SAG grading,
indigenous ownership of any algorithm, or the existence of any specific Indian interface. Interfaces of
C-DAC, C-DOT, SAG-approved modules or Indian HSM vendors must be **obtained from them**; until then the
sponsor questions in `research/trl56/16-iaf-clarification-register.md` stand.

## 1. What already exists (verified in code)

| Capability                  | Where                                                                | Behaviour                                                       |
| --------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------- |
| Provider identification     | `ProviderRegistry` (`packages/crypto-provider/registry.mjs`)         | `descriptor.id`, `apiVersion === 1`, declared suites            |
| Approved suite registration | Same + `policy.mjs`, authority `services/crypto-policy/registry.mjs` | Allow-list in persisted policy; lab suites need explicit opt-in |
| Key generation              | `CryptoEngine.generateKey`                                           | Provider-generated, handles tracked in key inventory            |
| Encapsulation/decapsulation | `encapsulate` / `decapsulate`                                        | Provider-implemented                                            |
| Signing/verification        | `sign` / `verify`                                                    | Provider-implemented                                            |
| Rotation and revocation     | `rotateKey`, `revokeKey`, `retireKey`, `migrateKey`                  | Lifecycle events hash-chained in engine evidence                |
| Provider health             | `CryptoEngine.health()`                                              | Per-provider status                                             |
| Explicit failure            | `resolve()` throws "fallback is forbidden"                           | No silent fallback to another provider or a weaker suite        |
| Downgrade prevention        | Suite and provider in signed context and AAD                         | `tests/crypto-agility/`                                         |

## 2. Gaps that block a real Indian or hardware provider

| #   | Gap                                                                                                   | Fix (engineering, inside this repository)                                                                |
| --- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| G1  | Registry requires `contentEncryption === 'AES-256-GCM'`; a graded suite with another AEAD is rejected | Make content AEAD a provider operation with its own suite field; ADR + negative tests                    |
| G2  | Providers are in-process JavaScript; no native boundary for PKCS#11/TPM                               | Native provider host (Rust, `forbid(unsafe)` except FFI shim) behind a local socket, per ADR-012 process |
| G3  | Key handles are software objects; no non-exportable handle type                                       | Handle type carrying provider, slot and attestation; engine never sees key bytes                         |
| G4  | No attestation of provider identity (which module, which firmware)                                    | Record module identity and version in key inventory and release evidence                                 |
| G5  | Authority-side verification of provider signatures uses OpenSSL only                                  | Verification adapter per suite, selected by signed suite ID                                              |
| G6  | Wire format names suites by string; no registry of OIDs for future Indian algorithms                  | Suite registry document with stable identifiers, versioned                                               |

## 3. Integration architecture (target)

```text
 Endpoint app ──► CryptoEngine (policy, lifecycle, evidence) ──► ProviderRegistry
                                                         ├─► classical (WebCrypto/OpenSSL)          [exists]
                                                         ├─► pqc-lab (OpenSSL ML-KEM/ML-DSA, Noble)  [lab only]
                                                         └─► native-host (local socket, mTLS or UDS)  [G2]
                                                                 ├─► PKCS#11 v3.1 module (Indian HSM / token)
                                                                 └─► TPM 2.0 (endpoint key custody)
```

Rules: the native host is a trusted local process, never a remote plugin; it holds no policy; each provider is
selected only by the signed `providerId`/`suiteId`; failure is an explicit error, never a fallback.

## 4. Qualification path (external; this repository cannot complete it)

1. Sponsor names the approved algorithm set and module (SAG decision).
2. Vendor supplies the module, its interface specification and test vectors.
3. SYNTRIASS implements the provider adapter against that specification, adds the vendor's vectors to the KAT
   harness (`assurance/kat/`), and runs the existing crypto-agility negative suite against it.
4. Independent evaluation of the integrated system (STQC/CERT-In-empanelled lab, sponsor-designated).
5. Only after 1–4: any statement about graded or indigenous cryptography, with the evidence reference.

## 5. Laboratory steps that can start now (no external dependency)

- G1 and G6 (pure software, testable now).
- PKCS#11 adapter against SoftHSM2 as a **test double** (registry entry: test-only, no hardware assurance),
  to prove the native-host boundary and the non-exportable handle model before any vendor arrives.
- TPM 2.0 adapter against a software TPM (swtpm) in the testbed, same caveat.

## 6. Claims guidance

Allowed: "provider-neutral seam with fail-closed suite selection; laboratory post-quantum candidates; ready to
integrate an approved provider once its interface is supplied." Not allowed: "indigenous crypto", "SAG-graded",
"quantum-proof", "HSM-backed" (until hardware is integrated and tested).
