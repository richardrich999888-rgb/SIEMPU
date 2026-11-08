# India public digital infrastructure interoperability — IUDX contract candidate

**Status: local synthetic contract tests, NOT government approval or live IAF integration.**

## Official references and intended applicability

- Public DX/IUDX Resource Proxy OpenAPI 3.0.2, v5.6.0: https://github.com/datakaveri/dx-rs-proxy/blob/main/docs/openapi.yaml
- Government-backed API Setu sample-data sandbox: https://sandbox.api-setu.in/
- Government open API access rules: https://docs.apisetu.gov.in/document-central/api-policy/Policy%20Statement.html
- Government-linked OpenForge project platform: https://openforge.gov.in/openforge/about.php

The code implements **only** the published read-only DX resource-proxy request:
`GET /ngsi-ld/v1/entities?id=<UUID>` with the vendor-documented `token` header.
It uses **no DX source code**, has **no new dependencies**, and is not loaded in
the production SIEPMU runtime.

## Reproduce the validation

```sh
node --test tests/india-dpi-iudx.test.mjs
```

The eight synthetic checks cover exact HTTPS origin allowlisting, the API
path/token/header shape, malformed ID/token rejection, non-sensitive error
reporting, upstream denial/redirect/error behavior, response content type and
JSON validation, bounded response sizes and streaming refusal. These are
contract tests on an injected *local fake transport*, not a live DX test.

## Threat boundary — mandatory before any further integration

1. An IUDX API token grants only data-provider permissions under that provider's
   rules. It does **not** represent an IAF personnel identity, SIEPMU device
   approval, local mission role or authority to receive a wrapped key.
2. IUDX responses are **untrusted external content**. This prototype neither
   imports files, nor seals any message, nor submits information to SIEPMU.
   A future bridge needs written data-sharing authorisation, classification
   controls, user consent where applicable, provenance, malware handling,
   local sender approval and the normal SIEPMU encryption/policy checks.
3. No IAF/DRDO system, government sandbox, C-DOT lab or production IUDX server
   was contacted during testing. No real credentials or sensitive data used.
4. API Setu's sandbox is suitable for separate sample-data experiments only.
   There is no asserted compatibility between its products and IUDX.
5. This integration does not establish cryptographic approval, SAG grading,
   government sponsorship, TRL 5 or procurement eligibility.
6. The adapter supports incremental body-size limits on Fetch streams. The
   text-only response fallback is for unit-test mocks, not an approved live
   transport. TLS client policy, response schemas, certificate operations,
   consent checks and safe data mapping need independent review before any
   authorised live connection.

## ASTRA review handoff

Run the exact test command, record the commit, Node version, test outputs and
failure list. Perform adversarial mutation tests for token leakage, redirects,
SSRF, schema drift and cross-domain data handling. ASTRA should report each
claim as `MOCK_TESTED`, `SOURCE_REVIEWED`, `LIVE_OWNER_AUTHORIZED` or
`EXTERNAL_APPROVAL_PENDING` — never convert mock success into certification.

### Next gates

- Written operational use case and data classification permission from the
  relevant authority (if defence-related).
- Approved test origin, access method and scope from IUDX/API Setu owner.
- Live sandbox conformance tests only in the officially permitted environment,
  with rate limits and an explicit allowlist.
- Separate SIEPMU-source-endpoint policy, file inspection, audit and adversarial
  tests before considering any information transfer.

This is an isolated research connector suitable for review and further
development; it is not a plug-in to any classified or restricted network.
