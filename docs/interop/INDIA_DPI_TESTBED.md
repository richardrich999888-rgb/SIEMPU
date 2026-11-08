# India public-interface laboratory profile

This is an opt-in **local synthetic DX resource-proxy reader**, excluded from the application
bundle. Live government interoperability and formal qualification are not established.

## Pinned contract and deliberate subset

- Upstream: [DataKaveri DX proxy OpenAPI](https://github.com/datakaveri/dx-rs-proxy/blob/a6d2bbb2199f1db65aa67e7b807c5241aea2895c/docs/openapi.yaml),
  commit `a6d2bbb2199f1db65aa67e7b807c5241aea2895c`, API 5.6.0 / OpenAPI 3.0.2.
- Retrieved source SHA-256: `8e11d6138029dd94d3915472aa8bc46934fcc89f0a1b85a8a91b51315acf74c4`.
- Request: `GET /ngsi-ld/v1/entities?id=<UUID>`; `token` header, at most 512 characters.
  The upstream pattern permits alphanumerics, `/`, `@`, `.`. This profile additionally rejects
  empty tokens. This is syntax checking, not provider authentication or a generic JWT validator.
- Upstream `entityresponse` describes object properties `type`, `title`, `results`; its example
  uses `urn:dx:rs:success`, resource IDs and pagination. It does **not** make these fields required.
  `SIEPMU_DX_READ_V1` intentionally requires them and rejects unknown root fields. This narrower
  application profile is not full schema equivalence or exhaustive upstream conformance.
- Every result must be an object with the requested `id`. Optional `limit`, `offset`, `totalHits`
  must be nonnegative safe integers. At most 1,000 results, depth 32 and 20,000 visited values.
  Prototype-related keys and nonfinite numbers are refused. Other result properties stay untrusted.
- UTF-8 JSON only; default 256 KiB, hard ceiling 1 MiB. Streams are bounded as consumed; there is
  no `text()` fallback. Whole-request deadline defaults to 2 seconds, configurable 10–10,000 ms.
  Invalid content, status, redirection or schema raises a fixed error code, never an upstream body.
- HTTP 204 returns `EMPTY`; successful content returns `RECEIVED_UNTRUSTED`, an immutable value and
  raw-byte digest. This digest does not establish truth, signatures, freshness or local authority.
- The spec's `example-proxy.com` server is a placeholder. The general IUDX resource-server guide
  describes `/entities/{id}`; that is a **different interface**, not implemented by this adapter.

## Transport and authority boundaries

`readIudxEntity` requires an explicitly injected trusted transport; it has no ambient networking.
The concrete `createIudxLoopbackReader` requires `enabled: true`, a private CA and canonical literal
`127.0.0.1` or `[::1]` HTTPS origin. It reuses TLS 1.3 with peer verification, byte/deadline limits
and no redirect following. DNS aliases, public hosts and arbitrary TLS overrides are unavailable.
The generic contract helper is not a public-network SSRF defence; a future public transport needs
reviewed DNS/IP egress controls, owner-authorized origin, credentials and lifecycle policy.

Provider tokens cannot become SIEPMU users, devices, mission roles or release grants. No response
triggers automatic import, URL following, document rendering or forwarding. The optional reader
runs at an endpoint; neither plaintext nor provider credentials enter the SIEPMU relay/authority.
An explicit synthetic import test seals returned content with locally selected sender/recipient
keys and traverses normal admission and policy release. Embedded roles remain ordinary data.
There is no production import route, provider-token exchange or SIEPMU authority mapping.

## Independent reproduction on a frozen revision

Use Node 24.21.0 (CI), OpenSSL CLI for temporary test CA generation and the existing lockfile.
The full evaluation uses Docker/Linux netem, Rust and Java as documented in the repository.

```sh
# In a checkout of the exact candidate SHA, with a clean working tree:
npm ci --ignore-scripts --no-audit --no-fund
npm run validate
npm run test:e2e
node scripts/interop-assurance.mjs artifacts/interop-observer-01
npm run test:adversarial -- artifacts/adversarial-observer-01
node assurance/sag/package.mjs artifacts/evaluation-observer-01
```

Use new artifact directories on every run. The interop runner refuses dirty source, checks the
entire committed tree before/after, retains failing TAP output, and writes raw timing samples,
source index, hashes, signed synthetic evidence, public verification key and the readiness report.
Its manifest digest must be retained independently; self-authored hashes are not independent
assessment. CI uploads this directory as `government-interop-assurance` on the exact checkout.

For a focused development check, including on a dirty working tree:

```sh
node --test --test-concurrency=1 tests/india-dpi-iudx.test.mjs scripts/policy-release-comparison.test.mjs
```

Such a development result is not frozen-candidate evidence. Tests cover origin confusion, malformed
credentials, oversized/invalid responses, schema drift, TLS identity, deadlines, cancellation,
redirect token leakage and actual local authority denial. See the full adversarial plan for
replay, cross-mission, ciphertext tampering, provider failure, crash and recovery coverage.

## Live interface gate — still blocked

Provide the exact resource/proxy version, intended unclassified use case, owner-permitted test
origin/resource and scoped token through a secret channel. Confirm data-owner permission and
retention/consent rules. Review public-network transport, freshness, audit and endpoint content
inspection before adding it. Do not reuse an API Setu token, IUDX token or MOSIP identity as
military identity. No government API transaction was performed by these tests.

[Government Interoperability and Defence Assurance Report](GOVERNMENT_INTEROPERABILITY_AND_DEFENCE_ASSURANCE.md)
contains the candidate-selection decisions, public sources, traceability and external gaps.
