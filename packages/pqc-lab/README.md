# Endpoint post-quantum laboratory

This package provides executable endpoint cryptography experiments. No relay or control service should instantiate an engine containing recipient private handles. It does not establish independent cryptographic review, constant-time JavaScript, FIPS module validation, SAG grading, IAF approval or a TRL decision.

The root application retains no runtime npm dependencies. `native-provider.mjs` uses Node 24.19.0 or later in the 24.x line and its bundled OpenSSL. Only `xwing-provider.mjs` requires the separate, pinned Noble package. No provider silently falls back to a different algorithm.

```sh
node --test tests/pqc/native-provider.test.mjs
npm ci --prefix packages/pqc-lab --ignore-scripts
npm --prefix packages/pqc-lab test
node packages/pqc-lab/benchmark.mjs > artifacts/pqc-benchmark.json
```

Create `artifacts/` before redirecting the benchmark. All test material is public synthetic data. Root tests exercise native cryptography without installing Noble. The isolated `laboratory.check.mjs` runner is invoked explicitly; it never silently skips missing dependencies.

## Provider contract

`createNativePqcProvider()` and `createXwingLabProvider()` implement provider API version 1. Each returns `descriptor` and async `generateKey`, `sign`, `verify`, `encapsulate`, and `decapsulate` methods. The engine supplies an explicit suite ID on every call. Public keys encode exact fields `{algorithm, format: 'raw-public', bytes}` and encapsulations encode `{algorithm, ciphertext}`; byte strings use canonical unpadded base64url. Unknown fields, mixed algorithms, malformed encodings and wrong key purposes fail closed.

| Provider ID            | Suite ID                               | Key establishment             | Signature         |
| ---------------------- | -------------------------------------- | ----------------------------- | ----------------- |
| `node-openssl-pqc-lab` | `ML-KEM-768-ML-DSA-65-AES-256-GCM-v1`  | OpenSSL ML-KEM-768            | OpenSSL ML-DSA-65 |
| `node-openssl-pqc-lab` | `ML-KEM-1024-ML-DSA-65-AES-256-GCM-v1` | OpenSSL ML-KEM-1024           | OpenSSL ML-DSA-65 |
| `noble-xwing-lab`      | `X-WING-ML-DSA-65-AES-256-GCM-v1`      | Noble published X-Wing preset | OpenSSL ML-DSA-65 |

All suites set `laboratory: true`; the engine rejects them under production policy. Suite versions are independent of envelope schema versions. AES-256-GCM content encryption and the engine's authenticated KEM-DEM key wrapping remain separate from X-Wing's fixed published internal composition. No custom hybrid combiner is implemented here.

The native provider holds KeyObjects in a private WeakMap. The X-Wing provider holds software byte arrays in a private WeakMap. Callers receive opaque frozen tokens. This is an application API boundary: Node KeyObjects and JavaScript heap memory are not hardware-backed, and process compromise can expose secrets. Garbage collection and zeroization cannot be guaranteed. These providers do not yet implement durable key backup, hardware custody or endpoint recovery.

## Evidence and limits

- Four NIST ACVP ML-KEM-768/1024 key-generation cases and two ML-DSA-65 key-generation cases are checked against independently supplied expected public keys.
- Three complete author X-Wing known-answer vectors cover deterministic key generation, encapsulation and decapsulation.
- Node/OpenSSL and Noble ML-KEM-768/1024 interoperate in both directions. ML-DSA-65 signatures verify in both directions.
- Provider/engine tests cover authenticated context, ciphertext alteration, suite substitution, wrong-purpose handles, revoked keys and the production-policy gate.
- These checks are selected conformance evidence, not exhaustive CAVP/ACVP validation. Native Node does not expose ML-KEM encapsulation coins, so deterministic native encapsulation KAT coverage is not claimed. The ML-DSA tests do not constitute the full FIPS 204 signature conformance corpus.

Noble 0.7.1 is MIT licensed and uses pinned Noble ciphers/curves/hashes 2.4.0. Upstream explicitly states that the post-quantum library has not been independently audited and does not claim constant-time JavaScript execution. Its preset was documented against X-Wing draft-10; this experiment also reproduces the vectors published with the author's current draft-11 source. X-Wing remains an individual draft, not an IETF-endorsed standard. Independent review is mandatory before enabling this profile outside an isolated laboratory.

An ML-KEM decapsulation may return an unrelated secret on a corrupted ciphertext instead of throwing. Authenticated key unwrapping must reject that result; tests exercise this behavior. A KEM alone supplies neither sender authentication nor forward secrecy after recipient long-term private-key compromise. This package adds no messaging ratchet. Rewrapping historical content does not make already captured classical ciphertext quantum-resistant.

## Benchmark interpretation

`PQC_BENCH_REPETITIONS` selects 5–1000 iterations (default 30); `PQC_BENCH_PAYLOAD_BYTES` selects 1–1048576 synthetic bytes (default 65536). JSON output records commit, dirty-tree flag, source digests, runtime/provider versions, host CPU/OS, operation latency, throughput, process CPU/memory, byte sizes, failures and limitations. Compare provider workloads on the same host. Shared virtual hardware, first-use costs and garbage collection prevent broad performance claims. Root application release/reconnection measurements are a separate integration experiment.

See `fixtures/PROVENANCE.md`, `THIRD-PARTY-NOTICES.txt` and `research/cryptographic-standards/` for sources and the external review gate.
