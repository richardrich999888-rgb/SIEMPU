# ADR-004: three bounded processes with one authority writer

Status: accepted design; deployment and performance remain measured gates.

## Context

The baseline repository contains only README and Apache-2.0 licence; there is no existing application stack to preserve. R4 asks for cloud microservices, but the demonstrator does not require Kubernetes, a distributed log or many independent databases. Splitting transactional release state across services would make the central invariant harder to validate.

## Decision

Use Node 24 or later and native crypto, HTTP, WebCrypto and `node:sqlite`; no npm runtime dependencies. Deploy three bounded processes: web gateway (8080), control authority (8081), and blind ciphertext relay (8082). Gateway serves the clients and forwards protected operations. Control owns identity/device/policy/admission/evidence in one database; relay owns ciphertext and workload replay nonces in a separate database. Authenticated internal service requests and network isolation are required; being on an internal port grants no authority.

Use WAL, `synchronous=FULL` and explicit serialised write transactions. Schema versioning and migrations are controlled source, not handwritten operator SQL. Bind locally by default; use a configured TLS boundary for any non-loopback deployment. Secrets and private state stay outside source and release artifacts.

This is a single-host prototype deployment. It demonstrates bounded service interfaces without claiming horizontal high availability, independently scalable authority writers or a certified defence cloud. Authority modules deliberately share a transaction boundary. Moving them into separately owned state is a future ADR requiring a replacement consistency proof.

## Consequences

The small runtime dependency surface improves inspectability but does not eliminate vulnerabilities in Node, OpenSSL, SQLite, the OS, containers, browser or development tools. SBOM and supply-chain review must include the runtime/container boundary. No npm packages is not the same as no third-party software.

Benchmark the actual single-host concurrency, queue, CPU, memory and storage envelope. A passing local HTTP run does not validate internet TLS configuration or container isolation. A built container, a scanned container and a remotely executed CI job are separate evidence classes.
