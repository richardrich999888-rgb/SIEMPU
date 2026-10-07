# Reproducible synthetic deployment

This is a single-host demonstrator. It is not SAG graded, accredited, highly available, hardware attested, or approved for classified information. The three services are independently running processes. The control authority deliberately keeps identity, current policy, release issuance and evidence in one SQLite transaction boundary.

## Local Node execution

Install Node 24.19.0. The running application has no npm dependencies. Pinned development tools are installed by `npm ci` for linting, formatting and scoped static type checking.

```sh
npm ci --ignore-scripts
npm run check
npm test
npm run security
npm run bootstrap
npm start
```

Open `http://localhost:8080/` for the unit workspace and `http://localhost:8080/admin` for administration. Bootstrap creates only synthetic identities and local protected files under `.data`; read the bootstrap output for enrollment instructions. It is explicit and never runs as a fallback during login or application startup. Never attach this synthetic identity population to an operational network.

The gateway binds loopback on port 8080. Authority and ciphertext relay bind loopback on 8081 and 8082. Stop the parent with Ctrl-C; it terminates all three children. The startup script fails on missing provisioning rather than generating credentials. Environment settings are documented in `.env.example`; the process environment must be populated explicitly (the app does not implicitly load `.env`).

Health: `/health` and `/health/live` are liveness endpoints on the gateway and relay; `/health/ready` checks authority availability on the gateway and database usability on the relay. Authority's `/health` is used for its container health check. Health responses do not disclose identities or secrets.

## Container execution

Docker and Compose must be installed on the operator machine. They are not available in the development execution workspace, so local image build and Compose execution are **NOT VERIFIED** there. The checked-in CI workflow builds and starts this configuration on an actual Docker runner; a successful observed run is required before describing container deployment as tested.

```sh
docker compose build
docker compose run --rm bootstrap
docker compose up -d --wait
curl --fail http://localhost:8080/api/meta
docker compose down
```

The optional `bootstrap` profile is enabled implicitly by `compose run bootstrap`. Provisioning writes a control volume and a separate volume containing only the relay workload key. The relay cannot mount the identity database, master encryption key, signing private key, or user profiles. Its separate volume contains ciphertext and HMAC replay nonces only. This is a logical workload separation; the host administrator and Docker daemon remain trusted.

Each container runs UID/GID 1000, a read-only application filesystem, dropped Linux capabilities, no new privileges, restricted temporary storage and PID/memory limits. The only published port is gateway port 8080 on host loopback. Two internal networks restrict ordinary service reachability; only the gateway also joins an edge bridge for its loopback-published ingress. The gateway therefore has an outbound network path that requires operator egress policy in any managed deployment; Docker host administrators can still cross these boundaries. Internal HTTP is explicitly enabled only for this synthetic local configuration. TLS is not implied by Docker networking.

The image is pinned to `node:24.19.0-bookworm-slim` by registry manifest digest in Dockerfile. Pinning provides reproducibility, not freedom from vulnerabilities. Review security scans and update the pin when required.

## TLS and managed deployment gate

For any access beyond the host, provision an approved TLS reverse proxy and DNS name, set `SIEPMU_PUBLIC_ORIGIN` to that exact HTTPS origin, and keep direct authority and relay ports inaccessible. TLS termination is operator supplied; this repository does not issue or trust production certificates. Between independently administered hosts, replace internal HTTP with authenticated TLS. The relay HMAC protects requests and replay but does not conceal metadata or transport bytes.

The gateway uses an exact origin check, loopback/configured Host allowlist, JSON mutation requests, fixed upstream URL, browser security headers, no CORS allowance, no caller-controlled forwarding headers, and a static asset allowlist. Sessions remain in client memory. A compromised distribution server can replace browser code; CSP does not cure that trust-boundary failure.

## State and recovery

Authority: `.data/control.sqlite` plus WAL; server signing key, master key, relay key and protected synthetic provisioning output. Relay: separate SQLite ciphertext database and replay nonces. Endpoint: encrypted local vault. Secrets are files provisioned on the host, not HSM protected. Protect access to both the live volumes and backups; encrypted user content does not make identity metadata nonsensitive.

Stop writers before making a complete demonstrator backup, or use a validated SQLite backup workflow. Restore consistent authority database/key state; never mix an older database with newer current-state claims. Full database snapshot rollback is not prevented by local epoch counters. Retain signed evidence checkpoints outside the authority host if suffix truncation must be detected. Restart tests prove durable restart, not adversarial anti-rollback or disaster-recovery readiness.

`docker compose down --volumes` destroys all provisioned identities, keys, relay blobs and evidence. It appears only in disposable CI cleanup and should not be used on retained demonstrations.

Before any operational pilot: approved identity enrollment, endpoint hardening, TLS deployment, secure key custody, backup/restore exercise, image vulnerability review, penetration test, log retention/access controls, IAF interface definitions and SAG/assurance decisions remain required. These are deployment boundaries, not claims that the prototype has passed approval.

## Public build metadata

`GET /api/meta` returns optional `build.revision` and `build.builtAt`. Docker CI supplies the checked-out commit SHA and UTC build timestamp through build arguments; local unconfigured values are `null`. The fields are operator declarations, not remote attestation or evidence of IAF approval. They do not establish that a dirty local checkout equals a commit. The image revision/timestamp labels carry the same supplied values.

## Controlled identity recovery

The prototype has an offline maintenance workflow for password/TOTP recovery: stop services, retain current protected state, and invoke `scripts/recover-identity.mjs` with explicit maintenance acknowledgement and a new private output path. The recovery transaction replaces the password/MFA material, revokes every existing session for that identity, increments authority/revocation versions and writes evidence/alert records. It preserves device approval state; a stolen or untrusted device must be revoked separately. Delivery of new MFA material and identity proofing remain controlled operator responsibilities. This is a tested synthetic recovery mechanism, not an accredited recovery ceremony or a substitute for independent identity verification.
