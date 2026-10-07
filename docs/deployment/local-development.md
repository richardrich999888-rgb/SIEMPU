# Local development

Use synthetic data only. The runnable stack is Node.js 24.19.0 with npm and Git. GNU Make
is optional: every Make target delegates to the npm command listed below. Docker with the
Compose plugin is optional for container validation; it is not needed for native development.
There is no separate database daemon or frontend dependency installation.

## Fresh checkout

```sh
git clone https://github.com/richardrich999888-rgb/SIEMPU.git
cd SIEMPU
git switch feature/repository-foundation
node --version
make setup
cp .env.example .env
```

Review `.env` before loading it. Defaults bind the three processes to loopback. `.env` is
ignored by Git and is not loaded implicitly by the application. In a POSIX shell, load the
reviewed development settings explicitly:

```sh
set -a
. ./.env
set +a
make bootstrap
make dev
```

Bootstrap creates random synthetic user credentials, distinct users/units/devices and initial
policy under `.data`; file permissions are restricted. It opens the database through the
versioned migration runner before seeding it. There is no manual SQL initialization step.
It refuses to overwrite an existing database. Subsequent starts apply pending versioned
migrations when the authority opens the database. See [database](../database.md).

`make dev` starts relay (8082), authority (8081) and web gateway (8080) together. Open
`http://localhost:8080/` for the unit client or `http://localhost:8080/admin` for administration.
Follow the [demo runbook](../hpsc/demo-runbook.md) to enroll the synthetic device and log in;
the private profile file is local test material and must not be committed or uploaded.
Stop with Ctrl-C. Startup fails if bootstrap state is missing; it does not silently provision.

In a second terminal, verify readiness:

```sh
curl --fail http://127.0.0.1:8080/health/ready
make e2e
```

The acceptance suite provisions its own temporary users, units, devices and SQLite stores and
uses ephemeral HTTP ports. It does not depend on or modify the running developer's `.data`.

## Developer commands

| Make command     | npm equivalent                  | Boundary                                                            |
| ---------------- | ------------------------------- | ------------------------------------------------------------------- |
| `make help`      | `npm run help`                  | Describe commands; npm help delegates to Make                       |
| `make setup`     | `npm run setup`                 | Locked install with lifecycle scripts disabled                      |
| `make bootstrap` | `npm run bootstrap`             | Explicit fresh synthetic provisioning                               |
| `make dev`       | `npm run dev`                   | Supervise all three application processes                           |
| `make build`     | `npm run build`                 | Allowlisted runtime files and SHA-256 manifest in `dist/`           |
| `make test`      | `npm test`                      | Node unit, integration and acceptance tests                         |
| `make lint`      | `npm run lint`                  | ESLint                                                              |
| `make typecheck` | `npm run typecheck`             | Strict checkJs scope in `tsconfig.json`; not all modules            |
| `make security`  | `npm run security`              | Narrow local repository rules                                       |
| `make e2e`       | `npm run test:e2e`              | Vertical slice, revocation and authorized backlog HTTP acceptance   |
| `make browser`   | `npm run test:browser:isolated` | Fresh isolated Chromium workflow with cleanup                       |
| `make ci`        | `npm run ci`                    | Local quality, coverage, acceptance, security rules, build and SBOM |

For browser validation, install the pinned browser once, then run the isolated runner:

```sh
npx --no-install playwright install --with-deps chromium
make browser
```

Browser evidence uses synthetic content only. Full dependency, secret, CodeQL and image
scans are separate [hosted gates](../ci-cd.md). `make ci` passing does not assert those hosted
gates passed, and it does not assert a Docker build occurred.

## Optional containers

```sh
docker compose config --quiet
make docker-build
docker compose run --rm bootstrap
docker compose up -d --wait --wait-timeout 90
curl --ipv4 --fail http://localhost:8080/api/meta
docker compose down
```

The Compose defaults expose only loopback port 8080 and use internal HTTP for this single-host
synthetic stack. Reuse the existing volumes on subsequent runs; do not rerun bootstrap against
provisioned state. `docker compose down` preserves state. Removing volumes intentionally erases
synthetic identities and stored objects, so do it only when resetting your own disposable demo.

This execution workspace has no Docker binary. Container build/start/scan evidence must come
from an observed successful hosted `CI / container` job for the candidate commit. The manifests
alone do not prove a working container. No CD workflow is active.
