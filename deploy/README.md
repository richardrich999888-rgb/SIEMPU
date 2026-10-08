# Deployment entry points

The executable local deployment is maintained once: [`compose.yaml`](../compose.yaml),
[`Dockerfile`](../Dockerfile), and the bootstrap/health helpers in [`deployment/`](../deployment/).
See [local development](../docs/deployment/local-development.md) for tested native commands
and the separate Docker verification gate. This directory does not duplicate those manifests.

There is no staging or production deployment pipeline. The previous manually dispatched
artifact packaging recipe is retained at `disabled-workflows/release.yml` for review, outside
GitHub's workflow discovery directory. It is inactive. It must not be restored until CI and
security gates pass for the candidate commit and release requirements are reviewed.

Before proposing a deployment beyond the developer machine, supply an approved environment,
TLS and workload identity boundary, secret custody, state backup/restore procedure, rollback
procedure, and a measured capacity target. None of these is inferred from a passing container
build. The existing Compose stack is a synthetic single-host demonstrator.
