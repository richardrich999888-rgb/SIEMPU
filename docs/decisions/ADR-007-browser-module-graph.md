# ADR-007: the browser crypto module imports only `canonical.mjs`

Status: accepted, 2026-10-08. Commit `2fc827e`.

## Context

A deployed service worker intercepts only the paths in its own `ASSETS` list. When a newer
`crypto.mjs` statically imports a module that the older worker never cached, the browser loads it
from the network once, cannot cache it, and offline start-up fails after an interrupted upgrade.
PR #15 added three such imports (`providers/webcrypto.mjs`, `object-format/schema.mjs`,
`mission/policy.mjs`). The Chromium regression `tests/browser/shell-upgrade.mjs` reproduces the
failure on the merged branch and passes on PR #16, which kept the graph minimal.

## Decision

`packages/crypto/crypto.mjs` holds the wire contract (schema fields, mission labels) and the default
WebCrypto provider, and statically imports only `../protocol/canonical.mjs`. The former modules
re-export from it, so server import paths and the PR #15 provider interface are unchanged.
The service worker uses PR #16's immutable cache-first generations (no `skipWaiting`, atomic
`addAll`); its cache name is bumped whenever any shell asset changes.

## Consequences

- One source of truth for the contract; no duplicated field lists.
- Adding any browser import to `crypto.mjs` is a breaking change that requires a new shell
  generation and must keep `shell-upgrade.mjs` passing.
