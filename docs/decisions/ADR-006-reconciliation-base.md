# ADR-006: engineering branch is the base; Q-agile work is ported selectively

Status: accepted, 2026-10-08. Commit `2fc827e`.

## Context

Two agent branches diverged from `main` `ad80210`: the TRL 5/6 engineering candidate
(PR #15, `32b4a1c`, hosted CI green) and the Q-agile branch (PR #16, `a4abc80`, hosted CI red).
PR #16 was built from an earlier snapshot of the PR #15 work: 61 of 84 shared files are
byte-identical. Of the 23 that differ, PR #16 removes or weakens PR #15 controls in the authority
core, control/relay/web servers (TLS replaced by an injectable plain-HTTP factory, custody
recovery guard and FLASH approval removed, explicit route dispatch collapsed). Five PR #16 files
were published with invalid UTF-8 and cannot be recovered from their own bytes.

## Decision

Fast-forward to PR #15 and port PR #16 content file-by-file. A history merge is not used.
PR #16-only subsystems that duplicate PR #15 (mTLS stack, integration adapter) are not ported.
Every port records the source SHA in the commit message. The full matrix is
[docs/engineering/RECONCILIATION_MATRIX.md](../engineering/RECONCILIATION_MATRIX.md).

## Consequences

- Trust boundary: unchanged from PR #15; PR #16 additions are confined to endpoint lab code,
  the authority crypto-policy registry and the evidence schema.
- Migration: PR #16 `004-crypto-policy.sql` collided with PR #15 `004-release-approvals.sql`;
  it is applied as `005-crypto-policy.sql`. Databases created from PR #16 are not upgrade-compatible
  (laboratory branch; no deployed data).
- Evidence: `npm run validate` PASS on `2fc827e` locally (208/208 tests). Hosted CI is the
  acceptance gate.
