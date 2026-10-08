---
name: siepmu-github-handover
description: Managing SIEPMU branches and pull requests - comparing divergent agent branches, reconciling PRs file by file, reproducing and diagnosing hosted CI failures, handling review findings, and handing over between engineering sessions. Use when starting a session, inspecting PRs or CI, porting work between branches, or before ending a session.
---

# SIEPMU GitHub workflow and handover

## Session start

1. Read `CLAUDE.md` and `docs/engineering/CURRENT_STATE.md`.
2. `git fetch origin 'refs/heads/*:refs/remotes/origin/*'` and
   `git fetch origin 'refs/pull/*/head:refs/remotes/pr/*'` (PR heads as `pr/<n>`).
3. Compare HEAD with the SHAs in CURRENT_STATE. If they differ, re-verify before relying on recorded results.

## Comparing two branches

```sh
git merge-base pr/15 pr/16                        # common ancestor
git rev-list --count A..B                          # commits unique to B
comm -12 <(git diff --name-only BASE A | sort) <(git diff --name-only BASE B | sort)   # shared paths
git rev-parse A:path B:path                        # identical blobs?  (same hash = identical)
git diff A B -- path                               # actual divergence
```

Classify each shared path: identical, divergent, unique. For divergent files decide per file and
record the reason (template: `docs/engineering/RECONCILIATION_MATRIX.md`). Watch for parallel
re-implementations of one subsystem and colliding migration numbers.

## Porting rules

- Never force-push, rewrite or merge into another agent's branch; never push to `main`; never merge PRs.
- Prefer selective file import (`git checkout <sha> -- <paths>`) plus manual edits, with the source
  SHA in the commit message. History merges of other agents' branches may be blocked by policy.
- Check imported text for corruption: `node scripts/check.mjs` (text-integrity gate).
- Run the full gate before pushing (`npm run validate`, `npm run test:e2e`).

## Diagnosing hosted CI

1. List runs: GitHub MCP `actions_list` `list_workflow_runs` filtered by branch.
2. Failed logs: `get_job_logs` with `run_id`, `failed_only: true`, `return_content: true`.
   Gate summaries print `--- <gate> failure excerpt ---` with the failing tests.
3. Artefacts may be unreachable from the build container (egress policy); rely on job logs.
4. Reproduce locally with Node 24.21.0 (`https://nodejs.org/dist/v24.21.0/`, verify `SHASUMS256.txt`).
5. Distinguish: real defect, environment/timing dependence (find the test), or base-branch failure.
   Never skip or weaken tests; never push empty commits to retrigger.

Known lesson (2026-10-08): PR #16 failed because five files were published with corrupted bytes
via a connector; the gates reported it only indirectly. Always run `npm run check` before publishing.

## Review findings

Verify each finding against code; fix with a regression test or reply with the traced reason.
Security findings stay open until the owner decides.

## Session end / before compaction

Update `docs/engineering/CURRENT_STATE.md`: date, branch, HEAD SHA, last passing validation SHA
and run URLs, failing or unexplained results, open PRs, next executable task. Commit and push.
After compaction, re-read CURRENT_STATE and the relevant skill before continuing.

## Definition of done for a handover

A new session can continue from CURRENT_STATE alone without reconstructing history.
