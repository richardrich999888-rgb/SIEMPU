# ADR-019: Preserve independent custody during synthetic multi-store recovery

Status: laboratory prototype; production recovery remains unqualified.

PR #42 verifies legacy migration candidates but does not establish live recovery or
writer authority. Restoring custody from the same service backup would erase the
independent rollback boundary.

Require independently pinned sealed archive, exact checkpoint/fenced lease, separately
signed/pinned monitoring snapshot, strict schema/history/state/policy reconciliation
and expiring separate-reviewer approval of the complete plan. Stage into a new private
directory. Use existing explicit atomic writer transfer, retain its receipt and obtain
a fresh custody lease before serving. Never restore/bootstrap custody or reseal history.

An uncertain handover is reconciled only from existing signed custody history. Resume
requires original evidence/plan pin and unchanged logical rows including BLOB bytes.
After protected work advances, a new consistent set and review are required. Exclude
source tools from deployed packages. No runtime crypto or SQL migration changes.

This supports laboratory recovery and crash testing, not independent administration,
full-site DR, endpoint/connector recovery, quorum HA or physical power-loss qualification.
Monitoring uses bounded full replay, not durable exporter-cursor recovery.
See [procedure](../qualification/GUARDED_DISASTER_RECOVERY.md).
Provisional TRL 4 remains unchanged; TRL 5 qualification is not established.
SAG grading and IAF operational approval are not established.
