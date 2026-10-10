# TRL readiness decision after the 24-hour advancement sprint

**Decision:** **TRL 4: validated laboratory prototype, with the TRL 5 advancement tests completed
and gates outstanding.**

This is the applicant's internal engineering assessment. The repository records no IAF approval,
SAG grading, independent assessment, certification or operational authorisation.

## Why not "Provisional TRL 5"

The declared matrix passed in full (`EXECUTION_REPORT.md`). TRL 5 nevertheless requires component
validation **in a relevant environment**. Four facts make a TRL 5 claim indefensible at this point.
Each one alone is sufficient.

1. **The environment is not a relevant environment in the TRL sense.**
   - The three hosts are network namespaces on one kernel. They share CPU, clock, memory and file
     system (`ENVIRONMENT.md`).
   - Virtual machines were not available to the run.
   - The IAF has not defined the relevant environment, its interfaces, scale or acceptance
     criteria (Q14).
   - The thresholds are the applicant's own.
2. **No independent witness.** Every test was designed, executed and evaluated by the applicant.
3. **A scaling defect bounds throughput (D-T5-01, `PERFORMANCE_REPORT.md`).**
   - The independent-custody recovery guard ships and re-verifies the whole evidence chain twice
     on every request, serialised across all requests.
   - The cost grows linearly with chain length, about 0.15 ms per record per authorisation
     in-process.
   - Sustained throughput was about 1.6 exchanges per second at 4 KiB, and it degrades as evidence
     accumulates.
   - A system that slows down with its own audit history is not ready for a representative-scale
     environment.
4. **Packet loss has been exercised only on namespaces.** The local kernel lacks netem. Loss
   profiles L1/L2 passed in the hosted CI job (run 37800666173, 35/35 on `1348b86`), but that job
   is also three namespaces on one kernel.

The guard test `tests/trl-matrix.test.mjs` continues to hold every element at TRL ≤ 4 while the
relevant environment is "NOT DEFINED". That guard was not changed.

## What the sprint did establish

These statements cover lab validation only:

- The platform runs as separately addressed hosts, with the authority's internals unreachable from
  unit hosts. Every exchange crossed a real TLS hop with hostname verification.
- Release, revocation, concurrency, duplicate, recovery and interoperability properties held on
  that topology under delay, jitter, bandwidth limits and a 20-second outage, with the
  pre-declared criteria unchanged.
- Two defects were found and fixed, each with a regression test that was shown to fail on the old
  code:
  - The relay-down path returned HTTP 500 instead of 503 RELAY_UNAVAILABLE (product defect).
  - The WAN emulator reordered TLS records (harness defect).
- One defect was found and **not** fixed: D-T5-01, scaling. A fix requires a custody protocol change
  with its own ADR and negative tests.

## Gates before a TRL 5 claim can be considered

| #   | Gate                                                                                                                                                     | Owner             | Status                                                                        |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------- |
| G1  | Sponsor defines or agrees the relevant environment, interfaces, scale and acceptance criteria (Q14)                                                      | IAF / sponsor     | Not started                                                                   |
| G2  | Fix D-T5-01: incremental custody checkpoints (verify only records since the anchored head), with an ADR, rollback/fork negative tests and a scaling test | Applicant         | Not started                                                                   |
| G3  | Re-run the matrix on separate machines or VMs (three hosts, distinct kernels and clocks), including loss profiles                                        | Applicant         | Not started                                                                   |
| G4  | Hosted CI `relevant-env` job green on the candidate revision, with L1/L2 executed                                                                        | Applicant         | Met for `1348b86` (CI run 37800666173); must be re-met on any later candidate |
| G5  | Independent witness or assessor observes the run and reviews the evidence manifest                                                                       | Independent party | Not engaged                                                                   |
| G6  | Per-device enrolment on each host, instead of conductor-provisioned profiles                                                                             | Applicant         | Not started                                                                   |

## Allowed wording

- Allowed: "TRL 4 laboratory prototype. A TRL 5 advancement test matrix (33 tests, declared before
  execution) passed on a three-host namespace environment. Scaling and environment gates are
  outstanding."
- Not allowed: "TRL 5", "provisional TRL 5", "validated in a relevant environment", "IAF-accepted",
  "SAG-graded", "certified".

## Addendum 2026-10-10: D-T5-01 fixed and re-tested (decision unchanged)

Branch `claude/siepmu-sovereign-research-w886dv`: incremental checkpoint custody (ADR-014, `d879b4a`). The
declared matrix was re-run on the same three-namespace environment at `1a0218d`: **33/33 PASS**; sustained load
T8.1 1.56 → 5.93 exchanges/s; custodian CPU 72.3 % → 17.1 % (`docs/trl5/evidence/1a0218d/`, guarded by
`tests/d-t5-01-retest.test.mjs`). Blocking reason 3 is resolved; reasons 1, 2 and 4 stand, so the decision
remains **TRL 4**. Detail: `docs/research/sovereign/09-TRL_READINESS_UPDATE.md`.
