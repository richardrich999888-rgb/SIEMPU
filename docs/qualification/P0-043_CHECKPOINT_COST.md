# P0 043 checkpoint signing cost

This increment follows draft PR #42 at `92353e1224e3eedb35db9d7420b6820a2574632a`.
It does not change the frozen PR #41 candidate or activate a migrated store.
Provisional internal TRL 4 is unchanged. All 19 qualification gaps remain open or partial.

SAG grading is not established.

TRL 5 qualification and IAF operational approval are not established.

## Observed cost and narrow correction

A diagnostic 20-object fenced comparison on the unchanged baseline called
`Authority.checkpoint()` 1,869 times, counting fixture setup, revocation controls and
verification as well as the measured exchange loop. The instrumented calls took
338.32 ms in aggregate. This is a diagnostic sample, not an isolated percentage of
exchange latency: its scope differs from the timed exchange loop.

Authorization seal creation, seal verification and custody lease eligibility previously
called `checkpoint()` only to use its sequence/head hash. That method made a new ECDSA
signature which these callers discarded. `readEvidenceHead()` now queries the same
last evidence row directly. It does not cache a row, digest, authorization decision,
checkpoint, key or lease. Each invocation observes the database through the caller's
current SQLite transaction/snapshot.

`Authority.checkpoint()` still signs the same payload, including the fresh issue time.
Outgoing full/incremental custody requests, checkpoints, writer envelopes, state seals
and leases remain signed and verified. Seal creation remains in the original transaction;
seal verification still compares the complete current authorization digest and evidence
head. Guard freshness, nonce, signature, epoch, writer-generation and state checks are
unchanged. No SQL migration, wire format, digest version, cryptographic algorithm,
policy check, timeout or rate threshold changes. No dependency is added.

The unsigned helper is a local observation, never evidence of trustworthy history.
It must not be used as an exported checkpoint or independent trust input. Backup and
migration verification still validate complete signed history and retained evidence
before the seal check; their read-only database facades supply the same fresh row lookup.

## Regression evidence and failed attempts

Run the four new regressions with:

```sh
node --test tests/evidence-head.test.mjs
```

They check retained signatures without throwaway checkpoint generation, transaction
rollback, an independent SQLite connection modifying the head, and full/incremental
custody rejection after a previously valid lease. The tests also join the existing
ADV-04 custody family and security/engineering commands. Existing partial-policy
rollback, unanchored-tail, writer-fence, recovery and migration cases remain required.

The first focused run recorded 132/145 passes and 13 failures: the legacy adversarial
test's deliberately small authority facade lacked the new `get` operation. The fixture
now delegates `get` to the same SQLite connection. All original attacker mutations and
denial assertions remain; no fallback or bypass was added to runtime code. Retain this
failed log with the correction and final clean-source reports.

The first frozen candidate `3af776349d6604eb78740122e09f3099918ba997` passed
619/620 native tests and the other nine validation gates. The remaining failure was
line-scoped qualification wording in two documentation passages. The correction makes
the disclaimers explicit on their own lines; the claims audit and all negative tests
remain unchanged. These predecessor logs are retained separately from final results.

## Reproducible matched measurement

`assurance/bench/checkpoint-cost.mjs` uses the existing 20 × 4 KiB fenced policy-release
comparison, including fresh revocation denial, old-key negative control and tamper
verification. It records exact target commit/tree/source fingerprint, its own harness
SHA-256, runtime, raw samples, CPU, RSS and checkpoint calls. It refuses a dirty source
or source changes during execution, and refuses to overwrite an existing output.

Use the **same candidate harness file** from each clean checkout's working directory:

```sh
cd /path/to/clean-baseline
node /path/to/clean-candidate/assurance/bench/checkpoint-cost.mjs /path/to/new-baseline-1.json
cd /path/to/clean-candidate
node /path/to/clean-candidate/assurance/bench/checkpoint-cost.mjs /path/to/new-candidate-1.json
```

Repeat in fresh processes, alternating baseline/candidate order. Do not run other
test or benchmark workloads concurrently. Compare medians across runs and retain
each run's per-operation samples. There is no hardware-independent acceptance threshold
or test that demands a speedup. Report a neutral or negative outcome if observed.

This single-process workload is not sustained-load qualification, maximum throughput,
independent administration, physical crash testing or comparison with a named messaging
product. Repeat hosted T8.1 separately without substituting its result for this comparison.
The full-state digest still scans authorization rows; evidence/state growth, retention,
full-system recovery and representative-scale capacity remain open. An optimization here
does not close IAF-G10 or establish a new TRL. Final results belong to the exact executed
revision's generated report and PR evidence, not this pre-freeze procedure.

Packaging review found the first benchmark location under `scripts/` entered the application
bundle. It was moved into the existing assurance-only tree before final delivery.
Application and offline release allowlists omit that tree; retain the observed initial
manifest entry and the corrected package checks. No production activation occurred.
