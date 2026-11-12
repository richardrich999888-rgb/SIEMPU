# P0-047 continuation: interrupted online delivery

Provisional TRL 4 remains unchanged. Independent-host, independent-custody, physical-token
and external-evaluator qualification remain blocked. These changes remain in draft PR #47
against the reconciled P0-046 integration branch; no laboratory request has been sent.

## Retained negative result: OPEN-NET-047-01

Source `691bee47e20fc677669e212c7dc11dbca297a231`, tree
`f76bac3e95a74766cf19d188f4732dc5606261d0`, had one failed T3.L2 exchange in
[PR CI attempt 1](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/43091430162/attempts/1).
The profile was 64 KiB, 100 ms ± 20 ms, 3% random packet loss; 4/5 objects arrived intact.
The send error was `Transport deadline exceeded`; its protocol substage was not recorded.
The contemporaneous push run passed 35/35 on the same source tree.

The single predeclared unchanged repeat, job `130779216655`, logged 35/35 including 5/5
T3.L2 on 11 November. Its source gate passed; evidence upload failed after five provider
attempts with an HTML/JSON response error. The repeat has job-log evidence only, not a
retrieved raw result bundle. The original failure artifact `13890165415` remains retained
with SHA-256 `78dd8ff70179041d18aaada3ee5c95e2c466b9a059579994f8c0b41cb64f6fe3`.
The successful repeat does not close the original intermittent failure.

SDK errors now carry fixed request-stage labels. The relevant-environment agent records
the operation stage and elapsed time on send/receive failure. It does not add retries,
change the 10-second transport deadline, alter loss profiles, or relax five-of-five
acceptance. Artifact names include run and attempt so repetitions retain distinct results.
The observed upload error is not attributed to a name collision without evidence.

## Corrected continuity gap: NET-047-02

At the frozen source, managed `send()` directly called `submit(await seal(...))`, even when
an encrypted outbox was configured. If the authority committed and the reply was lost,
that call retained no local sealed object. Repeating `send()` would generate a new object.
This is a separate finding; it is not asserted to be the cause of OPEN-NET-047-01.

With a configured outbox, online send now encrypts, durably enqueues, then submits that
exact object. A response loss leaves PENDING state for explicit recovery with `flushQueue()`.
Each attempt obtains a fresh device proof and uses the normal authority. Only the SDK's
verified signed receipt permits SUBMITTED state. Capacity refusal precedes publication;
expired items become HELD. No automatic retry, cached key release, plaintext persistence,
session bypass, queue eviction or automatic HA is introduced.

`tests/managed-delivery.test.mjs` uses real TLS authority, relay and custodian processes.
A loopback-only TLS fault injector discards an actual successful submission response or
disconnects before forwarding; it never supplies a mock authority acceptance. Five cases
cover restart and identical signed receipts with one SUBMITTED event, sender revocation,
three explicit failed attempts and capacity refusal, altered receipts, and expired/held
entries. The regression uses the shared managed delivery implementation with software
keys. It does not establish the combined physical-token/scanner path or independent hosts.

The preserved negative reproduction substitutes the exact old online-send expression
into this fixture. It fails because no pending entry exists after real authority commit.
This is a call-sequence reproduction, not an execution of the complete native companion.
Its harness, failure log and changed-source hashes are retained separately from frozen
qualification evidence. Full-suite reports identify the exact final candidate.

## Inventory binding correction

The first continuation candidate `9b2ce0c` (local tree-equivalent `560d5a3`) failed
the full native suite: 716/717 passed and `CRYPTO_REVIEW_DRIFT` rejected two stale
inventory bindings, for `packages/integration/client.mjs` and the managed companion
entry point. This failed candidate and its reports are retained. Its network results
do not establish a passing full qualification baseline.

Applicant code review confirms that the SDK change adds fixed diagnostic labels around
the existing request; transport configuration, request bodies, proof generation and
signature validation are unchanged. The companion change calls the reviewed durable
delivery helper after inspection/sealing. That helper persists before publication,
reopens encrypted state for each explicit attempt, invokes the normal SDK submission,
and records success only after receipt verification. It introduces no cryptographic
algorithm or key-custody change. The queue component inventory now includes the helper
and its five-case regression; only the two changed bindings and two new file bindings
are updated. The drift assertion and all acceptance thresholds remain enforced. This
is applicant review pending draft-PR review, not independent cryptographic approval.

## Predeclared next measurements

For this candidate, run the existing push and pull-request network matrices once each
on their assigned hosted runners; retain both outcomes, with no retries until green.
Keep five 64-KiB exchanges per impairment profile and the original thresholds. Run the
existing CORE and Mininet campaigns (three repetitions of five objects per four profiles,
plus outage recovery) on the same candidate. These are applicant CI/emulation trials with
one kernel per topology, not independent-host or external laboratory validation.

Run native coverage, E2E and adversarial suites. The latter includes the new five-case
delivery regression. Regenerate source-bound local campaign and evaluator evidence after
freezing the revision. A failure remains a failure and is carried forward with its source.
Five samples per loss condition do not estimate rare-failure probability or a production SLA.
No endurance, physical hardware, independent administration or automatic recovery claim
follows. IAF-G05 and IAF-G10 remain PARTIAL_LAB; all nineteen gap statuses are unchanged.
