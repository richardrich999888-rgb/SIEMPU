# P0-047 real-network evaluation candidate

SYNTRIASS Labs Pvt. Ltd. — AIRON–SIEPMU, iDEX DISC-14 PS-69.
Prepared 12 November 2026 IST. Provisional internal TRL 4 remains unchanged.
SAG grading, TRL 5 qualification and IAF operational approval are not established.

This increment reconciles the separate recovery branches and adds executable node
manifests, a real-service application campaign, CORE/Mininet adapters and external
evaluation procedures. **Overall mission remains BLOCKED** until authorised independent
hosts and evaluators execute the outstanding campaigns. A successful local report is
not an independent-host result. See generated source-bound results for observed counts;
this document does not predict a pass.

## Source reconciliation

The observed open PR inventory is `branch-reconciliation.json`, including every open
PR head/base and tree. PRs #38–#42 are ancestors of #43/#45 and #44. PR #44 advanced to
`64df68c13cb1fa7a3f27af2275a9dab9aca857c3`; #45 is
`6ac57e5e6e561c73525de08b09950263d2fe7dee`. The initial audit found no published
P0-046 candidate. PR #46 subsequently appeared at
`9d9d21acdfe2e6a30b7a5bbfc73bfb1fe95ac6be` and was reviewed and merged with both
parents retained. The stacked review base is now #46's
`codex/p0-046-unified-defence-assurance`. The late conflict/resolution record is in
`branch-reconciliation.json`; P0-047 keeps the newer #44 reliability fixes, all ten
unified recovery tests and the quarantine/verification separation. Older divergent
PRs are inventoried, not silently merged.
The existing PRs remain drafts and this author's inspection is not external approval.

The first reconciled source is `f26cbe949ee056c0ceb74031bfe88ac72812ab21`.
Four textual conflicts were reconciled by preserving both branches' source inventory,
test lists and history. An unchanged 83-test focused run reported 80 passes and three
failures (two failing leaf assertions plus their enclosing subtest). Both invalid
snapshots were refused, but earlier backup errors did not match the recovery contract.
The correction translates only the two exact errors and rethrows; it never retries
restore. The unchanged eight-test negative family and ten inventory tests then passed.
The original source and failure log are retained in the evaluation package.

## Deliverable map

| Item                   | Location                                                                            | Evidence limit                                                     |
| ---------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| D1 architecture        | `ARCHITECTURE.md`                                                                   | Proposed host/custody boundaries, not observed deployment          |
| D2 CORE/Mininet        | `deployment/real-network/emulate.py`                                                | Executed on hosted privileged runners; shared kernel, not independent hosts  |
| D3 campaign            | `campaign.mjs`, `run-local.mjs`, `run-remote.mjs`, `CAMPAIGNS.md`                   | All NET IDs explicitly represented; unsupported steps stay blocked |
| D4 adversarial         | retained baseline failure; existing nine-family campaign; `CAMPAIGNS.md`            | Applicant lab tests, not third-party assessment                    |
| D5 performance         | generated `campaign.json`                                                           | Three short repetitions; no endurance/RTO guarantee                |
| D6 evaluation          | existing `assurance/sag/package.mjs` and `verify.mjs`, plus campaign logs/manifests | Independent retention and reproduction still required              |
| D7 readiness           | `READINESS.md`, existing 19-gap register                                            | No gap closed by emulation or CI                                   |
| D8 laboratory requests | `LAB_ACCESS.md`, `TESTBED_SELECTION.md`                                             | Prepared only, no submission or terms acceptance                   |
| D9 draft PR            | published PR metadata                                                               | Source SHA and hosted results must be read at exact head           |

## Run a local application experiment

From a clean committed checkout with Node 24.19–24.x and OpenSSL:

```sh
npm ci --ignore-scripts --no-audit --no-fund
python3 deployment/real-network/preflight.py
node deployment/real-network/run-local.mjs artifacts/p0-047/local .data/p0-047-local
```

Use new output and state directories for every repetition of the full experiment.
The actual web, control, relay, checkpoint and monitoring servers run as separate
processes with separate role directories. The real software endpoint SDK uses the
existing cryptography and durable encrypted managed outbox. The full native companion
is a separate required profile: `managed-driver.mjs` calls `openManagedEndpoint` with
real enrolled token keys and ClamAV/Bubblewrap configuration. It fails if prerequisites
are missing and has no mock/fallback. Its configuration/enrolment procedure remains
`integrations/managed-endpoint/README.md`; native-inputs.json carries the public peer
and sender signing key. Credentials, token PIN and outbox secret remain private.

The software campaign is not a managed-companion or physical-token acceptance result.
Endpoint requests use verified TLS 1.3 plus MFA and signed device proof. Internal
service connections use pinned mTLS. The existing web ingress does not require client
certificates: do not describe the whole path as endpoint mTLS.

## Deploy to authorised distinct hosts

1. Freeze a clean source SHA. Generate synthetic node state with
   `node deployment/real-network/provision.mjs .data/p047-remote multi-host`.
2. Supply six authorised Linux hosts/VMs, SSH account keys, already verified known_hosts,
   approved experiment addresses and local clock synchronisation. Start with 2 vCPU,
   4 GiB RAM and 10 GiB disk per host. These are requested resources, not measured minima.
3. Copy the exact source to each host and **only its lettered private node directory**.
   Preserve permissions. Do not distribute another node's keys or aggregate directories.
   Source needs no runtime npm dependency; development suites require the locked install.
4. Have the host operator configure experiment-only DNS or `/etc/hosts`: web/control at B,
   relay at C, checkpoint/collector at D. Certificates bind these stable service names.
   The supplied `hosts.example` uses 10.77.0.0/24; replace with the allocated addresses.
   Keep the management network outside fault injection. Apply the firewall table in D1.
5. Run `node deployment/real-network/host.mjs /absolute/private/D`, then C, then B,
   using a dedicated unprivileged user. The supervisor checks exact committed source,
   forwards termination to its children and enforces a two-hour session bound.
6. Populate a private copy of `inventory.example.json` with actual permitted hosts and
   frozen SHA. Confirm the authorisation flag only after documented allocation and
   permitted experiment scope. Run `node deployment/real-network/run-remote.mjs INVENTORY OUTPUT`.
   This performs SSH preflight and the implemented endpoint campaign only; it does not
   allocate machines, accept policies, execute remote fault hooks or activate standby.
7. Ctrl-C supervisors to tear down services. Revoke disposable certs/credentials, export
   reviewed non-secret evidence, then have each operator delete its experiment state.
   Do not delete recovery/custody material before retaining evidence and confirming no
   further recovery experiment needs it. No global process or namespace cleanup is used.

Distinct hostnames and boot hashes are screening evidence, not proof against a malicious
hypervisor or cloning. Retain provider allocation IDs, host/VM UUIDs, independent storage
records, signed administrator attestations and topology evidence separately. For strongest
custody, D must generate/retain its own keys and be administered by an independent evaluator;
the common-provisioner fixtures explicitly do not establish that property.

## Emulate links without claiming independent hosts

On a dedicated authorised Linux machine with root/CAP_NET_ADMIN and the chosen installed
backend, provision a fresh multi-host fixture. Then:

```sh
sudo python3 deployment/real-network/emulate.py --backend mininet --state .data/p047-mn --output artifacts/p0-047/mininet --execute
sudo python3 deployment/real-network/emulate.py --backend core --state .data/p047-core --output artifacts/p0-047/core --execute
```

Create each input with the provisioner first. No emulator installs software automatically.
Both adapters start the actual service commands, use private hosts mappings, drop workload
privileges to the fixture owner, set netem only on the created sender interface, retain
observed qdisc counters, and tear down their own session. Do not run against an existing
shared tenant interface. Profiles cover delay/jitter, loss/duplication, reordering and a
complete sender outage, then queue reconnection. Both backends executed on a privileged hosted runner at predecessor
`3770f1b35fe01c0001cda9759a3f934e2fbef1e0`: 60 exchanges per backend, observed
netem counters, complete sender outage and encrypted-queue reconnection. Those
results remain bound to that source. Read the exact final-head workflow and retained
artifact before applying them to a later revision. CORE uses official release 9.2.1,
with its Debian package SHA-256 pinned in the workflow; Mininet uses the recorded
distribution package. Both use namespaces on one host per job.

## Evidence collection and independent verification

Never publish `.data`, node bundles, sessions, PINs, CA/private keys, control backups,
outbox secrets or raw SQLite stores. Signed release/ACK records are synthetic and public
evidence; their signatures do not attest that the runner honestly measured time.
Campaign files have SHA-256 manifests; retain the manifest digest through an independent
channel. Keep timings, errors and blocked rows even if a later attempt passes.

After final `npm run validate`, use `npm run sag:package -- artifacts/p047-evaluation`.
This is an applicant evaluation package format, not a grading result. Use its existing
verifier with an independently retained digest. An external evaluator must fetch the
published source independently, check SHA/tree/lockfiles, verify signatures with separately
pinned public keys/checkpoints, reproduce tests and sign their own observations.

Packet capture is BLOCKED here (no CAP_NET_RAW/tool allocation). On an approved isolated
experiment link, an operator may use a bounded header-only capture (snaplen 96, explicit
experiment peers, packet count 10000). Never capture management/login traffic or enable
TLS key logging. Inspect even synthetic IP/device metadata before sharing. Header-only
capture alone cannot prove payload confidentiality or observe application decisions.

## Retained harness findings

The first application attempt at `0c40ec0` failed before the NET rows because the runner
requested a sender grant for the deliberately restricted Eve identity. `fc8cb2d` keeps
normal authentication separate from grant acquisition; no policy permission changed.
The second attempt failed NET-05 because the harness expected identical resubmission to
return 409. Source inspection established the existing idempotency contract:
`Authority.submit` returns the original receipt for an identical envelope/signature.
`208f4a3` asserts that exact signed receipt and a single visible object. It also performs
the post-revocation request directly against the claim endpoint using a proof prepared
before revocation; denial at an earlier readiness endpoint no longer satisfies this row.
The original logs/reports and their source revisions are retained. These were harness
errors, not observed plaintext disclosure or unsafe snapshot acceptance.

The additional `P0-047 isolated emulation` workflow runs only on a standard public-repository
runner. It installs the distribution Mininet backend and records its package versions,
then executes the actual application processes. Read the hosted result before claiming
execution; a defined workflow is not evidence. CI and namespace results remain separate
from independent-host, independent-administrator and external-laboratory evidence.

The first hosted runs at `d7b45c2` and diagnostic revision `58e31f2` failed readiness.
The retained diagnostic artifact identifies `PRIVATE_DATABASE_DIRECTORY` while opening
the control telemetry store. The private database guard was preserved. Deployment now
canonicalises host/endpoint state paths and explicitly restores 0700 on copied private
directories. A symlinked-workspace reproduction checks the actual outbox path; the hosted
report records whether the requested workspace path was canonical. This finding does
not close the separate historical IAF-G18 adapter-startup gap.
