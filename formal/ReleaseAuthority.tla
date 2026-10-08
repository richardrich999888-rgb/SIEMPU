---------------------------- MODULE ReleaseAuthority ----------------------------
(***************************************************************************)
(* Model of the SIEPMU control-authority release state machine.           *)
(*                                                                         *)
(* Source of the modelled behaviour (services/control/core.mjs):          *)
(*   Authority.claim   -> Claim       (one BEGIN IMMEDIATE transaction)    *)
(*   Authority.change  -> ChangeAuth  (mutation + epoch bump + evidence)   *)
(*   authorizeRelease  -> ApproveFlash                                     *)
(*   Authority.dispatch with a recovery guard -> Anchor (custodian         *)
(*     checkpoint before and after every request; a response is sent only *)
(*     after the post-request checkpoint is accepted)                     *)
(*   services/evidence/custody.mjs CheckpointCustodian.accept -> Anchor    *)
(*     (refuses a head that is not an extension of the saved checkpoint)   *)
(*                                                                         *)
(* Abstractions (stated so a reviewer can judge them):                     *)
(*  - All of authorityReason (users, devices, roles, duty, unit, mission, *)
(*    policy edge, crypto policy) is one boolean auth[r] per recipient.   *)
(*    Every change to it bumps the epoch, as Authority.change does.        *)
(*  - The sender is always authorised; grant expiry is not modelled.      *)
(*  - SQLite serialisability is assumed: each action is one transaction. *)
(*  - Evidence hashing/signatures are abstracted to exact sequence        *)
(*    equality (the custodian compares sequence and head hash).           *)
(*  - Time, lease expiry and network loss are folded into Crash.          *)
(*                                                                         *)
(* Two switches produce deliberately broken designs that TLC must reject: *)
(*   Atomic = FALSE  : the policy check and the issuance commit are       *)
(*                     separate steps (time-of-check/time-of-use).        *)
(*   Guarded = FALSE : no independent checkpoint custody; responses are   *)
(*                     sent at commit and restore is unchecked.           *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Recipients,  \* recipient identities
          Objects,     \* queued encrypted objects
          Rcpt,        \* [Objects -> Recipients]: fixed recipient of each object
          Flash,       \* subset of Objects with FLASH priority (dual control)
          MaxEpoch,    \* bound on authority epoch (state-space bound only)
          MaxEvidence, \* bound on evidence length (state-space bound only)
          MaxBackups,  \* bound on retained database snapshots
          Atomic,      \* TRUE = faithful model; FALSE = check/issue race mutant
          Guarded      \* TRUE = faithful model; FALSE = no custodian mutant

ASSUME Rcpt \in [Objects -> Recipients] /\ Flash \subseteq Objects
ASSUME MaxEpoch \in Nat /\ MaxEvidence \in Nat /\ MaxBackups \in Nat
ASSUME Atomic \in BOOLEAN /\ Guarded \in BOOLEAN

None == "none"
States == {"absent", "queued", "held", "released"}

\* Uniform evidence record; unused fields carry None / FALSE / 0.
Ev(kind, o, r, v, e) == [kind |-> kind, o |-> o, r |-> r, v |-> v, e |-> e]

VARIABLES
  db,          \* authority database: the only state restored from backup
  backups,     \* set of retained database snapshots
  anchor,      \* custodian's saved evidence prefix (independent store)
  outbox,      \* committed responses not yet sent (wait for post-request anchor)
  pending,     \* Atomic = FALSE only: objects that passed the check, not yet issued
  clientEpoch, \* epoch each recipient client last observed (may be stale)
  delivered,   \* ghost: objects whose key-bearing response reached the recipient
  acked,       \* ghost: acknowledged auth changes as [r, v, idx] (idx into evidence)
  step         \* ghost: name of the last action (lets properties exclude restore)

vars == <<db, backups, anchor, outbox, pending, clientEpoch, delivered, acked, step>>

DB == [epoch : 1..MaxEpoch,
       auth : [Recipients -> BOOLEAN],
       obj : [Objects -> States],
       issued : SUBSET Objects,
       approval : [Objects -> 0..MaxEpoch],
       evidence : Seq([kind : STRING, o : Objects \cup {None}, r : Recipients \cup {None},
                       v : BOOLEAN, e : 0..MaxEpoch])]

IsPrefix(p, s) == Len(p) <= Len(s) /\ SubSeq(s, 1, Len(p)) = p

Init ==
  /\ db = [epoch |-> 1,
           auth |-> [r \in Recipients |-> TRUE],
           obj |-> [o \in Objects |-> "absent"],
           issued |-> {},
           approval |-> [o \in Objects |-> 0],
           evidence |-> <<>>]
  /\ backups = {}
  /\ anchor = <<>>
  /\ outbox = {}
  /\ pending = {}
  /\ clientEpoch = [r \in Recipients |-> 1]
  /\ delivered = {}
  /\ acked = {}
  /\ step = "init"

Append1(rec) == db.evidence \o <<rec>>

\* A response becomes visible immediately without custody, or after anchoring with it.
Respond(msg) ==
  IF Guarded
    THEN /\ outbox' = outbox \cup {msg}
         /\ UNCHANGED <<delivered, acked>>
    ELSE /\ outbox' = outbox
         /\ delivered' = IF msg.kind = "key" THEN delivered \cup {msg.o} ELSE delivered
         /\ acked' = IF msg.kind = "auth" THEN acked \cup {[r |-> msg.r, v |-> msg.v, idx |-> msg.idx]}
                     ELSE acked

\* Guarded mode: a request is processed only right after the custodian accepted the
\* current head (Authority.dispatch calls recoveryGuard.authorize before routing).
GuardOK == ~Guarded \/ anchor = db.evidence

Submit(o) ==
  /\ GuardOK
  /\ db.obj[o] = "absent"
  /\ db' = [db EXCEPT !.obj[o] = "queued",
                      !.evidence = Append1(Ev("SUBMITTED", o, None, FALSE, db.epoch))]
  /\ step' = "submit"
  /\ UNCHANGED <<backups, anchor, outbox, pending, clientEpoch, delivered, acked>>

\* Authority.change: any authorisation change bumps the epoch in the same transaction.
ChangeAuth(r, v) ==
  /\ GuardOK
  /\ db.auth[r] # v
  /\ db.epoch < MaxEpoch
  /\ LET idx == Len(db.evidence) + 1 IN
     /\ db' = [db EXCEPT !.auth[r] = v, !.epoch = db.epoch + 1,
                         !.evidence = Append1(Ev("AUTH", None, r, v, db.epoch + 1))]
     /\ Respond([kind |-> "auth", o |-> None, r |-> r, v |-> v, idx |-> idx])
  /\ step' = "change"
  /\ UNCHANGED <<backups, anchor, pending, clientEpoch>>

\* A recipient client reads the current epoch (GET /api/control); it may act on it later.
Observe(r) ==
  /\ clientEpoch[r] # db.epoch
  /\ clientEpoch' = [clientEpoch EXCEPT ![r] = db.epoch]
  /\ step' = "observe"
  /\ UNCHANGED <<db, backups, anchor, outbox, pending, delivered, acked>>

\* authorizeRelease: a separate commander approves a FLASH object for the current epoch.
ApproveFlash(o) ==
  /\ GuardOK
  /\ o \in Flash
  /\ db.obj[o] \in {"queued", "held"}
  /\ db.auth[Rcpt[o]]
  /\ db.approval[o] # db.epoch
  /\ db' = [db EXCEPT !.approval[o] = db.epoch,
                      !.evidence = Append1(Ev("FLASH_APPROVED", o, None, TRUE, db.epoch))]
  /\ step' = "approve"
  /\ UNCHANGED <<backups, anchor, outbox, pending, clientEpoch, delivered, acked>>

\* authorityReason ?? approvalReason ?? EPOCH_MISMATCH, evaluated on the given state.
Releasable(d, o, expected) ==
  /\ d.auth[Rcpt[o]]
  /\ (o \in Flash => d.approval[o] = d.epoch)
  /\ expected = d.epoch

Deny(o) ==
  db' = [db EXCEPT !.obj[o] = "held",
                   !.evidence = Append1(Ev("RELEASE_DENIED", o, Rcpt[o], FALSE, db.epoch))]

Issue(o) ==
  IF o \in db.issued
    THEN db' = [db EXCEPT !.obj[o] = "released",
                          !.evidence = Append1(Ev("RELEASE_RETRY", o, Rcpt[o], TRUE, db.epoch))]
    ELSE db' = [db EXCEPT !.obj[o] = "released", !.issued = db.issued \cup {o},
                          !.evidence = Append1(Ev("RELEASE_ISSUED", o, Rcpt[o], TRUE, db.epoch))]

KeyMsg(o) == [kind |-> "key", o |-> o, r |-> Rcpt[o], v |-> TRUE, idx |-> Len(db.evidence) + 1]

\* Authority.claim: one transaction re-validates current authority, then issues or holds.
Claim(o) ==
  /\ Atomic
  /\ GuardOK
  /\ db.obj[o] \in {"queued", "held", "released"}
  /\ IF Releasable(db, o, clientEpoch[Rcpt[o]])
       THEN Issue(o) /\ Respond(KeyMsg(o))
       ELSE Deny(o) /\ UNCHANGED <<outbox, delivered, acked>>
  /\ step' = "claim"
  /\ UNCHANGED <<backups, anchor, pending, clientEpoch>>

\* Mutant (Atomic = FALSE): the check commits first, the issuance later, with no re-check.
ClaimCheck(o) ==
  /\ ~Atomic
  /\ GuardOK
  /\ db.obj[o] \in {"queued", "held"}
  /\ o \notin pending
  /\ Releasable(db, o, clientEpoch[Rcpt[o]])
  /\ pending' = pending \cup {o}
  /\ step' = "check"
  /\ UNCHANGED <<db, backups, anchor, outbox, clientEpoch, delivered, acked>>

ClaimCommit(o) ==
  /\ ~Atomic
  /\ o \in pending
  /\ Issue(o) /\ Respond(KeyMsg(o))
  /\ pending' = pending \ {o}
  /\ step' = "claim"
  /\ UNCHANGED <<backups, anchor, clientEpoch>>

\* CheckpointCustodian.accept + post-request authorize: the custodian saves the head only
\* if it extends the saved prefix; then held responses up to that head are sent.
Anchor ==
  /\ Guarded
  /\ IsPrefix(anchor, db.evidence)
  /\ anchor # db.evidence \/ outbox # {}
  /\ anchor' = db.evidence
  /\ LET sent == {m \in outbox : m.idx <= Len(db.evidence)} IN
     /\ outbox' = outbox \ sent
     /\ delivered' = delivered \cup {m.o : m \in {x \in sent : x.kind = "key"}}
     /\ acked' = acked \cup {[r |-> m.r, v |-> m.v, idx |-> m.idx] : m \in {x \in sent : x.kind = "auth"}}
  /\ step' = "anchor"
  /\ UNCHANGED <<db, backups, pending, clientEpoch>>

Backup ==
  /\ Cardinality(backups) < MaxBackups
  /\ db \notin backups
  /\ backups' = backups \cup {db}
  /\ step' = "backup"
  /\ UNCHANGED <<db, anchor, outbox, pending, clientEpoch, delivered, acked>>

\* Process crash: unsent responses and in-flight work are lost; the database survives.
Crash ==
  /\ outbox # {} \/ pending # {}
  /\ outbox' = {} /\ pending' = {}
  /\ step' = "crash"
  /\ UNCHANGED <<db, backups, anchor, clientEpoch, delivered, acked>>

\* Operator restores a retained snapshot; the process restarts (quarantined if Guarded).
RestoreBackup(b) ==
  /\ b \in backups
  /\ db' = b
  /\ outbox' = {} /\ pending' = {}
  /\ step' = "restore"
  /\ UNCHANGED <<backups, anchor, clientEpoch, delivered, acked>>

Next ==
  \/ \E o \in Objects : Submit(o) \/ ApproveFlash(o) \/ Claim(o) \/ ClaimCheck(o) \/ ClaimCommit(o)
  \/ \E r \in Recipients, v \in BOOLEAN : ChangeAuth(r, v)
  \/ \E r \in Recipients : Observe(r)
  \/ Anchor \/ Backup \/ Crash
  \/ \E b \in backups : RestoreBackup(b)

Spec == Init /\ [][Next]_vars

\* State-space bound for model checking (not a system property).
Bounded == Len(db.evidence) <= MaxEvidence

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
  /\ db \in DB
  /\ IsPrefix(<<>>, anchor)
  /\ pending \subseteq Objects /\ delivered \subseteq Objects
  /\ clientEpoch \in [Recipients -> 1..MaxEpoch]

NewlyIssued(o) == o \notin db.issued /\ o \in db'.issued /\ step' # "restore"

\* P1: an issuance commits only when the recipient is authorised in the committing state,
\* FLASH dual control is satisfied at the current epoch, and the client's expected epoch is
\* current (stale grants and stale observations are fenced).
IssueRequiresCurrentAuthority ==
  [][\A o \in Objects : NewlyIssued(o) => Releasable(db, o, clientEpoch[Rcpt[o]])]_vars

\* P2: issuance and RELEASE_ISSUED evidence are one-to-one in every reachable database.
EvidenceMatchesIssuance ==
  \A o \in Objects :
    /\ (o \in db.issued) <=> (\E i \in 1..Len(db.evidence) :
                                db.evidence[i].kind = "RELEASE_ISSUED" /\ db.evidence[i].o = o)
    /\ Cardinality({i \in 1..Len(db.evidence) :
                     db.evidence[i].kind = "RELEASE_ISSUED" /\ db.evidence[i].o = o}) <= 1

\* P3: a key-bearing response reaches a recipient only after its decision is anchored by the
\* custodian, whose saved prefix never regresses (P4).
DeliveredImpliesAnchored ==
  Guarded => \A o \in delivered : \E i \in 1..Len(anchor) :
                 anchor[i].o = o /\ anchor[i].kind \in {"RELEASE_ISSUED", "RELEASE_RETRY"}

AnchorMonotone == [][IsPrefix(anchor, anchor')]_anchor

\* P5: once a revocation of r has been acknowledged to the administrator, no key for r is
\* issued or re-sent unless a later re-authorisation of r is present in the same history,
\* including after any database restore.
AckedRevocationHolds ==
  [][\A o \in Objects :
       (step' = "claim" /\ db'.obj[o] = "released" /\ db'.evidence # db.evidence
        /\ db'.evidence[Len(db'.evidence)].kind \in {"RELEASE_ISSUED", "RELEASE_RETRY"}
        /\ db'.evidence[Len(db'.evidence)].o = o)
       => \A a \in acked :
            (a.r = Rcpt[o] /\ a.v = FALSE)
              => /\ a.idx <= Len(db.evidence)
                 /\ db.evidence[a.idx] = Ev("AUTH", None, a.r, FALSE, db.evidence[a.idx].e)
                 /\ \E j \in (a.idx + 1)..Len(db.evidence) :
                      db.evidence[j].kind = "AUTH" /\ db.evidence[j].r = a.r /\ db.evidence[j].v]_vars
=============================================================================
