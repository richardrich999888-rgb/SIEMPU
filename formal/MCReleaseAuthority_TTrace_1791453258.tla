---- MODULE MCReleaseAuthority_TTrace_1791453258 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, MCReleaseAuthority

_expression ==
    LET MCReleaseAuthority_TEExpression == INSTANCE MCReleaseAuthority_TEExpression
    IN MCReleaseAuthority_TEExpression!expression
----

_trace ==
    LET MCReleaseAuthority_TETrace == INSTANCE MCReleaseAuthority_TETrace
    IN MCReleaseAuthority_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        pending = ({})
        /\
        anchor = (<<>>)
        /\
        delivered = ({"o1"})
        /\
        step = ("claim")
        /\
        clientEpoch = ([r1 |-> 1])
        /\
        outbox = ({})
        /\
        acked = ({[r |-> "r1", v |-> FALSE, idx |-> 3]})
        /\
        db = ([epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_RETRY", r |-> "r1", v |-> TRUE, e |-> 1]>>])
        /\
        backups = ({[epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>]})
    )
----

_init ==
    /\ delivered = _TETrace[1].delivered
    /\ db = _TETrace[1].db
    /\ outbox = _TETrace[1].outbox
    /\ pending = _TETrace[1].pending
    /\ clientEpoch = _TETrace[1].clientEpoch
    /\ step = _TETrace[1].step
    /\ anchor = _TETrace[1].anchor
    /\ acked = _TETrace[1].acked
    /\ backups = _TETrace[1].backups
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ delivered  = _TETrace[i].delivered
        /\ delivered' = _TETrace[j].delivered
        /\ db  = _TETrace[i].db
        /\ db' = _TETrace[j].db
        /\ outbox  = _TETrace[i].outbox
        /\ outbox' = _TETrace[j].outbox
        /\ pending  = _TETrace[i].pending
        /\ pending' = _TETrace[j].pending
        /\ clientEpoch  = _TETrace[i].clientEpoch
        /\ clientEpoch' = _TETrace[j].clientEpoch
        /\ step  = _TETrace[i].step
        /\ step' = _TETrace[j].step
        /\ anchor  = _TETrace[i].anchor
        /\ anchor' = _TETrace[j].anchor
        /\ acked  = _TETrace[i].acked
        /\ acked' = _TETrace[j].acked
        /\ backups  = _TETrace[i].backups
        /\ backups' = _TETrace[j].backups

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("MCReleaseAuthority_TTrace_1791453258.json", _TETrace)

=============================================================================

 Note that you can extract this module `MCReleaseAuthority_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `MCReleaseAuthority_TEExpression.tla` file takes precedence 
  over the module `MCReleaseAuthority_TEExpression` below).

---- MODULE MCReleaseAuthority_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, MCReleaseAuthority

expression == 
    [
        \* To hide variables of the `MCReleaseAuthority` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        delivered |-> delivered
        ,db |-> db
        ,outbox |-> outbox
        ,pending |-> pending
        ,clientEpoch |-> clientEpoch
        ,step |-> step
        ,anchor |-> anchor
        ,acked |-> acked
        ,backups |-> backups
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_deliveredUnchanged |-> delivered = delivered'
        
        \* Format the `delivered` variable as Json value.
        \* ,_deliveredJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(delivered)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_deliveredModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].delivered # _TETrace[s-1].delivered
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE MCReleaseAuthority_TETrace ----
\*EXTENDS IOUtils, TLC, MCReleaseAuthority
\*
\*trace == IODeserialize("MCReleaseAuthority_TTrace_1791453258.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE MCReleaseAuthority_TETrace ----
EXTENDS TLC, MCReleaseAuthority

trace == 
    <<
    ([pending |-> {},anchor |-> <<>>,delivered |-> {},step |-> "init",clientEpoch |-> [r1 |-> 1],outbox |-> {},acked |-> {},db |-> [epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "absent", o2 |-> "absent"], issued |-> {}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<>>],backups |-> {}]),
    ([pending |-> {},anchor |-> <<>>,delivered |-> {},step |-> "submit",clientEpoch |-> [r1 |-> 1],outbox |-> {},acked |-> {},db |-> [epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "queued", o2 |-> "absent"], issued |-> {}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1]>>],backups |-> {}]),
    ([pending |-> {},anchor |-> <<>>,delivered |-> {"o1"},step |-> "claim",clientEpoch |-> [r1 |-> 1],outbox |-> {},acked |-> {},db |-> [epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>],backups |-> {}]),
    ([pending |-> {},anchor |-> <<>>,delivered |-> {"o1"},step |-> "backup",clientEpoch |-> [r1 |-> 1],outbox |-> {},acked |-> {},db |-> [epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>],backups |-> {[epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>]}]),
    ([pending |-> {},anchor |-> <<>>,delivered |-> {"o1"},step |-> "change",clientEpoch |-> [r1 |-> 1],outbox |-> {},acked |-> {[r |-> "r1", v |-> FALSE, idx |-> 3]},db |-> [epoch |-> 2, auth |-> [r1 |-> FALSE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1], [o |-> "none", kind |-> "AUTH", r |-> "r1", v |-> FALSE, e |-> 2]>>],backups |-> {[epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>]}]),
    ([pending |-> {},anchor |-> <<>>,delivered |-> {"o1"},step |-> "restore",clientEpoch |-> [r1 |-> 1],outbox |-> {},acked |-> {[r |-> "r1", v |-> FALSE, idx |-> 3]},db |-> [epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>],backups |-> {[epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>]}]),
    ([pending |-> {},anchor |-> <<>>,delivered |-> {"o1"},step |-> "claim",clientEpoch |-> [r1 |-> 1],outbox |-> {},acked |-> {[r |-> "r1", v |-> FALSE, idx |-> 3]},db |-> [epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_RETRY", r |-> "r1", v |-> TRUE, e |-> 1]>>],backups |-> {[epoch |-> 1, auth |-> [r1 |-> TRUE], obj |-> [o1 |-> "released", o2 |-> "absent"], issued |-> {"o1"}, approval |-> [o1 |-> 0, o2 |-> 0], evidence |-> <<[o |-> "o1", kind |-> "SUBMITTED", r |-> "none", v |-> FALSE, e |-> 1], [o |-> "o1", kind |-> "RELEASE_ISSUED", r |-> "r1", v |-> TRUE, e |-> 1]>>]}])
    >>
----


=============================================================================

---- CONFIG MCReleaseAuthority_TTrace_1791453258 ----
CONSTANTS
    Recipients <- MCRecipients
    Objects <- MCObjects
    Rcpt <- MCRcpt
    Flash <- MCFlash
    MaxEpoch = 4
    MaxEvidence = 7
    MaxBackups = 1
    Atomic = TRUE
    Guarded = FALSE

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Thu Oct 08 09:54:19 UTC 2026