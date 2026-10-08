------------------------- MODULE MCReleaseAuthority -------------------------
(* Finite instance for TLC. Bounds are documented in formal/README.md.     *)
EXTENDS ReleaseAuthority

MCRecipients == {"r1"}
MCObjects == {"o1", "o2"}
MCRcpt == [o \in MCObjects |-> "r1"]
MCFlash == {"o2"}
=============================================================================
