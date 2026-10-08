# iDEX grant rules relevant to a DISC-14 winner (research record)

**Retrieved:** 8 October 2026.

**Method:** web search limited to official domains (idex.gov.in, pib.gov.in, drdo.gov.in).
Those hosts were **not reachable** from the build environment: DNS failed, and the proxy returned
CONNECT 403. Every value below is therefore an **official-domain search-index excerpt that was not
fetched or read in full**.

**Before external use:** someone with direct access must re-check each value against the current
SPARK Grant Agreement, the Financial FAQ and the PS-69 page.

## Facts used in the funding model

| #   | Fact                  | Value                                                                                                                                       | Official URL (indexed)                              | Excerpt                                                                                                                 |
| --- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| G1  | DISC grant ceiling    | Up to Rs 1.5 crore                                                                                                                          | https://idex.gov.in/faq                             | "Grant support of up to ₹1.5 crore is provided to DISC winners"                                                         |
| G2  | Cap relative to PDB   | Lower of the tier cap or 50 % of Product Development Budget                                                                                 | https://idex.gov.in/financial-faq                   | "SPARK Grant will remain up to Rs.1.5 Cr/10 Cr/ 25 Cr or half (50%) the product development budget whichever is lower." |
| G3  | Matching contribution | At least 50 % of total project cost; cash, past expenditure or in-kind; mandatory                                                           | https://idex.gov.in/faq                             | "MC is at least 50% of the Total Project Cost."                                                                         |
| G4  | IP counted as MC      | Lower of 20 % of MC or Rs 25 lakh                                                                                                           | https://idex.gov.in/financial-faq                   | "capped at 20% of the total Matching contribution or the amount Rs. 25 Lac whichever is lower."                         |
| G5  | PDB composition       | PDB = SPARK grant + MC; tentative at signing                                                                                                | https://idex.gov.in/financial-faq                   | "Product development budget(Spark Grant and Matching contribution)"                                                     |
| G6  | Eligible spend        | R&D, prototyping, pilot implementation, market assessment; equipment at amortised or depreciated cost                                       | SPARK document (idex.gov.in uploads); financial FAQ | "a. Research & Development b. Prototyping c. Pilot Implementation d. Market Assessment"                                 |
| G7  | Ineligible spend      | Cost overruns, land/buildings, new R&D centre, investments, loan interest, fines, entertainment, and any spend outside the approved PDB/WBS | https://idex.gov.in/financial-faq                   | "Cost overruns - The SPARK Grantee shall bear the additional cost"                                                      |
| G8  | Tranches              | 6 milestones: M0 10 %, M1–M4 20 % each, M5 10 % of sanctioned grant; milestones set by the HPSC                                             | https://idex.gov.in/faq                             | "in the form of 6 Milestones"                                                                                           |
| G9  | Higher tiers          | iDEX Prime above Rs 1.5 cr up to Rs 10 cr; ADITI up to 50 % of PDB, max Rs 25 cr                                                            | PIB PRID 1818984; idex.gov.in ADITI scheme PDF      | "support projects, requiring support beyond Rs 1.5 crore up to Rs 10 crore"                                             |
| G10 | PS-69 listing         | DISC 14, Challenge 69, Indian Air Force                                                                                                     | https://idex.gov.in//disc-category/45               | "Challenge 69 Secure Information Exchange Platform for Military Units (SIEPMU) on public internet"                      |

## Not verified

- The full PS-69 page text (`/challenges-cpt/2507`). The repository's requirement ledger uses the
  DISC-14 compendium (`docs/requirements/README.md`).
- Formal PDB definition and its annexure.
- Prime-cost and overhead percentage limits.
- The deliverable that triggers each tranche.
- Whether a newer agreement revision changes any value above.
- Any official SAG grading procedure. None was found; DRDO describes SAG only as a cryptology lab.
  The question is recorded as Q15 in `docs/requirements/open-questions.md`.

## Conflicts in official wording

- The FAQ calls the funding grant-in-aid ("DIO does not take any equity"). The SPARK document still
  says "grant/equity/debt/other relevant structures".
- One FAQ entry expands HPSC as "High-Powered Steering Committee".
- For DISC, the 50 % ratio comes from the general Financial FAQ wording, not from a DISC-specific
  document.
