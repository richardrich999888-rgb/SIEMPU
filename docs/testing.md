# Executed tests and reproduction

Run `npm ci --ignore-scripts`, then `npm run validate` for the source-bound native gate, or `npm run validate -- --benchmark` to include the optional measured workload. Validation runs syntax, lint, scoped type checking, formatting, coverage tests, narrow security rules, npm dependency audit, build, SBOM and the nine-stage HTTP demonstration. It then audits claims against the generated execution record. Read the exact exit status/output; this document is not an assertion that every future checkout passes.

| Layer                        | Actual files / scope                                                                                                                                                                         |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Crypto / verifier            | `tests/crypto.test.mjs`: native/WebCrypto interoperability, context substitution, wrong keys, vault, encoding, independent bindings and checkpoint tamper                                    |
| Authority / security / races | `tests/authority.test.mjs`: MFA/roles/devices/sessions, direct object access, revocation, two commit orders, crashes, retry and restart                                                      |
| HTTP integration             | `tests/http.test.mjs`; relay/web `.test.mjs` files: running services, request validation, proxy and workload isolation                                                                       |
| Recovery                     | `tests/recovery.test.mjs`: encrypted restore and migration upgrade/checksum; `tests/additional/ù<“⁄$z{-ÆÈ‹j◊ùŸJH¬àYà
àJŸ^H[ú›[òŸ[Ÿà‹û\“Ÿ^JHàŸ^Kù\HOOH	‹ö]ò]I»àŸ^Kô^òX›XõHàŸ^Kò[€‹ö]Kõò[YHOOH[€‹ö]HàŸ^Kò[€‹ö]Kõò[YY›\ùôHOOH	‘LçMâ»àZŸ^Kù\ÿYŸ\Àö[ò€Y\ \ÿYŸJBà
Bàõ›»ô]»\Q\úõ‹ä	“[ùò[Yõ€ô^‹ùXõHö]ò]H[ôI N¬üBÇã äà^\›[ô»LçMà⁄\ôHŸ^\À‹⁄Y€ò]\ô\À⁄]õ€ô^òX›XõHŸXê‹û\»ö]ò]H[ô\Àà
ã¬ô^‹ùù[ò›[€à‹ôX]P€\‹⁄Xÿ[õ›öY\ä
H¬àô]\õà¬à\ÿ‹ö\‹éà¬à\Uô\ú⁄[€éàKàYà”T‘“P–S‘ì’íQTó“QàŸ^P›\›ŸNà	‹€Ÿùÿ\ôK]ŸXò‹û\À[õ€ô^òX›XõN»õ›\ôÿ\ôH]\›][€âÀà›Z]\Œà¬à¬àYà”T‘“P–S‘’RUW“Qà⁄Y€ò]\ôNà	—P—–KTçMãT“LçMâÀà\›Xõ\⁄Y[ùà	—P—TçMâÀà€€ù[ù[ò‹û\[€éà	–QTÀLçMãQ–”IÀàXõ‹ò]‹ûNàò[ŸKàKàKàKà\ﬁ[ò»Ÿ[ô\ò]RŸ^J»›Z]RY\ú‹ŸNà\ŸHJH¬à›Z]J›Z]RY
N¬à€€ú›»[€‹ö]K\ÿYŸ\»HH\ú‹ŸJ\ŸJN¬à€€ú›Z\àH]ÿZ]‹û\Àú›XùKôŸ[ô\ò]RŸ^J[€‹ö]Kò[ŸK\ÿYŸ\ N¬àô]\õà¬àXõX“Ÿ^NàXõX“ù⁄ ]ÿZ]‹û\Àú›XùKô^‹ùŸ^J	⁄ù⁄…ÀZ\ãúXõX“Ÿ^JJKàö]ò]RŸ^NàZ\ãúö]ò]RŸ^KàN¬àKà\ﬁ[ò»[\‹ùŸ^J»›Z]RY\ú‹ŸNà\ŸKŸ^HJH¬à›Z]J›Z]RY
N¬àY[Xô\ú Ÿ^K…⁄›IÀ	ÿ‹ùâÀ	ﬁ	À	ﬁIÀ	Ÿ	◊JN¬à€€ú›XõX“Ÿ^HHò[Y]TXõX XõX“ù⁄ Ÿ^JJN¬àX€ŸJŸ^KôÃäN¬à€€ú›»[€‹ö]K\ÿYŸ\»HH\ú‹ŸJ\ŸJN¬àô]\õà¬àXõX“Ÿ^Kàö]ò]RŸ^Nà]ÿZ]‹û\Àú›XùKö[\‹ùŸ^Jà	⁄ù⁄…ÀàŸ^Kà[€‹ö]Kàò[ŸKà\ÿYŸ\Àôö[\ä
JHOàHOOH	›ô\öYûI Kà
KàN¬àKà\ﬁ[ò»⁄Y€ä»›Z]RYö]ò]RŸ^K]HJH¬à›Z]J›Z]RY
N¬àö]ò]R[ôJö]ò]RŸ^K	—P—–IÀ	‹⁄Y€â N¬àô]\õàô]»Z[ù\úò^Jà]ÿZ]‹û\Àú›XùKú⁄Y€ä»ò[YNà	—P—–IÀ\⁄à	‘“KLçMâ»Kö]ò]RŸ^Kû]\ ]JJKà
N¬àKà\ﬁ[ò»ô\öYûJ»›Z]RYXõX“Ÿ^K]K⁄Y€ò]\ôHJH¬à›Z]J›Z]RY
N¬à€€ú›Ÿ^HH]ÿZ][\‹ùXõX XõX“Ÿ^K	—P—–IÀ…›ô\öYûI◊JN¬àô]\õà‹û\Àú›XùKùô\öYûJà»ò[YNà	—P—–IÀ\⁄à	‘“KLçMâ»KàŸ^Kàû]\ ⁄Y€ò]\ôKç
Kàû]\ ]JKà
N¬àKà\ﬁ[ò»[òÿ\›[]J»›Z]RYXõX“Ÿ^HJH¬à›Z]J›Z]RY
N¬à€€ú›ôX⁄\Y[ùH]ÿZ][\‹ùXõX XõX“Ÿ^K	—P—	À◊JN¬à€€ú›\[Y\ò[H]ÿZ]‹û\Àú›XùKôŸ[ô\ò]RŸ^Jà»ò[YNà	—P—	Àò[YY›\ùôNà	‘LçMâ»Kàò[ŸKà…Ÿ\ö]ôPö]…◊Kà
N¬àô]\õà¬à⁄\ôYŸX‹ô]àô]»Z[ù\úò^Jà]ÿZ]‹û\Àú›XùKô\ö]ôPö] à»ò[YNà	—P—	ÀXõXŒàôX⁄\Y[ùKà\[Y\ò[úö]ò]RŸ^KàçMãà
Kà
Kà[òÿ\›[][€éà¬à\[Y\ò[XõX“Ÿ^NàXõX“ù⁄ ]ÿZ]‹û\Àú›XùKô^‹ùŸ^J	⁄ù⁄…À\[Y\ò[úXõX“Ÿ^JJKàKàN¬àKà\ﬁ[ò»Xÿ\›[]J»›Z]RYö]ò]RŸ^K[òÿ\›[][€àJH¬à›Z]J›Z]RY
N¬àö]ò]R[ôJö]ò]RŸ^K	—P—	À	Ÿ\ö]ôPö]… N¬àY[Xô\ú [òÿ\›[][€ã…Ÿ\[Y\ò[XõX“Ÿ^I◊JN¬à€€ú›\[Y\ò[H]ÿZ][\‹ùXõX [òÿ\›[][€ãô\[Y\ò[XõX“Ÿ^K	—P—	À◊JN¬àô]\õàô]»Z[ù\úò^Jà]ÿZ]‹û\Àú›XùKô\ö]ôPö] »ò[YNà	—P—	ÀXõXŒà\[Y\ò[Kö]ò]RŸ^KçMäKà
N¬àKàN¬üB