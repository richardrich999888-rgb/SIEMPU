# Technical demonstration map

| Observation                             | Actual mechanism                                   | Evidence                                                   |
| --------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------- |
| A/B authenticate and bind devices       | scrypt/TOTP + signed challenge                     | authority suite; browser record                            |
| Relay cannot read the payload           | endpoint AES-GCM; opaque key withheld by authority | crypto/interoperability tests; relay inspection assertions |
| Denied identity cannot claim B's object | recipient/device/unit/role checks                  | HTTP demo + authority negatives                            |
| Local work survives outage/reload       | encrypted vault/outbox, cached shell/grant         | actual Chromium offline/reload test                        |
| Changed policy holds backlog            | fresh signed control + prepare/current claim       | browser deny/allow; HTTP demo                              |
| Old READY cannot release                | serialised epoch-fenced issuance                   | separate-process race tests                                |
| Restart does not forget authority       | durable SQLite and unique issuance                 | crash/reopen/recovery tests                                |
| Receipt can be checked independently    | native verifier and independent root/checkpoint    | detached positive/negative vectors                         |

The release moment is capability-issuance commit, not network transmission. Already-released plaintext is not recalled. Ciphertext plus withheld wrapped-key envelope are separate paths. Do not describe normal data-format checking as a cross-domain guard or the synthetic adapter as AFNET integration.

See [runbook](demo-runbook.md), [evidence index](evidence-index.md), [limitations](../limitations.md) and [claims](../claims.md).
