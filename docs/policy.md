# Current policy engine

[Authority.authorityReason](../services/control/core.mjs) is the deterministic release check. It requires a current signed creation grant, unexpired object, active sender/recipient, approved devices belonging to those users, operator sender, operator/viewer recipient, unchanged units, mutual mission membership, correct recipient encryption-key identity and an explicit allowed `(fromUnit,toUnit,missionId)` policy edge. Missing allow is denial. Unknown/stale authority cannot silently permit release.

A creation grant binds user/device/unit/missions, issuance and expiry, creation epoch/policy digest and DEMO sensitivity. Its one-hour lifetime is a prototype parameter, not an IAF requirement. Admission/release requires it still be valid; a client timestamp does not prove historical offline creation.

Administrative authority changes increment global epoch and revocation version in the same transaction as evidence. `prepare` records READY or HELD but releases no wrapped key. `claim` checks current authority and the caller's expected epoch inside the issuance transaction. Object states are PENDING, HELD, READY, RELEASED, DELIVERED and REJECTED; an HTTP rejection before admission need not create a stored REJECTED row.

[Policy tests](../tests/authority.test.mjs) cover downgrade, mission removal, recipient/device/session revocation, policy race and retry revalidation. This is a bounded RBAC/context policy engine, not a general ABAC language, multilevel-security guard or proof of policy correctness.
