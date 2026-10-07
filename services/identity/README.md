# Identity interface

This is the identity boundary of the existing control process. Executable methods
live in [`Authority`](../control/core.mjs); this directory does not introduce a
separate server, datastore or importable implementation.

## Public contract

All protected routes use `Authorization: Bearer <token>`. Mutation bodies are JSON.

| HTTP route                            | Request                                                 | Response / authority                                                  |
| ------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------- |
| `POST /api/auth/login`                | `{username,password,otp}`                               | `{token,user,expiresAt}`; password and unused six-digit TOTP required |
| `GET /api/auth/me`                    | None                                                    | `{user,device,expiresAt}`; authenticated session, device may be null  |
| `POST /api/auth/logout`               | `{}`                                                    | `{ok:true}`; revokes the caller's session                             |
| `POST /api/admin/units`               | `{name,proof}`                                          | `{unit:{id,name}}`; bound administrator                               |
| `POST /api/admin/users`               | `{username,password,unitId,role,missionIds,proof}`      | `{user,totpSecret,otpauthUri}`; bound administrator                   |
| `PATCH /api/admin/users/:id`          | One or more of `{active,role,missionIds}`, plus `proof` | `{user}`; bound administrator                                         |
| `POST /api/admin/sessions/:id/revoke` | `{proof}`                                               | `{ok:true}`; bound administrator                                      |

`user` is `{id,username,unitId,role,missionIds,active}`. Roles are `admin`,
`operator`, `viewer`, and `auditor`. Provisioning accepts a 3–80 character username
matching `[a-zA-Z0-9_.-]`, a 12–256 character password, an existing unit, and up to
32 mission identifiers matching `[A-Za-z0-9._:-]{1,80}`. User patching does not
provide a unit-change, password-change or MFA-reset endpoint. Administrator
mutations use the [device operation proof](../device/README.md) with operation
`admin:<METHOD>:<path>`.

## Internal methods and persistence

`login(body, ip)` verifies scrypt password hashes and TOTP, creates a 15-minute
session and returns the opaque token once. `authenticate(token)` loads the token
digest, checks expiry/revocation and reloads the active user. `bound(session)` adds
a fresh session/device check; `role(session, allowed)` enforces the role supplied
by that fresh view. Direct callers must retain these checks rather than reuse a
previously authorized object indefinitely.

The boundary owns `units`, `users`, `sessions` and login rate-limit buckets in the
control SQLite database. Passwords use scrypt (`N=16384,r=8,p=1`) with random
16-byte salts. TOTP secrets are encrypted with the server master key; session
tokens are stored as SHA-256 digests. Login limits are 40/IP and 8/username per
minute; authenticated requests share a 500/session/minute limit.

Login atomically advances the durable TOTP replay floor, inserts the session and
appends `LOGIN` evidence in `BEGIN IMMEDIATE`. Logout revocation and evidence also
share a transaction. Administrative changes run through `change()` so their data,
epoch/revocation-version increment and evidence commit together. Current user
activity, role and missions are rechecked by exchange authorization; deactivation
does not require deletion of prior sessions. An administrator cannot deactivate or
demote their own account through the patch endpoint.

Offline administrator recovery is implemented in
[`scripts/recover-identity.mjs`](../../scripts/recover-identity.mjs). See
[`docs/identity.md`](../../docs/identity.md) and
[`tests/authority.test.mjs`](../../tests/authority.test.mjs).
