import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';
import { ApiClient, enrollUser } from './helpers/client.mjs';

// Regression for CodeQL js/insufficient-password-hash (PR #17): a client-chosen password in
// POST /api/admin/users entered the operation-proof request hash (unsalted SHA-256) that the
// authority persists with the challenge, bypassing scrypt's cost for anyone with the database.

test('authority generates the initial password; a client-supplied password is refused', async (t) => {
  const f = await coreFixture(t);
  await f.clients.admin.authenticate();
  const refused = await f.clients.admin.admin('POST', '/api/admin/users', {
    username: 'chosen-password',
    password: 'Admin-Chosen-Password-1',
    unitId: f.provisioned.units.B,
    role: 'operator',
    missionIds: ['DEMO-MISSION'],
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.body.code, 'PASSWORD_SERVER_GENERATED');
  assert.equal(
    f.authority.get("SELECT COUNT(*) AS n FROM users WHERE username='chosen-password'").n,
    0,
  );

  const { profile } = await enrollUser(f.clients.admin, {
    username: 'generated-password',
    unitId: f.provisioned.units.B,
  });
  // 18 random bytes, base64url: 24 characters, never equal across users.
  assert.match(profile.password, /^[A-Za-z0-9_-]{24}$/);
  const row = f.authority.get("SELECT password FROM users WHERE username='generated-password'");
  assert.equal(row.password.includes(profile.password), false);
  // No challenge payload carries the password or a body that contained it.
  for (const c of f.authority.all('SELECT payload FROM challenges'))
    assert.equal(c.payload.includes(profile.password), false);
  // The generated password works for login (enrollUser already bound a device with it).
  const again = new ApiClient(f.transport, profile);
  assert.equal(
    (
      await again.request('POST', '/api/auth/login', {
        username: profile.username,
        password: profile.password + 'x',
        otp: '000000',
      })
    ).status,
    401,
  );
});
