import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';
import { hash } from './helpers/client.mjs';

test('protected requests enforce the 500/session/minute ceiling and reset without reviving revoked users', async (t) => {
  const f = await coreFixture(t);
  t.mock.timers.enable({ apis: ['Date'], now: Math.ceil(Date.now() / 60000) * 60000 + 1000 });
  const a = f.clients.alice;
  await a.authenticate();
  const session = f.authority.get('SELECT id FROM sessions WHERE token_hash=?', hash(a.token));
  const used = f.authority.get(
    'SELECT count FROM rate_limits WHERE bucket=?',
    'session:' + session.id,
  ).count;
  assert.ok(used > 0 && used < 500);
  for (let n = used; n < 500; n++)
    assert.equal((await a.request('GET', '/api/auth/me')).status, 200);
  for (let i = 0; i < 2; i++) {
    const denied = await a.request('GET', '/api/auth/me');
    assert.equal(denied.status, 429);
    assert.equal(denied.body.code, 'RATE_LIMITED');
  }
  await f.clients.bob.authenticate();
  assert.equal((await f.clients.bob.request('GET', '/api/auth/me')).status, 200);
  t.mock.timers.tick(60000);
  assert.equal((await a.request('GET', '/api/auth/me')).status, 200);
  await f.clients.admin.authenticate();
  assert.equal(
    (
      await f.clients.admin.admin('PATCH', `/api/admin/users/${a.profile.userId}`, {
        active: false,
      })
    ).status,
    200,
  );
  assert.equal((await a.request('GET', '/api/auth/me')).status, 401);
});
