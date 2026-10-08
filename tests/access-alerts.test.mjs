// Wrong-role access produces a bounded, monitored security event (PS-69 threat detection).
import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';

const accessAlerts = (authority, userId) =>
  authority.all("SELECT * FROM alerts WHERE kind='ACCESS_DENIED' AND actor_id=?", userId);

test('a role-forbidden request is refused and recorded as ACCESS_DENIED', async (t) => {
  const f = await coreFixture(t),
    { admin, bob } = f.clients;
  for (const c of [admin, bob]) await c.authenticate();
  const denied = await bob.request('GET', '/api/admin/overview');
  assert.equal(denied.status, 403);
  assert.equal(denied.body.code, 'FORBIDDEN');
  const [alert, ...rest] = accessAlerts(f.authority, f.profiles.bob.userId);
  assert.equal(rest.length, 0);
  assert.equal(alert.reason, 'ROLE_FORBIDDEN');
  // The administrator's own successful request records nothing.
  const overview = await admin.admin('GET', '/api/admin/overview');
  assert.equal(overview.status, 200);
  assert.ok(overview.body.alerts.some((a) => a.kind === 'ACCESS_DENIED'));
  assert.equal(accessAlerts(f.authority, f.profiles.admin.userId).length, 0);
});

test('access alerts are capped per user per minute; denials beyond the cap still fail', async (t) => {
  const f = await coreFixture(t),
    { bob } = f.clients;
  await bob.authenticate();
  const attempts = 25;
  const minute = () => Math.floor(Date.now() / 60000);
  const start = minute();
  for (let i = 0; i < attempts; i++)
    assert.equal((await bob.request('GET', '/api/admin/overview')).status, 403);
  const recorded = accessAlerts(f.authority, f.profiles.bob.userId).length;
  if (minute() === start) assert.equal(recorded, 20);
  // Crossing a minute boundary opens a second window; never more than one alert per attempt.
  else assert.ok(recorded >= 20 && recorded <= attempts, String(recorded));
});

test('non-role refusals (unauthenticated) do not create access alerts', async (t) => {
  const f = await coreFixture(t);
  const anonymous = await f.clients.bob.request('GET', '/api/admin/overview');
  assert.equal(anonymous.status, 401);
  assert.equal(f.authority.all("SELECT * FROM alerts WHERE kind='ACCESS_DENIED'").length, 0);
});
