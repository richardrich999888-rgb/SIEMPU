import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';
import { totp, verify, hash } from './helpers/client.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';

async function request(client, otp) {
  const body = { otp };
  return { ...body, proof: await client.proof('renew-session', body) };
}

test('session renewal atomically replaces the bound session and records signed evidence', async (t) => {
  const f = await coreFixture(t),
    client = f.clients.alice;
  await client.authenticate();
  const old = client.token;
  const body = await request(client, totp(f.profiles.alice.totpSecret, Date.now() + 30000));
  const result = await client.ok('POST', '/api/auth/renew', body);
  assert.notEqual(result.token, old);
  assert.equal(result.device.id, f.profiles.alice.deviceId);
  assert.equal(result.user.id, f.profiles.alice.userId);
  assert.equal((await client.request('GET', '/api/auth/me')).status, 401);
  assert.equal((await client.request('POST', '/api/auth/renew', body)).status, 401);
  client.token = result.token;
  assert.equal((await client.ok('GET', '/api/auth/me')).device.id, result.device.id);
  const rows = f.authority.all('SELECT record FROM evidence').map((r) => JSON.parse(r.record));
  const event = rows.find((r) => r.payload.eventType === 'SESSION_RENEWED');
  assert.ok(verify(event.payload, event.signature, f.provisioned.serverPublicKey));
  assert.equal(JSON.stringify(rows).includes(result.token), false);
  assert.equal(
    f.authority.get('SELECT revoked FROM sessions WHERE token_hash=?', hash(old)).revoked,
    1,
  );
  assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
});

test('renewal refuses session/user/device revocation and expiry committed after challenge', async (t) => {
  for (const kind of ['session', 'user', 'device', 'expired'])
    await t.test(kind, async (t) => {
      const f = await coreFixture(t),
        c = f.clients.alice;
      await c.authenticate();
      const body = await request(c, totp(c.profile.totpSecret, Date.now() + 30000));
      const count = f.authority.get('SELECT count(*) n FROM sessions').n;
      f.authority.tx(() => {
        if (kind === 'session')
          f.authority.run('UPDATE sessions SET revoked=1 WHERE token_hash=?', hash(c.token));
        if (kind === 'user')
          f.authority.run('UPDATE users SET active=0 WHERE id=?', c.profile.userId);
        if (kind === 'device')
          f.authority.run("UPDATE devices SET status='revoked' WHERE id=?", c.profile.deviceId);
        if (kind === 'expired')
          f.authority.run('UPDATE sessions SET expires_at=0 WHERE token_hash=?', hash(c.token));
      });
      const response = await c.request('POST', '/api/auth/renew', body);
      assert.ok([401, 403].includes(response.status));
      assert.equal(response.body.token, undefined);
      assert.equal(f.authority.get('SELECT count(*) n FROM sessions').n, count);
      assert.equal(f.authority.get('SELECT count(*) n FROM issuances').n, 0);
    });
});

test('renewal requires unused MFA, correct device/body proof and exact schema', async (t) => {
  const f = await coreFixture(t),
    c = f.clients.alice;
  await c.authenticate();
  const now = Date.now(),
    same = totp(c.profile.totpSecret, now),
    fresh = totp(c.profile.totpSecret, now + 30000);
  assert.equal(
    (await c.request('POST', '/api/auth/renew', await request(c, same))).body.code,
    'MFA_REPLAY',
  );
  const wrongScope = { otp: fresh, proof: await c.proof('grant', { otp: fresh }) };
  assert.equal((await c.request('POST', '/api/auth/renew', wrongScope)).body.code, 'PROOF_SCOPE');
  const changed = await request(c, fresh);
  changed.otp = same;
  assert.equal(
    (await c.request('POST', '/api/auth/renew', changed)).body.code,
    'PROOF_BODY_MISMATCH',
  );
  for (const body of [
    { otp: 123456, proof: {} },
    { otp: fresh, proof: {}, extra: true },
  ])
    assert.equal((await c.request('POST', '/api/auth/renew', body)).status, 400);
  const event = f.authority
    .all('SELECT record FROM evidence')
    .map((r) => JSON.parse(r.record))
    .find((r) => r.payload.reason === 'MFA_REPLAY');
  assert.ok(verify(event.payload, event.signature, f.provisioned.serverPublicKey));
});

test('endpoint proactively renews once under concurrency; never logs in again after expiry or denial', async (t) => {
  const f = await coreFixture(t),
    routes = [];
  const endpoint = new IntegrationEndpoint({
    url: 'https://synthetic.invalid',
    tls: {},
    profile: f.profiles.alice,
    authorityKey: f.provisioned.serverPublicKey,
    sessionRenewal: true,
  });
  // Unit transport bridge only; combined native acceptance separately uses real TLS.
  endpoint.call = async (method, path, body) => {
    routes.push(path);
    const r = await f.transport(method, path, body, endpoint.token);
    if (r.status !== 200) throw Object.assign(new Error(r.body.code), { code: r.body.code });
    return r.body;
  };
  await endpoint.authenticate();
  const old = endpoint.token;
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 800000 });
  await Promise.all([endpoint.ensureSession(), endpoint.ensureSession()]);
  assert.notEqual(endpoint.token, old);
  assert.equal(routes.filter((p) => p === '/api/auth/renew').length, 1);
  f.authority.run('UPDATE sessions SET revoked=1 WHERE token_hash=?', hash(endpoint.token));
  t.mock.timers.tick(800000);
  await assert.rejects(endpoint.ensureSession(), { code: 'SESSION_INVALID' });
  assert.equal(endpoint.token, null);
  assert.equal(routes.filter((p) => p === '/api/auth/login').length, 1);
  endpoint.token = old;
  endpoint.expiresAt = Date.now() - 1;
  await assert.rejects(endpoint.ensureSession(), { code: 'SESSION_INVALID' });
  assert.equal(endpoint.token, null);
});
