import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { coreFixture, httpFixture } from './helpers/fixture.mjs';
import { createControlServer } from '../services/control/server.mjs';
import { createWebServer } from '../services/web/server.mjs';
import { createRelayServer } from '../services/relay/server.mjs';
import { createRelayClient } from '../services/relay/client.mjs';

async function listen(server, port = 0) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}
async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  });
}

test('mission readiness requires a current session, bound device and admin or auditor role over HTTP', async (t) => {
  const f = await httpFixture(t);
  const path = '/api/admin/readiness';
  assert.equal((await f.transport('GET', path)).status, 401);
  await f.clients.admin.login();
  assert.equal((await f.clients.admin.request('GET', path)).status, 403);
  await f.clients.admin.bind();
  const report = await f.clients.admin.ok('GET', path);
  assert.equal(report.releaseDecision, 'NOT_QUALIFIED');
  assert.equal(report.baseline.provisionalTrl, 4);
  assert.ok(report.qualificationGates.every((g) => g.status === 'EVIDENCE_REQUIRED'));
  assert.equal(report.checks.find((c) => c.id === 'control-mtls').status, 'GAP');
  assert.equal(report.checks.find((c) => c.id === 'https-origin').status, 'GAP');
  assert.equal(report.recovery.state, 'NOT_CONFIGURED');
  const text = JSON.stringify(report);
  for (const profile of Object.values(f.profiles)) {
    assert.ok(!text.includes(profile.password));
    assert.ok(!text.includes(profile.totpSecret));
    assert.ok(!text.includes(profile.keys.signing.privateKey.d));
  }
  for (const name of ['alice', 'eve']) {
    await f.clients[name].authenticate();
    assert.equal((await f.clients[name].request('GET', path)).status, 403);
  }
  await f.clients.admin.ok('POST', '/api/auth/logout', {});
  assert.equal((await f.clients.admin.request('GET', path)).status, 401);
});

test('auditor can read readiness without changing policy, evidence or crypto state', async (t) => {
  const f = await coreFixture(t);
  f.authority.run("UPDATE users SET role='auditor' WHERE username='bob'");
  await f.clients.bob.authenticate();
  const before = {
    epoch: f.authority.epoch(),
    count: f.authority.get('SELECT COUNT(*) n FROM evidence').n,
    policy: f.authority.crypto.policy(),
  };
  const report = await f.clients.bob.ok('GET', '/api/admin/readiness');
  assert.equal(report.checks.find((c) => c.id === 'control-mtls').status, 'UNKNOWN');
  assert.deepEqual(
    {
      epoch: f.authority.epoch(),
      count: f.authority.get('SELECT COUNT(*) n FROM evidence').n,
      policy: f.authority.crypto.policy(),
    },
    before,
  );
  assert.equal((await f.clients.bob.request('PUT', '/api/admin/readiness', {})).status, 403);
  f.authority.run("UPDATE devices SET status='revoked' WHERE id=?", f.profiles.bob.deviceId);
  assert.notEqual((await f.clients.bob.request('GET', '/api/admin/readiness')).status, 200);
});

test('all local observations can be present without assigning operational qualification', async (t) => {
  const f = await coreFixture(t);
  f.authority.deployment = {
    controlMutualTls: true,
    publicOriginHttps: true,
    monitoringConfigured: true,
  };
  // Test-only guard: this exercises reporting, not custody signature validation.
  f.authority.recoveryGuard = { state: 'VALIDATED', authorize: async () => {}, allows: () => true };
  await f.clients.admin.authenticate();
  const report = await f.clients.admin.ok('GET', '/api/admin/readiness');
  assert.ok(report.checks.every((c) => c.status === 'OBSERVED'));
  assert.equal(report.releaseDecision, 'NOT_QUALIFIED');
  assert.ok(report.qualificationGates.every((g) => g.status === 'EVIDENCE_REQUIRED'));
  f.authority.crypto.allowPqcLab = true;
  assert.equal(
    (await f.clients.admin.ok('GET', '/api/admin/readiness')).checks.find(
      (c) => c.id === 'lab-crypto',
    ).status,
    'GAP',
  );
});

test('gateway readiness fails during a real relay outage and recovers after relay restart', async (t) => {
  const f = await coreFixture(t);
  const secret = randomBytes(32);
  const options = { database: join(f.dir, 'readiness-relay.sqlite'), secret };
  let relay = createRelayServer(options);
  const relayUrl = await listen(relay);
  const relayPort = relay.address().port;
  f.authority.relay = createRelayClient({ baseUrl: relayUrl, secret });
  const control = createControlServer({ authority: f.authority });
  const controlUrl = await listen(control);
  const web = createWebServer({ controlUrl });
  const base = await listen(web);
  t.after(async () => {
    await close(web);
    await close(control);
    await close(relay);
  });
  const status = async (path) =>
    (await fetch(base + path, { signal: AbortSignal.timeout(4000) })).status;
  assert.equal(await status('/health/ready'), 200);
  await close(relay);
  assert.equal(await status('/health/live'), 200);
  assert.equal(await status('/health/ready'), 503);
  assert.equal((await fetch(controlUrl + '/live')).status, 200);
  relay = createRelayServer(options);
  await listen(relay, relayPort);
  assert.equal(await status('/health/ready'), 200);
});

test('readiness rejects malformed successful responses, wrong services and unavailable authorities', async (t) => {
  let body = '{}';
  let status = 200;
  const paths = [];
  const upstream = createServer((req, res) => {
    paths.push(req.url);
    res.writeHead(status);
    res.end(body);
  });
  const controlUrl = await listen(upstream);
  const web = createWebServer({ controlUrl });
  const base = await listen(web);
  t.after(async () => {
    await close(web);
    await close(upstream);
  });
  for (const value of [
    '{}',
    '<html>ok</html>',
    '{"status":"ok","service":"relay"}',
    '{"status":"unavailable","service":"control"}',
  ]) {
    body = value;
    assert.equal((await fetch(base + '/health/ready')).status, 503);
  }
  body = '{"status":"ok","service":"control"}';
  assert.equal((await fetch(base + '/health/ready')).status, 200);
  status = 503;
  assert.equal((await fetch(base + '/health/ready')).status, 503);
  assert.ok(paths.every((path) => path === '/ready'));
  await close(upstream);
  assert.equal((await fetch(base + '/health/ready')).status, 503);
});

test('relay health probe is bounded and rejects malformed or redirected responses', async (t) => {
  let mode = 'valid';
  const upstream = createServer((_req, res) => {
    if (mode === 'hang') return;
    if (mode === 'redirect') {
      res.writeHead(302, { location: '/elsewhere' });
      res.end();
      return;
    }
    res.end(mode === 'valid' ? '{"status":"ok","service":"blind-ciphertext-relay"}' : mode);
  });
  const baseUrl = await listen(upstream);
  t.after(() => close(upstream));
  const client = createRelayClient({ baseUrl, secret: randomBytes(32) });
  assert.equal(await client.health(), true);
  mode = '{}';
  assert.equal(await client.health(), false);
  for (const value of ['not-json', 'redirect', 'x'.repeat(2048), 'hang']) {
    mode = value;
    await assert.rejects(client.health());
  }
});
