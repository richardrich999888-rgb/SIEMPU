import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateLabPKI } from '../../deployment/secure/lab-pki.mjs';
import {
  createTransportServer,
  requestBytes,
  serverTLS,
  clientTLS,
  secureProfile,
} from '../../packages/transport/tls.mjs';

async function listen(t, server) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(
    () =>
      new Promise((r) => {
        server.close(r);
        server.closeAllConnections();
      }),
  );
  return 'https://127.0.0.1:' + server.address().port;
}
test('TLS 1.3 authenticates CA, hostname, client identity, expiry, CRL and rotation', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-tls-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const pki = generateLabPKI(join(dir, 'pki'));
  for (const n of ['server', 'client', 'other', 'next']) pki.issue(n);
  pki.issue('expired', { expired: true });
  pki.issue('wrong', { wrongHost: true });
  const foreign = generateLabPKI(join(dir, 'foreign'));
  foreign.issue('client');
  let calls = 0;
  const serve = (name, extra = {}) =>
    createTransportServer(
      (_q, r) => {
        calls++;
        r.end('ok');
      },
      {
        ...pki.material(name),
        requestCert: true,
        clientFingerprints: [pki.pin('client')],
        ...extra,
      },
    );
  const url = await listen(t, serve('server'));
  const good = await requestBytes(url, { tls: pki.material('client') });
  assert.equal(good.status, 200);
  assert.equal(good.headers['strict-transport-security'], 'max-age=31536000');
  const before = calls;
  await assert.rejects(
    requestBytes(url, {
      tls: {
        ca: foreign.material('client').ca,
        ...{ cert: pki.material('client').cert, key: pki.material('client').key },
      },
    }),
  );
  await assert.rejects(requestBytes(url, { tls: { ca: pki.material('client').ca } }));
  await assert.rejects(
    requestBytes(url, { tls: { ...foreign.material('client'), ca: pki.material('client').ca } }),
  );
  assert.equal((await requestBytes(url, { tls: pki.material('other') })).status, 403);
  assert.equal(calls, before);
  for (const n of ['expired', 'wrong']) {
    const invalid = await listen(t, serve(n));
    await assert.rejects(requestBytes(invalid, { tls: pki.material('client') }));
  }
  const expiredClient = await listen(
    t,
    serve('server', { clientFingerprints: [pki.pin('expired')] }),
  );
  await assert.rejects(requestBytes(expiredClient, { tls: pki.material('expired') }));
  const rotation = await listen(
    t,
    serve('next', { clientFingerprints: [pki.pin('client'), pki.pin('next')] }),
  );
  assert.equal((await requestBytes(rotation, { tls: pki.material('next') })).status, 200);
  const retired = await listen(t, serve('next', { clientFingerprints: [pki.pin('next')] }));
  assert.equal((await requestBytes(retired, { tls: pki.material('client') })).status, 403);
  const crl = pki.revoke('client');
  const revoked = await listen(t, serve('server', { crl }));
  await assert.rejects(requestBytes(revoked, { tls: pki.material('client') }));
  const revokedServer = await listen(t, serve('client'));
  await assert.rejects(requestBytes(revokedServer, { tls: { ...pki.material('client'), crl } }));
  assert.throws(
    () => requestBytes(url.replace('https:', 'http:'), { tls: pki.material('client') }),
    /downgrade/,
  );
});

test('secure configuration fails closed and development remains explicit', async (t) => {
  assert.equal(secureProfile({}), false);
  assert.throws(() => secureProfile({ SIEPMU_PROFILE: 'unknown' }));
  assert.throws(() => secureProfile({ SIEPMU_PROFILE: 'secure', SIEPMU_ALLOW_REMOTE_HTTP: '1' }));
  assert.throws(() => serverTLS('control', { SIEPMU_PROFILE: 'secure' }));
  assert.throws(() => serverTLS('web', { SIEPMU_PROFILE: 'secure' }));
  assert.equal(serverTLS('web', {}), undefined);
  assert.equal(clientTLS('web', {}), undefined);
  assert.throws(() => createTransportServer(() => {}, { cert: 'invalid' }));
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-tls-config-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const pki = generateLabPKI(join(dir, 'pki'));
  pki.issue('web');
  const env = {
    SIEPMU_PROFILE: 'secure',
    SIEPMU_TLS_CA: join(pki.dir, 'ca.crt'),
    SIEPMU_WEB_TLS_CERT: join(pki.dir, 'web.crt'),
    SIEPMU_WEB_TLS_KEY: join(pki.dir, 'web.key'),
    SIEPMU_WEB_CLIENT_TLS_CERT: join(pki.dir, 'web.crt'),
    SIEPMU_WEB_CLIENT_TLS_KEY: join(pki.dir, 'web.key'),
  };
  assert.ok(serverTLS('web', env));
  assert.ok(clientTLS('web', env));
  await chmod(join(pki.dir, 'web.key'), 0o644);
  assert.throws(() => serverTLS('web', env), /permissions/);
});

test('bounded transport rejects redirects, oversize, interrupted service and deadlines', async (t) => {
  const server = createTransportServer((q, r) => {
    if (q.url === '/redirect') {
      r.writeHead(302, { location: 'https://example.invalid' });
      r.end();
    } else if (q.url === '/big') r.end('x'.repeat(4096));
    else if (q.url === '/cut') {
      r.write('x');
      r.destroy();
    } else if (q.url === '/wait') {
    } else r.end('ok');
  });
  const https = await listen(t, server),
    url = https.replace('https:', 'http:');
  for (const path of ['/redirect', '/big', '/cut', '/wait'])
    await assert.rejects(requestBytes(url + path, { maxBytes: 32, timeoutMs: 80 }));
  assert.equal((await requestBytes(url)).body.toString(), 'ok');
  assert.throws(() => requestBytes('file:///etc/passwd'));
});
