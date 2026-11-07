import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import {
  SecurityCollector,
  createCollectorServer,
  redactSecurityEvents,
} from '../services/monitoring/collector.mjs';
import { DETECTION_RULES, WINDOW_MS } from '../services/monitoring/detections.mjs';
import { packet, hash, verifyPacket } from '../services/control/primitives.mjs';
import { pair } from './helpers/client.mjs';
import { coreFixture } from './helpers/fixture.mjs';
import { generateLabPKI } from '../deployment/secure/lab-pki.mjs';
import { requestBytes } from '../packages/transport/tls.mjs';

const NOW = Math.floor(Date.now() / WINDOW_MS) * WINDOW_MS + 10000;
const signal = (type = 'AUTH_FAILURE', timestamp = NOW) => ({
  eventId: hash(randomUUID()),
  eventType: type,
  timestamp,
  epoch: 1,
  correlationId: hash(randomUUID()),
  reason: 'LOGIN_DENIED',
});
function fixture(t, options = {}) {
  const source = pair(),
    observer = pair();
  const collector = new SecurityCollector({
    database: ':memory:',
    sourceKey: source.publicKey,
    signingKey: observer.privateKey,
    ...options,
  });
  t.after(() => collector.close());
  return {
    collector,
    source,
    observer,
    ingest: (events, now = NOW + 1000) =>
      collector.ingest(packet(source.privateKey, { version: 1, events }), now),
  };
}

test('signed signal thresholds emit once; replayed records never inflate a count', (t) => {
  const f = fixture(t),
    events = Array.from({ length: 5 }, () => signal());
  f.ingest(events.slice(0, 4));
  assert.equal(f.collector.detections.list().length, 0);
  f.ingest([...events, ...events]);
  const [row] = f.collector.detections.list();
  assert.equal(verifyPacket(f.observer.publicKey, row.detection), true);
  assert.equal(row.detection.payload.ruleId, 'AUTH_FAILURE_SIGNALS');
  assert.equal(row.detection.payload.observedSignals, 5);
  assert.equal(row.detection.payload.triggerEventId, events[4].eventId);
  const original = JSON.stringify(row);
  f.ingest(events);
  f.ingest([signal()]);
  assert.equal(JSON.stringify(f.collector.detections.list()[0]), original);
  assert.equal(f.collector.db.prepare('SELECT count FROM threat_buckets').get().count, 6);
});

test('rules, fixed windows and out-of-order event times have explicit boundaries', (t) => {
  const f = fixture(t);
  assert.equal(DETECTION_RULES.length, 3);
  f.ingest([signal('ACCESS_DENIED', NOW), signal('ACCESS_DENIED', NOW - 1000)]);
  f.ingest([signal('RELEASE_DENIED')]);
  assert.equal(f.collector.detections.list().length, 0);
  f.ingest([signal('ACCESS_DENIED', NOW - 2000)]);
  const p = f.collector.detections.list()[0].detection.payload;
  assert.equal(p.firstEventAt, NOW - 2000);
  assert.equal(p.lastEventAt, NOW);
  assert.equal(p.windowEnd - p.windowStart, WINDOW_MS);
  f.ingest(
    [signal('ACCESS_DENIED', NOW + WINDOW_MS), signal('ACCESS_DENIED', NOW + WINDOW_MS)],
    NOW + WINDOW_MS + 1000,
  );
  assert.equal(f.collector.detections.list().length, 1, 'counts do not cross fixed windows');
  f.ingest([signal('RELEASE_DENIED'), signal('RELEASE_DENIED')]);
  assert.equal(f.collector.detections.list().length, 2);
});

test('untrusted, malformed, stale or future telemetry cannot generate detections', (t) => {
  const f = fixture(t),
    events = Array.from({ length: 5 }, () => signal());
  assert.throws(
    () => f.collector.ingest(packet(f.observer.privateKey, { version: 1, events }), NOW),
    /SIGNATURE/,
  );
  for (const bad of [
    { ...events[0], privateKey: 'SYNTHETIC_SECRET_CANARY' },
    { ...events[0], timestamp: NOW + 2001 },
    { ...events[0], timestamp: NOW - 8 * 86400000 },
  ])
    assert.throws(() => f.ingest([...events, bad]), /REDACTION_OR_TIME/);
  assert.equal(f.collector.list().length, 0);
  assert.equal(f.collector.detections.list().length, 0);
});

test('later conflict rolls back newly accepted signals, counters and detections together', (t) => {
  const f = fixture(t),
    old = signal('OTHER_EVENT');
  f.ingest([old]);
  assert.throws(
    () => f.ingest([...Array.from({ length: 5 }, () => signal()), { ...old, reason: 'CHANGED' }]),
    /CONFLICT/,
  );
  assert.equal(f.collector.list().length, 1);
  assert.equal(f.collector.detections.list().length, 0);
  assert.equal(f.collector.db.prepare('SELECT count(*) AS n FROM threat_buckets').get().n, 0);
});

test('collector event capacity rolls back detections and signals without silent loss', (t) => {
  const f = fixture(t, { maxEvents: 4 });
  assert.throws(() => f.ingest(Array.from({ length: 5 }, () => signal())), /COLLECTOR_CAPACITY/);
  assert.equal(f.collector.list().length, 0);
  assert.equal(f.collector.detections.list().length, 0);
  assert.equal(f.collector.db.prepare('SELECT count(*) AS n FROM threat_buckets').get().n, 0);
});

test('bounded detection storage preserves unacknowledged signals and recovers after disposition and retention', (t) => {
  const f = fixture(t, { maxDetections: 1, retentionMs: 60000 });
  f.ingest(Array.from({ length: 3 }, () => signal('ACCESS_DENIED')));
  const first = f.collector.detections.list()[0].detection;
  const later = NOW + 120000,
    events = Array.from({ length: 3 }, () => signal('ACCESS_DENIED', later));
  assert.throws(() => f.ingest(events, later + 1000), /DETECTION_CAPACITY/);
  assert.equal(f.collector.list().length, 3);
  assert.deepEqual(f.collector.detections.list()[0].detection, first);
  const ack = f.collector.detections.acknowledge(
    { detectionId: first.payload.detectionId, disposition: 'INVESTIGATING' },
    'synthetic-operator',
    later,
  );
  assert.equal(verifyPacket(f.observer.publicKey, ack), true);
  assert.throws(() => f.ingest(events, later + 1000), /DETECTION_CAPACITY/);
  f.collector.detections.acknowledge(
    { detectionId: first.payload.detectionId, disposition: 'RESOLVED' },
    'synthetic-operator',
    later,
  );
  f.ingest(events, later + 1000);
  assert.equal(f.collector.detections.list().length, 1);
  assert.notEqual(
    f.collector.detections.list()[0].detection.payload.detectionId,
    first.payload.detectionId,
  );
});

test('bucket limits and acknowledgement inputs fail closed', (t) => {
  const f = fixture(t, { maxDetectionBuckets: 1 });
  f.ingest([signal()]);
  assert.throws(() => f.ingest([signal('ACCESS_DENIED')]), /DETECTION_BUCKET_CAPACITY/);
  assert.equal(f.collector.list().length, 1);
  assert.throws(
    () =>
      f.collector.detections.acknowledge(
        { detectionId: 'a'.repeat(64), disposition: 'CLOSE' },
        'x',
      ),
    /SCHEMA/,
  );
  assert.throws(
    () =>
      f.collector.detections.acknowledge(
        { detectionId: 'a'.repeat(64), disposition: 'RESOLVED' },
        'x',
      ),
    /NOT_FOUND/,
  );
  for (const limit of [0, -1, 1.5, 100001])
    assert.throws(
      () =>
        new SecurityCollector({
          database: ':memory:',
          sourceKey: f.source.publicKey,
          signingKey: f.observer.privateKey,
          maxDetections: limit,
        }),
      /LIMIT_CONFIG/,
    );
});

test('restart preserves correlation, immutable detections and replay suppression', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-detections-')),
    source = pair(),
    observer = pair();
  const config = {
    database: join(dir, 'collector.sqlite'),
    sourceKey: source.publicKey,
    signingKey: observer.privateKey,
  };
  let collector = new SecurityCollector(config);
  t.after(() => {
    collector.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const events = Array.from({ length: 5 }, () => signal());
  const ingest = (es) =>
    collector.ingest(packet(source.privateKey, { version: 1, events: es }), NOW + 1000);
  ingest(events.slice(0, 4));
  collector.close();
  collector = new SecurityCollector(config);
  ingest(events);
  const before = collector.detections.list();
  collector.close();
  collector = new SecurityCollector(config);
  ingest(events);
  assert.deepEqual(collector.detections.list(), before);
  assert.equal(before.length, 1);
});

test('persisted detector state refuses source-key changes, rule-profile changes and missing configuration', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-detection-config-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const source = pair(),
    observer = pair();
  const config = {
    database: join(dir, 'collector.sqlite'),
    sourceKey: source.publicKey,
    signingKey: observer.privateKey,
  };
  const collector = new SecurityCollector(config);
  collector.ingest(
    packet(source.privateKey, { version: 1, events: Array.from({ length: 5 }, () => signal()) }),
    NOW + 1000,
  );
  const stored = collector.detections.list();
  collector.close();
  assert.throws(
    () => new SecurityCollector({ ...config, sourceKey: pair().publicKey }),
    /CONFIG_MISMATCH/,
  );
  const db = new DatabaseSync(config.database);
  t.after(() => db.close());
  const profile = db.prepare('SELECT profile_id FROM detection_configuration').get().profile_id;
  db.prepare('UPDATE detection_configuration SET profile_id=?').run('0'.repeat(64));
  assert.throws(() => new SecurityCollector(config), /CONFIG_MISMATCH/);
  db.prepare('UPDATE detection_configuration SET profile_id=?').run(profile);
  const restarted = new SecurityCollector(config);
  assert.deepEqual(restarted.detections.list(), stored);
  restarted.close();
  db.exec('DELETE FROM detection_configuration');
  assert.throws(() => new SecurityCollector(config), /CONFIG_MISSING/);
  db.exec('DELETE FROM threat_buckets');
  assert.throws(() => new SecurityCollector(config), /CONFIG_MISSING/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM events').get().n, 5);
  assert.equal(db.prepare('SELECT count(*) AS n FROM detections').get().n, 1);
});

test('real authority login failures produce authenticated, redacted threat signals', async (t) => {
  const f = await coreFixture(t),
    observer = pair();
  const collector = new SecurityCollector({
    database: ':memory:',
    sourceKey: f.provisioned.serverPublicKey,
    signingKey: observer.privateKey,
  });
  t.after(() => collector.close());
  const observedNow = Date.now() + 1000;
  t.mock.method(Date, 'now', () => observedNow);
  for (let n = 0; n < 3; n++)
    assert.throws(
      () =>
        f.authority.login(
          {
            username: f.profiles.alice.username,
            password: 'SYNTHETIC_WRONG_PASSWORD',
            otp: '000000',
          },
          'synthetic-source',
        ),
      /LOGIN_DENIED/,
    );
  const events = redactSecurityEvents(f.authority);
  collector.ingest(packet(f.authority.key, events), Date.now() + 1000);
  const rows = collector.detections.list();
  assert.ok(rows.some((r) => r.detection.payload.ruleId === 'AUTH_FAILURE_SIGNALS'));
  assert.equal(JSON.stringify(rows).includes(f.profiles.alice.userId), false);
  assert.equal(JSON.stringify(rows).includes('SYNTHETIC_WRONG_PASSWORD'), false);
  // One failed login currently has both an evidence record and an alert. Rules count signals,
  // never infer a number of distinct login attempts or a unique attacker from those records.
});

test('actual mTLS operator API reads and acknowledges signed detections with measured latency', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-detection-api-')),
    pki = generateLabPKI(dir);
  for (const name of ['collector', 'source', 'operator']) pki.issue(name);
  const f = fixture(t);
  const server = createCollectorServer({
    collector: f.collector,
    tls: {
      ...pki.material('collector'),
      requestCert: true,
      clientFingerprints: [pki.pin('source'), pki.pin('operator')],
    },
    sourcePin: pki.pin('source'),
    operatorPin: pki.pin('operator'),
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => {
    await new Promise((r) => server.close(r));
    rmSync(dir, { recursive: true, force: true });
  });
  const url = `https://127.0.0.1:${server.address().port}`;
  const call = (path, who, body) =>
    requestBytes(url + path, {
      tls: pki.material(who),
      method: body ? 'POST' : 'GET',
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
  const started = performance.now(),
    timestamp = Date.now();
  assert.equal(
    (
      await call(
        '/v1/events',
        'source',
        packet(f.source.privateKey, {
          version: 1,
          events: Array.from({ length: 5 }, () => signal('AUTH_FAILURE', timestamp)),
        }),
      )
    ).status,
    200,
  );
  const response = await call('/v1/detections', 'operator');
  assert.equal(response.status, 200);
  const rows = JSON.parse(response.body).detections;
  assert.equal(rows.length, 1);
  assert.equal(verifyPacket(f.observer.publicKey, rows[0].detection), true);
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 5000, 'declared synthetic loopback observation budget, not IAF SLA');
  t.diagnostic(
    JSON.stringify({
      kind: 'DETECTION_LOOPBACK_OBSERVATION',
      signals: 5,
      detectionMs: elapsed,
      thresholdMs: 5000,
      iafAcceptance: 'NOT_ESTABLISHED',
    }),
  );
  assert.equal((await call('/v1/detections', 'source')).status, 403);
  const body = { detectionId: rows[0].detection.payload.detectionId, disposition: 'RESOLVED' };
  assert.equal((await call('/v1/detections/ack', 'source', body)).status, 403);
  assert.equal(
    (await call('/v1/detections/ack', 'operator', { ...body, extra: true })).status,
    403,
  );
  const ack = await call('/v1/detections/ack', 'operator', body);
  assert.equal(ack.status, 200);
  assert.equal(verifyPacket(f.observer.publicKey, JSON.parse(ack.body)), true);
  assert.equal(JSON.parse(ack.body).payload.operator, pki.pin('operator'));
});
