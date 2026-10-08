import test from 'node:test';
import assert from 'node:assert/strict';
import { coreFixture } from './helpers/fixture.mjs';
import { pair } from './helpers/client.mjs';
import { SecurityCollector, redactSecurityEvents } from '../services/monitoring/collector.mjs';
import { packet, verifyPacket } from '../services/control/primitives.mjs';

test('independent collector authenticates, redacts, deduplicates, acknowledges and bounds retention', async (t) => {
  const f = await coreFixture(t),
    keys = pair(),
    now = Date.now();
  const collector = new SecurityCollector({
    database: ':memory:',
    sourceKey: f.provisioned.serverPublicKey,
    signingKey: keys.privateKey,
    retentionMs: 60000,
    maxEvents: 100,
  });
  t.after(() => collector.close());
  f.authority.tx(() =>
    f.authority.alert('REQUEST_DENIED', f.profiles.alice.userId, 'CREDENTIAL_REJECTED'),
  );
  const redacted = redactSecurityEvents(f.authority),
    signed = packet(f.authority.key, redacted);
  assert.equal(JSON.stringify(redacted).includes(f.profiles.alice.userId), false);
  const result = collector.ingest(signed, now + 1000);
  assert.equal(verifyPacket(keys.publicKey, result), true);
  assert.ok(result.payload.accepted > 0);
  assert.equal(collector.ingest(signed, now + 1000).payload.accepted, 0);
  for (const field of ['plaintext', 'password', 'privateKey', 'authorization']) {
    const bad = structuredClone(redacted);
    bad.events[0][field] = 'SYNTHETIC_SECRET_CANARY';
    assert.throws(() => collector.ingest(packet(f.authority.key, bad), now + 1000), /REDACTION/);
  }
  assert.throws(() => collector.ingest(packet(keys.privateKey, redacted)), /SIGNATURE/);
  const changed = structuredClone(redacted);
  changed.events[0].reason = 'CHANGED';
  assert.throws(() => collector.ingest(packet(f.authority.key, changed), now + 1000), /CONFLICT/);
  for (const row of collector.list())
    assert.equal(
      verifyPacket(
        keys.publicKey,
        collector.acknowledge(
          { eventId: row.event.eventId, disposition: 'RESOLVED' },
          'synthetic-operator',
        ),
      ),
      true,
    );
  collector.ingest(packet(f.authority.key, { version: 1, events: [] }), now + 62000);
  assert.equal(collector.list().length, 0);
  assert.throws(() => collector.ingest(signed, now + 62000), /TIME/);
  assert.throws(
    () => collector.acknowledge({ eventId: 'a'.repeat(64), disposition: 'SECRET_FREE_TEXT' }, 'x'),
    /SCHEMA/,
  );
  const tiny = new SecurityCollector({
    database: ':memory:',
    sourceKey: f.provisioned.serverPublicKey,
    signingKey: keys.privateKey,
    maxEvents: 1,
  });
  t.after(() => tiny.close());
  assert.throws(() => tiny.ingest(signed, now + 1000), /CAPACITY/);
  assert.equal(tiny.list().length, 0);
});
