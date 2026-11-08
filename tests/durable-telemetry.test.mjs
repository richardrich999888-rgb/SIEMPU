import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { coreFixture } from './helpers/fixture.mjs';
import { pair } from './helpers/client.mjs';
import { packet, hash, canonical } from '../services/control/primitives.mjs';
import { generateLabPKI } from '../deployment/secure/lab-pki.mjs';
import { createTransportServer } from '../packages/transport/tls.mjs';
import { SecurityCollector } from '../services/monitoring/collector.mjs';
import { DurableTelemetryExporter } from '../services/monitoring/durable-exporter.mjs';

async function fixture(t) {
  const f = await coreFixture(t),
    keys = pair();
  const collector = new SecurityCollector({
    database: ':memory:',
    sourceKey: f.provisioned.serverPublicKey,
    signingKey: keys.privateKey,
  });
  const material = generateLabPKI(join(f.dir, 'tls')).issue('web');
  const state = { mode: 'ok', batches: [] };
  const server = createTransportServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const batch = JSON.parse(Buffer.concat(chunks));
    state.batches.push(batch);
    try {
      let receipt = collector.ingest(batch);
      if (state.mode === 'lost') {
        req.socket.destroy();
        return;
      }
      if (state.mode === 'forged')
        receipt = packet(keys.privateKey, { ...receipt.payload, batchDigest: '0'.repeat(64) });
      res.end(JSON.stringify(receipt));
    } catch {
      res.writeHead(409);
      res.end('{}');
    }
  }, material);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => {
    await new Promise((r) => server.close(r));
    collector.close();
  });
  const config = {
    database: join(f.dir, 'export.sqlite'),
    url: `https://127.0.0.1:${server.address().port}/v1/events`,
    tls: { ca: material.ca },
    collectorKey: keys.publicKey,
    authority: f.authority,
    batchSize: 200,
  };
  return { ...f, keys, collector, state, config };
}

test('durable telemetry drains beyond recent-event window and replays identical pending batch after lost ACK/restart', async (t) => {
  const f = await fixture(t);
  f.authority.tx(() => {
    for (let i = 0; i < 1205; i++)
      f.authority.event('SYNTHETIC_CONTINUITY', null, {
        details: { excluded: 'SYNTHETIC_SECRET' },
      });
    for (let i = 0; i < 12; i++) f.authority.alert('AUTH_FAILURE', null, 'LOGIN_DENIED');
  });
  let exporter = new DurableTelemetryExporter(f.config);
  f.state.mode = 'lost';
  assert.equal(await exporter.deliver(), null);
  await exporter.close();
  exporter = new DurableTelemetryExporter(f.config);
  t.after(() => exporter.close());
  f.state.mode = 'ok';
  await exporter.deliver();
  assert.equal(hash(canonical(f.state.batches[0])), hash(canonical(f.state.batches[1])));
  for (let i = 0; i < 20 && exporter.state !== 'CAUGHT_UP'; i++)
    assert.ok(await exporter.deliver());
  assert.equal(exporter.state, 'CAUGHT_UP');
  const expected =
    f.authority.get('SELECT count(*) n FROM evidence').n +
    f.authority.get('SELECT count(*) n FROM alerts').n;
  assert.equal(f.collector.db.prepare('SELECT count(*) n FROM events').get().n, expected);
  assert.equal(JSON.stringify(f.state.batches).includes('SYNTHETIC_SECRET'), false);
});

test('wrong ACK cannot advance cursor; source rollback and changed binding refuse further delivery', async (t) => {
  const f = await fixture(t),
    exporter = new DurableTelemetryExporter(f.config);
  f.state.mode = 'forged';
  assert.equal(await exporter.deliver(), null);
  f.state.mode = 'ok';
  assert.ok(await exporter.deliver());
  assert.deepEqual(f.state.batches[0], f.state.batches[1]);
  assert.throws(
    () => new DurableTelemetryExporter({ ...f.config, collectorKey: pair().publicKey }),
    /CURSOR/,
  );
  f.authority.run('DELETE FROM evidence WHERE sequence=(SELECT max(sequence) FROM evidence)');
  const before = f.state.batches.length;
  assert.equal(await exporter.deliver(), null);
  assert.equal(f.state.batches.length, before);
  await exporter.close();
  const db = new DatabaseSync(f.config.database);
  db.prepare('UPDATE telemetry_cursor SET signed=?').run('{}');
  db.close();
  assert.throws(() => new DurableTelemetryExporter(f.config), /CURSOR/);
});

test('retention rejection retains pending batch; concurrent delivery uses one request', async (t) => {
  const f = await fixture(t),
    exporter = new DurableTelemetryExporter(f.config);
  t.after(() => exporter.close());
  const results = await Promise.all([exporter.deliver(), exporter.deliver()]);
  assert.deepEqual(results[0], results[1]);
  assert.equal(f.state.batches.length, 1);
  f.authority.tx(() =>
    f.authority.event('OLD_SYNTHETIC_EVENT', null, { timestamp: Date.now() - 8 * 86400000 }),
  );
  assert.equal(await exporter.deliver(), null);
  const batch = f.state.batches.at(-1);
  assert.equal(await exporter.deliver(), null);
  assert.deepEqual(f.state.batches.at(-1), batch);
  assert.equal(exporter.state, 'DEGRADED');
});
