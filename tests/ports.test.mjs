import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import {
  DEFAULT_EPHEMERAL_RANGE,
  RESERVED_PORT_FLOOR,
  ephemeralRange,
  parseEphemeralRange,
  portCandidates,
  reservePort,
} from '../deployment/secure/ports.mjs';

test('ephemeral range parsing accepts the kernel format and rejects malformed input', () => {
  assert.deepEqual(parseEphemeralRange('32768\t60999\n'), { low: 32768, high: 60999 });
  assert.deepEqual(parseEphemeralRange(' 49152 65535 '), { low: 49152, high: 65535 });
  for (const bad of ['', '32768', 'a b', '60999 32768', '0 100', '1 70000'])
    assert.throws(() => parseEphemeralRange(bad));
});

test('candidates are deterministic, unique and strictly below the ephemeral range', () => {
  const ephemeral = DEFAULT_EPHEMERAL_RANGE;
  const a = portCandidates({ pid: 4242, ephemeral, count: 50 });
  assert.deepEqual(a, portCandidates({ pid: 4242, ephemeral, count: 50 }));
  assert.equal(new Set(a).size, a.length);
  for (const port of a) assert.ok(port >= RESERVED_PORT_FLOOR && port < ephemeral.low);
  assert.notDeepEqual(a[0], portCandidates({ pid: 4243, ephemeral, count: 1 })[0]);
});

test('candidate sequence wraps within the span and never exceeds it', () => {
  const ephemeral = { low: RESERVED_PORT_FLOOR + 1000, high: 60999 };
  const all = portCandidates({ pid: 1, ephemeral, count: 5000 });
  assert.equal(all.length, 1000);
  assert.equal(new Set(all).size, 1000);
});

test('a host whose ephemeral range leaves no reserved span fails closed', () => {
  assert.throws(
    () =>
      portCandidates({
        pid: 1,
        ephemeral: { low: RESERVED_PORT_FLOOR + 10, high: 60999 },
        count: 1,
      }),
    /no reserved laboratory port span/,
  );
});

test('reserved ports are outside the live ephemeral range, unique and bindable', async () => {
  const { low } = ephemeralRange();
  const ports = [];
  for (let i = 0; i < 8; i++) ports.push(await reservePort());
  assert.equal(new Set(ports).size, ports.length);
  for (const port of ports) {
    assert.ok(port < low, `${port} must be below ephemeral range ${low}`);
    const server = createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });
    await new Promise((resolve) => server.close(resolve));
  }
});

test('an occupied candidate is skipped rather than handed out', async () => {
  const first = await reservePort();
  // Occupy the next likely candidate region by holding the reserved port open; the allocator
  // must still return a different, bindable port.
  const holder = createServer();
  await new Promise((resolve) => holder.listen(first, '127.0.0.1', resolve));
  try {
    const next = await reservePort();
    assert.notEqual(next, first);
  } finally {
    await new Promise((resolve) => holder.close(resolve));
  }
});
