// Measured loopback measurements, not field, WAN, maximum capacity or SLA claims.
import { performance } from 'node:perf_hooks';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { cpus, totalmem } from 'node:os';
import { httpFixture } from '../tests/helpers/fixture.mjs';
import { createObject, decryptObject } from '../tests/helpers/client.mjs';
const count = Number(process.env.SIEPMU_BENCH_ITERATIONS || 30);
if (!Number.isSafeInteger(count) || count < 5 || count > 300)
  throw new Error('Benchmark iterations must be 5..300');
const f = await httpFixture(),
  samples = {
    loginAndDeviceBind: [],
    encrypt: [],
    submit: [],
    prepare: [],
    claim: [],
    decrypt: [],
  };
async function measure(name, operation) {
  const start = performance.now();
  const value = await operation();
  samples[name].push(performance.now() - start);
  return value;
}
try {
  await measure('loginAndDeviceBind', () => f.clients.alice.authenticate());
  await measure('loginAndDeviceBind', () => f.clients.bob.authenticate());
  const grant = await f.clients.alice.grant(),
    begin = performance.now(),
    cpuBefore = process.cpuUsage();
  for (let i = 0; i < count; i++) {
    const object = await measure('encrypt', () =>
      createObject(f.profiles.alice, f.profiles.bob, grant, {
        data: 'SYNTHETIC benchmark '.padEnd(4096, 'x'),
      }),
    );
    await measure('submit', () => f.clients.alice.submit(object));
    const prepared = await measure('prepare', () =>
      f.clients.alice.prepare(object.envelope.objectId),
    );
    if (prepared.status !== 200) throw new Error(JSON.stringify(prepared));
    const control = await f.clients.alice.ok('GET', '/api/control');
    const released = await measure('claim', () =>
      f.clients.bob.claim(object.envelope.objectId, control.payload.epoch),
    );
    if (released.status !== 200) throw new Error(JSON.stringify(released));
    await measure('decrypt', () => decryptObject(released.body, f.profiles.bob));
  }
  const elapsedMs = performance.now() - begin;
  const summary = (values) => {
    const s = [...values].sort((a, b) => a - b);
    return {
      samples: s.length,
      percentileMethod: 'nearest-rank',
      minMs: s[0],
      p50Ms: s[Math.ceil(s.length * 0.5) - 1],
      p95Ms: s[Math.ceil(s.length * 0.95) - 1],
      maxMs: s.at(-1),
    };
  };
  const report = {
    status: 'MEASURED',
    timestamp: new Date().toISOString(),
    environment: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      cpu: cpus()[0]?.model,
      logicalCpus: cpus().length,
      hostMemoryBytes: totalmem(),
    },
    workload: {
      mode: 'sequential loopback HTTP, three separate server processes, synthetic 4 KiB payloads',
      objects: count,
      concurrentSenders: 1,
      simultaneousSessions: 2,
    },
    measurements: Object.fromEntries(
      Object.entries(samples).map(([name, values]) => [name, summary(values)]),
    ),
    elapsedMs,
    achievedObjectsPerSecond: count / (elapsedMs / 1000),
    clientCpuMicroseconds: process.cpuUsage(cpuBefore),
    clientMemory: process.memoryUsage(),
    notMeasured: [
      'Server CPU/RAM separately',
      'WAN delay or loss',
      'Large fanout',
      'Maximum capacity',
      'High availability',
      'Hardware-backed cryptography',
      'Field or military network performance',
    ],
    limitations: [
      'Per-operation timings include proof challenge round trips where the helper requests them.',
      'Authentication samples=2; not a statistically robust authentication benchmark.',
      'CPU/RAM measurements belong to the benchmark client process, not aggregate services.',
    ],
  };
  const destination = resolve(process.env.SIEPMU_EVIDENCE_DIR || 'artifacts/benchmark');
  await mkdir(destination, { recursive: true });
  await writeFile(resolve(destination, 'results.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
} finally {
  await f.stop();
  await rm(f.dir, { recursive: true, force: true });
}
