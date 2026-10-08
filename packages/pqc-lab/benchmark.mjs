import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { cpus, platform, release, arch, totalmem } from 'node:os';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { CryptoEngine } from '../crypto-provider/engine.mjs';
import {
  createClassicalProvider,
  CLASSICAL_PROVIDER_ID,
  CLASSICAL_SUITE_ID,
} from '../crypto-provider/classical.mjs';
import {
  createNativePqcProvider,
  NATIVE_PQC_PROVIDER_ID,
  NATIVE_MLKEM768_SUITE,
  NATIVE_MLKEM1024_SUITE,
} from './native-provider.mjs';
import { createXwingLabProvider, XWING_PROVIDER_ID, XWING_SUITE } from './xwing-provider.mjs';

const repetitions = Number(process.env.PQC_BENCH_REPETITIONS ?? 30);
const payloadBytes = Number(process.env.PQC_BENCH_PAYLOAD_BYTES ?? 65536);
if (!Number.isSafeInteger(repetitions) || repetitions < 5 || repetitions > 1000)
  throw new Error('Use 5..1000 repetitions');
if (!Number.isSafeInteger(payloadBytes) || payloadBytes < 1 || payloadBytes > 1048576)
  throw new Error('Use 1..1048576 payload bytes');
const root = fileURLToPath(new URL('../../', import.meta.url));
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const files = [
  'packages/pqc-lab/native-provider.mjs',
  'packages/pqc-lab/xwing-provider.mjs',
  'packages/pqc-lab/benchmark.mjs',
  'packages/pqc-lab/package-lock.json',
  'packages/crypto-provider/engine.mjs',
  'packages/crypto-provider/classical.mjs',
  'packages/crypto-provider/primitives.mjs',
  'packages/crypto-provider/policy.mjs',
  'packages/crypto-provider/registry.mjs',
];
const sourceDigests = Object.fromEntries(
  files.map((file) => [
    file,
    createHash('sha256')
      .update(readFileSync(new URL(`../../${file}`, import.meta.url)))
      .digest('hex'),
  ]),
);
const bytes = (value) => Buffer.byteLength(JSON.stringify(value));
const profiles = [
  [createClassicalProvider, CLASSICAL_PROVIDER_ID, CLASSICAL_SUITE_ID],
  [createNativePqcProvider, NATIVE_PQC_PROVIDER_ID, NATIVE_MLKEM768_SUITE],
  [createNativePqcProvider, NATIVE_PQC_PROVIDER_ID, NATIVE_MLKEM1024_SUITE],
  [createXwingLabProvider, XWING_PROVIDER_ID, XWING_SUITE],
];
const results = [];

async function measure(operation, count = repetitions) {
  const cpuBefore = process.cpuUsage();
  const memoryBefore = process.memoryUsage();
  const samples = [];
  let peakRss = memoryBefore.rss;
  const started = performance.now();
  for (let index = 0; index < count; index++) {
    const start = performance.now();
    await operation(index);
    samples.push(performance.now() - start);
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
  }
  const wallMs = performance.now() - started;
  const cpu = process.cpuUsage(cpuBefore);
  samples.sort((a, b) => a - b);
  return {
    repetitions: count,
    wallMs,
    operationsPerSecond: (count * 1000) / wallMs,
    meanMs: samples.reduce((a, b) => a + b, 0) / count,
    medianMs: samples[Math.floor(count / 2)],
    p95Ms: samples[Math.ceil(count * 0.95) - 1],
    minMs: samples[0],
    maxMs: samples.at(-1),
    processCpuMicroseconds: cpu,
    memoryBefore,
    memoryAfter: process.memoryUsage(),
    peakObservedRssBytes: peakRss,
  };
}

for (const [factory, providerId, suiteId] of profiles) {
  const selection = { providerId, suiteId };
  const policy = {
    schemaVersion: 1,
    revision: 1,
    mode: 'laboratory',
    newSuites: [selection],
    legacySuites: [],
  };
  const provider = factory();
  const engine = new CryptoEngine({ providers: [provider], policy });
  const row = { providerId, suiteId, failures: [], metrics: {} };
  try {
    row.metrics.recipientKeyGeneration = await measure(() =>
      provider.generateKey({ suiteId, purpose: 'encapsulate' }),
    );
    const recipient = await engine.generateKey({ ...selection, purpose: 'encapsulate' });
    const signer = await engine.generateKey({ ...selection, purpose: 'sign' });
    const data = randomBytes(payloadBytes);
    let signature;
    row.metrics.sign = await measure(async () => {
      signature = await engine.sign({ keyId: signer.keyId, data });
    });
    row.metrics.verify = await measure(async () =>
      assert(await engine.verify({ key: signer, data, signature })),
    );
    row.metrics.encapsulateDecapsulate = await measure(async () => {
      const e = await engine.encapsulate({ key: recipient });
      assert.deepEqual(
        Buffer.from(
          await engine.decapsulate({ keyId: recipient.keyId, encapsulation: e.encapsulation }),
        ),
        Buffer.from(e.sharedSecret),
      );
      e.sharedSecret.fill(0);
    });
    let wrapped;
    row.metrics.encryptWrapUnwrapDecrypt = await measure(async (iteration) => {
      const key = randomBytes(32);
      const context = { objectId: `bench-${iteration}`, scope: 'synthetic', suiteId };
      const aad = Buffer.from(JSON.stringify(context));
      const encrypted = await engine.encrypt({ ...selection, key, plaintext: data, aad });
      wrapped = await engine.wrapKey({ key: recipient, contentKey: key, context });
      const recovered = await engine.unwrapKey({
        keyId: recipient.keyId,
        packet: wrapped,
        context,
      });
      assert.deepEqual(
        Buffer.from(await engine.decrypt({ ...selection, key: recovered, packet: encrypted, aad })),
        data,
      );
      recovered.fill(0);
      key.fill(0);
    });
    row.sizesBytes = {
      payload: payloadBytes,
      signature: signature.length,
      recipientPublicDescriptorJson: bytes(recipient),
      signingPublicDescriptorJson: bytes(signer),
      wrappedKeyPacketJson: bytes(wrapped),
      encapsulationJson: bytes(wrapped.encapsulation),
    };
  } catch (error) {
    row.failures.push({
      type: error.name,
      message: 'Benchmark operation failed; rerun test suite for diagnostic details',
    });
    process.exitCode = 1;
  }
  results.push(row);
}

const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  revision: git('rev-parse', 'HEAD'),
  treeDirty: Boolean(git('status', '--porcelain')),
  sourceDigests,
  host: {
    platform: platform(),
    release: release(),
    arch: arch(),
    cpuModel: cpus()[0]?.model ?? 'unknown',
    cpuCount: cpus().length,
    totalMemoryBytes: totalmem(),
  },
  runtime: {
    node: process.versions.node,
    openssl: process.versions.openssl,
    v8: process.versions.v8,
    noblePostQuantum: '0.7.1',
  },
  workload: {
    payloadBytes,
    repetitions,
    concurrency: 1,
    warmup: 'none; includes first-use cost',
    data: 'synthetic random bytes',
  },
  limitations: [
    'Single process on shared virtual hardware; no CPU affinity, GC isolation or statistical confidence interval.',
    'CPU and memory are process observations; peak RSS is sampled after each operation.',
    'Encapsulation/decapsulation and end-to-end measurements combine multiple operations.',
    'No network, hardware token, independent security audit, certification or field-readiness inference.',
    'Noble X-Wing is an unaudited JavaScript laboratory implementation; no constant-time claim.',
  ],
  results,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
