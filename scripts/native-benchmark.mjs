#!/usr/bin/env node
/**
 * Measures wall time and peak resident memory of the Node and Rust evidence verifiers on
 * synthetic evidence chains of increasing length. Writes artifacts/native/benchmark.json.
 *
 * Method: each chain is signed once (P-256, same packet format as the authority); each
 * verifier then runs RUNS times as a fresh process. Peak RSS is read exactly with
 * getrusage(RUSAGE_CHILDREN) in a one-line python3 harness, because Node exposes no child
 * resource usage. Reported figures are medians. Results describe this host only.
 *
 * Usage: node scripts/native-benchmark.mjs [--sizes 1000,10000,50000] [--runs 5]
 */
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { cpus, platform, release, tmpdir } from 'node:os';
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../packages/protocol/canonical.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const option = (name, fallback) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const sizes = option('--sizes', '1000,10000,50000').split(',').map(Number);
const runs = Number(option('--runs', '5'));
if (!sizes.every((n) => Number.isSafeInteger(n) && n > 0 && n <= 100000) || !(runs > 0))
  throw new Error('Invalid --sizes or --runs');
const rustBinary = join(root, 'native/target/release/siepmu-evidence-verify');
if (!existsSync(rustBinary)) throw new Error('Build the Rust verifier first: npm run build:native');

const HARNESS = `import json,resource,subprocess,sys,time
t=time.perf_counter();p=subprocess.run(sys.argv[1:],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
w=(time.perf_counter()-t)*1000;r=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(json.dumps({"status":p.returncode,"wallMs":w,"maxRssKiB":r,"stderr":p.stderr.decode()[:300]}))`;

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
function writeChain(dir, count) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const keyId = sha256(canonical(jwk));
  const packet = (payload) => ({
    payload,
    signature: sign('sha256', Buffer.from(canonical(payload)), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url'),
    keyId,
  });
  const records = [];
  let previousHash = '0'.repeat(64);
  for (let sequence = 1; sequence <= count; sequence++) {
    const record = packet({
      sequence,
      previousHash,
      eventId: `bench-${sequence}`,
      eventType: 'RELEASE_ISSUED',
      timestamp: 1700000000000 + sequence,
      epoch: 3,
      actorId: 'synthetic',
      details: { objectDigest: sha256(String(sequence)), authorityEpoch: 3, mission: 'BENCH' },
    });
    records.push(record);
    previousHash = sha256(canonical(record));
  }
  const checkpoint = packet({ sequence: count, headHash: previousHash, issuedAt: 1700000099999 });
  const input = join(dir, `chain-${count}.json`);
  writeFileSync(input, JSON.stringify({ records, checkpoint }));
  writeFileSync(join(dir, 'key.json'), JSON.stringify(jwk));
  return input;
}
const median = (values) => {
  const s = [...values].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};
function measure(command, cwd) {
  const samples = [];
  for (let i = 0; i < runs; i++) {
    const out = spawnSync('python3', ['-I', '-c', HARNESS, ...command], { cwd, encoding: 'utf8' });
    if (out.status !== 0) throw new Error(`harness failed: ${out.stderr}`);
    const sample = JSON.parse(out.stdout);
    if (sample.status !== 0) throw new Error(`verifier rejected benchmark chain: ${sample.stderr}`);
    samples.push(sample);
  }
  return {
    wallMsMedian: Number(median(samples.map((s) => s.wallMs)).toFixed(1)),
    maxRssMiBMedian: Number((median(samples.map((s) => s.maxRssKiB)) / 1024).toFixed(1)),
  };
}

const dir = mkdtempSync(join(tmpdir(), 'siepmu-native-bench-'));
try {
  const results = [];
  for (const size of sizes) {
    const input = writeChain(dir, size);
    const node = measure(
      [process.execPath, join(root, 'apps/verifier/verify.mjs'), input, 'key.json'],
      dir,
    );
    const rust = measure([rustBinary, input, 'key.json'], dir);
    results.push({
      records: size,
      inputMiB: Number((statSync(input).size / 1048576).toFixed(2)),
      node,
      rust,
      speedup: Number((node.wallMsMedian / rust.wallMsMedian).toFixed(2)),
    });
    console.log(JSON.stringify(results.at(-1)));
  }
  const report = {
    generatedAt: new Date().toISOString(),
    host: { platform: platform(), release: release(), cpu: cpus()[0]?.model, cpus: cpus().length },
    node: process.version,
    rustBinaryBytes: statSync(rustBinary).size,
    runs,
    method:
      'Fresh process per run; median wall time and median peak RSS (getrusage RUSAGE_CHILDREN). Synthetic data; host-specific.',
    results,
  };
  mkdirSync(join(root, 'artifacts/native'), { recursive: true });
  writeFileSync(
    join(root, 'artifacts/native/benchmark.json'),
    JSON.stringify(report, null, 2) + '\n',
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
