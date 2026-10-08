// Measures the cost of one recovery-guard authorisation (authority → independent custodian) as a
// function of evidence-chain length. Authority.dispatch performs two authorisations per request,
// serialised across all requests, and each ships and re-verifies the whole chain; this script
// quantifies that cost in-process (no TLS, no network), so it is a lower bound for the deployed
// path. Output: one JSON document on stdout.
//
// Usage: node scripts/custody-scaling.mjs [lengths...]   (default 250 500 1000 2000 4000)

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initDemo } from './bootstrap.mjs';
import { Authority } from '../services/control/core.mjs';
import { CheckpointCustodian, createRecoveryGuard } from '../services/evidence/custody.mjs';
import { generateKeyPairSync } from 'node:crypto';

/** Ephemeral P-256 JWK pair for the benchmark custodian (never persisted). */
function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    publicKey: publicKey.export({ format: 'jwk' }),
    privateKey: privateKey.export({ format: 'jwk' }),
  };
}

const DEFAULT_LENGTHS = [250, 500, 1000, 2000, 4000];
const REPEATS = 5;

/** Median of a non-empty numeric sample. */
export function median(values) {
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * Least-squares slope and intercept of y on x (ms per record, fixed ms).
 * @param {number[]} xs
 * @param {number[]} ys
 */
export function linearFit(xs, ys) {
  const n = xs.length;
  const mx = xs.reduce((a, b) => a + b, 0) / n;
  const my = ys.reduce((a, b) => a + b, 0) / n;
  let sxy = 0;
  let sxx = 0;
  for (let i = 0; i < n; i++) {
    sxy += (xs[i] - mx) * (ys[i] - my);
    sxx += (xs[i] - mx) ** 2;
  }
  const slope = sxx === 0 ? 0 : sxy / sxx;
  return { slope, intercept: my - slope * mx };
}

export async function measureCustodyScaling(lengths = DEFAULT_LENGTHS) {
  const temp = mkdtempSync(join(tmpdir(), 'siepmu-custody-scaling-'));
  try {
    await initDemo(temp);
    const key = JSON.parse(readFileSync(join(temp, 'server-key.json')));
    const masterKey = readFileSync(join(temp, 'master.key'));
    const authority = new Authority({
      dbPath: join(temp, 'control.sqlite'),
      signingKey: key,
      masterKey,
    });
    const custodyKey = keypair();
    const custodian = new CheckpointCustodian({
      database: join(temp, 'custody.sqlite'),
      authorityKey: JSON.parse(readFileSync(join(temp, 'public-key.json'))),
      signingKey: custodyKey.privateKey,
      allowBootstrap: true,
    });
    const guard = createRecoveryGuard({
      custodianKey: custodyKey.publicKey,
      exchange: async (request) => custodian.accept(JSON.parse(JSON.stringify(request))),
    });
    const rows = [];
    for (const target of [...lengths].sort((a, b) => a - b)) {
      const current = () => authority.get('SELECT count(*) n FROM evidence').n;
      authority.tx(() => {
        for (let i = current(); i < target; i++) authority.event('SCALING_BENCHMARK', null);
      });
      const samples = [];
      for (let r = 0; r < REPEATS; r++) {
        const t0 = performance.now();
        await guard.authorize(authority);
        samples.push(performance.now() - t0);
      }
      rows.push({ records: current(), authorizeMsMedian: Math.round(median(samples) * 10) / 10 });
    }
    custodian.close();
    authority.close();
    const fit = linearFit(
      rows.map((r) => r.records),
      rows.map((r) => r.authorizeMsMedian),
    );
    return {
      schemaVersion: 1,
      note: 'In-process lower bound; deployed path adds two mTLS round trips per authorisation',
      authorisationsPerRequest: 2,
      repeats: REPEATS,
      rows,
      fit: { msPerRecord: Math.round(fit.slope * 1e4) / 1e4, fixedMs: Math.round(fit.intercept) },
    };
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

if (process.argv[1] && process.argv[1].endsWith('custody-scaling.mjs')) {
  const lengths = process.argv.slice(2).map(Number);
  const result = await measureCustodyScaling(lengths.length ? lengths : DEFAULT_LENGTHS);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
