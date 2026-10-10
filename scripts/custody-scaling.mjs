// Measures the cost of one recovery-guard authorisation (authority → independent custodian) as a
// function of evidence-chain length. Authority.dispatch performs two authorisations per request,
// serialised across all requests, and each ships and re-verifies the whole chain; this script
// quantifies that cost in-process (no TLS, no network), so it is a lower bound for the deployed
// path. Output: one JSON document on stdout.
//
// Two modes (ADR-014): 'full-chain' (protocol version 1, the D-T5-01 baseline) and
// 'incremental' (version 2, only records after the custodian anchor are shipped and verified).
// Besides wall time, each row reports how many records the custodian verified per
// authorisation, which is deterministic and independent of machine speed.
//
// Usage: node scripts/custody-scaling.mjs [--incremental] [lengths...]
//        (default 250 500 1000 2000 4000, full-chain)

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

/** Nearest-rank percentile of a non-empty sample (p in (0, 100]). */
export function nearestRank(values, p) {
  if (!values.length) throw new RangeError('empty sample');
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(1, Math.ceil((p / 100) * sorted.length)) - 1];
}

/**
 * Measures one recovery-guard authorisation per chain length.
 * @param {number[]} lengths evidence-chain lengths (records)
 * @param {{repeats?: number|((records: number) => number), warmup?: number,
 *   mode?: 'full-chain'|'incremental', appendPerAuthorisation?: number}} [options]
 *   repeats: timed authorisations per length (default REPEATS); warmup: untimed authorisations
 *   before timing (default 0, the historical behaviour); mode: custody protocol (default
 *   'full-chain'); appendPerAuthorisation: records appended (untimed) before each timed
 *   authorisation, modelling a request's own evidence (default 0, the historical behaviour).
 */
export async function measureCustodyScaling(lengths = DEFAULT_LENGTHS, options = {}) {
  const repeatsFor = (n) =>
    typeof options.repeats === 'function' ? options.repeats(n) : (options.repeats ?? REPEATS);
  const warmup = options.warmup ?? 0;
  const mode = options.mode ?? 'full-chain';
  if (!['full-chain', 'incremental'].includes(mode)) throw new RangeError('Unknown custody mode');
  const append = options.appendPerAuthorisation ?? 0;
  if (!Number.isSafeInteger(append) || append < 0) throw new RangeError('Invalid append count');
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
    // Records the custodian had to verify in the most recent authorisation (all requests).
    let verified = 0;
    const roundTrip = (value) => JSON.parse(JSON.stringify(value));
    const guard = createRecoveryGuard({
      custodianKey: custodyKey.publicKey,
      exchange: async (request) => {
        const p = request.payload;
        verified += (p.version === 1 ? p.evidence.records : p.records).length;
        return custodian.accept(roundTrip(request));
      },
      ...(mode === 'incremental'
        ? { anchorQuery: async (request) => custodian.anchor(roundTrip(request)) }
        : {}),
    });
    const rows = [];
    for (const target of [...lengths].sort((a, b) => a - b)) {
      const current = () => authority.get('SELECT count(*) n FROM evidence').n;
      authority.tx(() => {
        for (let i = current(); i < target; i++) authority.event('SCALING_BENCHMARK', null);
      });
      for (let w = 0; w < warmup; w++) await guard.authorize(authority);
      const startRecords = current();
      const samples = [];
      const verifiedCounts = [];
      for (let r = 0; r < repeatsFor(target); r++) {
        if (append)
          authority.tx(() => {
            for (let i = 0; i < append; i++) authority.event('SCALING_BENCHMARK', null);
          });
        verified = 0;
        const t0 = performance.now();
        await guard.authorize(authority);
        samples.push(performance.now() - t0);
        verifiedCounts.push(verified);
      }
      const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
      const round = (x) => Math.round(x * 10) / 10;
      rows.push({
        records: startRecords,
        mode,
        appendPerAuthorisation: append,
        recordsVerifiedPerAuthorisationMax: Math.max(...verifiedCounts),
        authorizeMsMedian: round(median(samples)),
        repeats: samples.length,
        authorizeMsMean: round(mean),
        authorizeMsP95: round(nearestRank(samples, 95)),
        authorizeMsMax: round(Math.max(...samples)),
        authorisationsPerSecond: Math.round((1000 / mean) * 100) / 100,
        samplesMs: samples.map(round),
      });
    }
    custodian.close();
    authority.close();
    const fit = linearFit(
      rows.map((r) => r.records),
      rows.map((r) => r.authorizeMsMedian),
    );
    return {
      schemaVersion: 2,
      mode,
      note: 'In-process lower bound; deployed path adds two mTLS round trips per authorisation',
      authorisationsPerRequest: 2,
      repeats: options.repeats === undefined ? REPEATS : 'per row',
      warmup,
      rows,
      fit: { msPerRecord: Math.round(fit.slope * 1e4) / 1e4, fixedMs: Math.round(fit.intercept) },
    };
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

if (process.argv[1] && process.argv[1].endsWith('custody-scaling.mjs')) {
  const args = process.argv.slice(2);
  const mode = args.includes('--incremental') ? 'incremental' : 'full-chain';
  const lengths = args.filter((a) => a !== '--incremental').map(Number);
  const result = await measureCustodyScaling(lengths.length ? lengths : DEFAULT_LENGTHS, { mode });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
