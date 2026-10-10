import test from 'node:test';
import assert from 'node:assert/strict';
import { median, linearFit, measureCustodyScaling } from '../scripts/custody-scaling.mjs';

test('median: odd and even samples', () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(median([7]), 7);
});

test('linearFit: exact line, constant series and degenerate x', () => {
  assert.deepEqual(linearFit([1, 2, 3], [5, 7, 9]), { slope: 2, intercept: 3 });
  assert.deepEqual(linearFit([1, 2, 3], [4, 4, 4]), { slope: 0, intercept: 4 });
  assert.deepEqual(linearFit([2, 2], [1, 3]), { slope: 0, intercept: 2 });
});

test('custody scaling measurement: authorisation succeeds at each length and reports a fit', async () => {
  const result = await measureCustodyScaling([20, 60]);
  assert.equal(result.authorisationsPerRequest, 2);
  assert.deepEqual(
    result.rows.map((r) => r.records),
    [20, 60],
  );
  assert.ok(result.rows.every((r) => r.authorizeMsMedian > 0));
  assert.equal(typeof result.fit.msPerRecord, 'number');
});

test('nearestRank: p95 of small and large samples; empty sample rejected', async () => {
  const { nearestRank } = await import('../scripts/custody-scaling.mjs');
  assert.equal(nearestRank([5, 1, 3], 95), 5);
  assert.equal(
    nearestRank(
      Array.from({ length: 100 }, (_, i) => i + 1),
      95,
    ),
    95,
  );
  assert.equal(nearestRank([7], 50), 7);
  assert.throws(() => nearestRank([], 95), RangeError);
});

test('measurement options: per-length repeats, warmup, and per-row statistics', async () => {
  const result = await measureCustodyScaling([20], { repeats: () => 3, warmup: 1 });
  const [row] = result.rows;
  assert.equal(row.repeats, 3);
  assert.equal(row.samplesMs.length, 3);
  assert.ok(row.authorizeMsP95 >= row.authorizeMsMedian);
  assert.ok(row.authorisationsPerSecond > 0);
  assert.equal(result.warmup, 1);
});

test('incremental mode: custodian verifies only appended records after catch-up', async () => {
  const result = await measureCustodyScaling([20, 60], {
    mode: 'incremental',
    repeats: 3,
    warmup: 1,
    appendPerAuthorisation: 2,
  });
  assert.equal(result.mode, 'incremental');
  // Exact, timing-independent: each timed authorisation verifies the 2 appended records only.
  assert.deepEqual(
    result.rows.map((r) => r.recordsVerifiedPerAuthorisationMax),
    [2, 2],
  );
  assert.deepEqual(
    result.rows.map((r) => r.records),
    [20, 60],
  );
});

test('full-chain mode verifies the whole chain per authorisation; options are validated', async () => {
  const result = await measureCustodyScaling([30], { repeats: 2 });
  assert.equal(result.mode, 'full-chain');
  assert.equal(result.rows[0].recordsVerifiedPerAuthorisationMax, 30);
  await assert.rejects(measureCustodyScaling([10], { mode: 'other' }), RangeError);
  await assert.rejects(measureCustodyScaling([10], { appendPerAuthorisation: -1 }), RangeError);
});
