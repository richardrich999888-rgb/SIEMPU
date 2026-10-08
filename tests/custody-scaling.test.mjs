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
