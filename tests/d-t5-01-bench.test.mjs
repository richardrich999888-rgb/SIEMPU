import test from 'node:test';
import assert from 'node:assert/strict';
import { LENGTHS, repeatsFor, renderBaseline } from '../assurance/bench/d-t5-01.mjs';

test('baseline configuration matches the requested chain lengths', () => {
  assert.deepEqual([...LENGTHS], [1000, 10000, 100000]);
  assert.equal(repeatsFor(1000), 20);
  assert.equal(repeatsFor(100000), 10);
});

test('baseline report renders rows, the commit and the per-request ceiling', () => {
  const md = renderBaseline({
    result: {
      warmup: 1,
      fit: { msPerRecord: 0.1, fixedMs: 2 },
      rows: [
        {
          records: 1000,
          repeats: 2,
          authorizeMsMedian: 100,
          authorizeMsMean: 100,
          authorizeMsP95: 110,
          authorizeMsMax: 110,
          authorisationsPerSecond: 10,
        },
      ],
    },
    revision: { commit: 'a'.repeat(40), dirty: false },
    command: 'node assurance/bench/d-t5-01.mjs',
    startedAt: 's',
    finishedAt: 'f',
    runtime: { 'Node.js': 'test' },
    cpu: 'test',
  });
  assert.match(md, /\| 1,000 \| 2 \| 100 \| 100 \| 110 \| 110 \| 10 \| 5 \|/);
  assert.match(md, /clean working tree/);
  assert.match(md, /Production code is unchanged/);
});
