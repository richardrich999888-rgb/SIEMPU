// Budget model: rule arithmetic, boundaries and fail-closed input validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { computeBudget, validateInputs, budgetMarkdown, lakh } from '../scripts/hpsc-budget.mjs';

const committed = () => JSON.parse(readFileSync('docs/hpsc/budget-inputs.json', 'utf8'));
const rules = () => committed().idexRules;
const withLines = (lines, mc = {}) => ({
  ...committed(),
  lines,
  matchingContribution: { cash: 0, pastExpenditure: 0, inKind: 0, intellectualProperty: 0, ...mc },
});
const line = (id, rate, quantity = 1, basis = 'ESTIMATE') => ({
  id,
  category: 'C',
  item: id,
  unit: 'u',
  quantity,
  rate,
  basis,
});

test('committed inputs compute and satisfy the grant-side rules', () => {
  const r = computeBudget(committed());
  assert.equal(
    r.pdb,
    r.lines.reduce((a, l) => a + l.total, 0),
  );
  assert.ok(r.maxGrant <= rules().grantCeiling);
  assert.ok(r.maxGrant <= r.pdb / 2);
  assert.equal(r.maxGrant + r.minMatching >= r.pdb, true);
  assert.equal(r.tranches.length, 6);
  assert.ok(r.tranches.reduce((a, t) => a + t.amount, 0) <= r.maxGrant);
  // Matching contribution is a founder input; zeros must be reported, not hidden.
  assert.equal(r.checks.declaredMatchingCoversMinimum, false);
  assert.match(budgetMarkdown(r), /Product Development Budget/);
});

test('grant is half the PDB below the ceiling and capped above it', () => {
  const small = computeBudget(withLines([line('A', 10000000)]));
  assert.equal(small.maxGrant, 5000000);
  assert.equal(small.minMatching, 5000000);
  const exact = computeBudget(withLines([line('A', 30000000)]));
  assert.equal(exact.maxGrant, 15000000);
  const large = computeBudget(withLines([line('A', 50000000)]));
  assert.equal(large.maxGrant, 15000000);
  assert.equal(large.minMatching, 35000000);
  assert.equal(large.pdbForFullCeiling, 30000000);
});

test('odd PDB rounds the grant down and the matching contribution up', () => {
  const r = computeBudget(withLines([line('A', 1000001)]));
  assert.equal(r.maxGrant, 500000);
  assert.equal(r.minMatching, 500001);
});

test('intellectual property in the matching contribution is capped', () => {
  const r = computeBudget(
    withLines([line('A', 10000000)], { cash: 4000000, intellectualProperty: 1000000 }),
  );
  assert.equal(r.declaredMatching, 5000000);
  assert.equal(r.ipCap, 1000000);
  assert.equal(r.checks.ipWithinCap, true);
  const over = computeBudget(
    withLines([line('A', 10000000)], { cash: 3000000, intellectualProperty: 2000000 }),
  );
  assert.equal(over.checks.ipWithinCap, false);
  const absolute = computeBudget(
    withLines([line('A', 100000000)], { cash: 47000000, intellectualProperty: 3000000 }),
  );
  assert.equal(absolute.ipCap, 2500000);
  assert.equal(absolute.checks.ipWithinCap, false);
});

test('malformed inputs fail closed', () => {
  const bad = [
    { ...committed(), schemaVersion: 2 },
    withLines([]),
    withLines([line('A', -1)]),
    withLines([line('A', 1.5)]),
    withLines([line('A', 1), line('A', 2)]),
    withLines([line('A', 1, 1, 'GUESS')]),
    withLines([line('A', 1)], { cash: -5 }),
    { ...committed(), idexRules: { ...rules(), trancheShares: [0.5, 0.4] } },
    { ...committed(), idexRules: { ...rules(), maxGrantShareOfPdb: 1.5 } },
    { ...committed(), durationMonths: 0 },
  ];
  for (const input of bad) assert.throws(() => validateInputs(input), TypeError);
});

test('rupee rendering in lakh', () => {
  assert.equal(lakh(15000000), '₹150.00 L');
  assert.equal(lakh(250000), '₹2.50 L');
});
