// Deterministic Product Development Budget model for the HPSC package.
//
// Pure computation over docs/hpsc/budget-inputs.json: line totals, category totals, the
// maximum admissible grant, the minimum matching contribution, the tranche schedule, and rule
// checks. All money is integer rupees; no floating-point currency is stored. Inputs are
// engineering estimates for founder review, not quotations (see the inputs file status field).
//
// Rules (research/hpsc/idex-grant-rules.md; official-domain excerpts, re-verify before use):
//   grant <= min(grantCeiling, maxGrantShareOfPdb * PDB)
//   matching contribution >= minMatchingShareOfPdb * PDB
//   IP counted in matching contribution <= min(ipMatchingCapShare * MC, ipMatchingCapAbsolute)
//   tranches are fixed shares of the sanctioned grant

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const BASES = new Set(['ESTIMATE', 'QUOTE_REQUIRED', 'QUOTED']);

/** @param {unknown} condition @param {string} message @returns {asserts condition} */
function require_(condition, message) {
  if (!condition) throw new TypeError(message);
}

const nonNegativeInteger = (v) => Number.isSafeInteger(v) && v >= 0;
const share = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1;

/** Validates the input document; throws on any malformed field (fail closed). */
export function validateInputs(inputs) {
  require_(inputs?.schemaVersion === 1, 'Unsupported budget schema');
  require_(
    Number.isSafeInteger(inputs.durationMonths) && inputs.durationMonths > 0,
    'durationMonths',
  );
  const r = inputs.idexRules;
  require_(nonNegativeInteger(r?.grantCeiling) && r.grantCeiling > 0, 'grantCeiling');
  for (const k of ['maxGrantShareOfPdb', 'minMatchingShareOfPdb', 'ipMatchingCapShare'])
    require_(share(r[k]), k);
  require_(nonNegativeInteger(r.ipMatchingCapAbsolute), 'ipMatchingCapAbsolute');
  require_(
    Array.isArray(r.trancheShares) &&
      r.trancheShares.length > 0 &&
      r.trancheShares.every(share) &&
      // Compare in integer basis points to avoid floating-point drift.
      r.trancheShares.reduce((a, b) => a + Math.round(b * 10000), 0) === 10000,
    'trancheShares must sum to 1',
  );
  require_(Array.isArray(inputs.lines) && inputs.lines.length > 0, 'lines');
  const ids = new Set();
  for (const line of inputs.lines) {
    require_(
      typeof line.id === 'string' && !ids.has(line.id),
      `duplicate or missing id ${line.id}`,
    );
    ids.add(line.id);
    require_(typeof line.category === 'string' && line.category.length > 0, `${line.id} category`);
    require_(
      nonNegativeInteger(line.quantity) && nonNegativeInteger(line.rate),
      `${line.id} amount`,
    );
    require_(BASES.has(line.basis), `${line.id} basis`);
  }
  const mc = inputs.matchingContribution;
  for (const k of ['cash', 'pastExpenditure', 'inKind', 'intellectualProperty'])
    require_(nonNegativeInteger(mc?.[k]), `matchingContribution.${k}`);
  return inputs;
}

/**
 * Computes the budget. PDB = sum of line totals. Grant = the largest admissible amount.
 * Integer arithmetic: shares are applied with Math.floor, which never exceeds a cap.
 */
export function computeBudget(inputs) {
  validateInputs(inputs);
  const r = inputs.idexRules;
  const lines = inputs.lines.map((l) => ({ ...l, total: l.quantity * l.rate }));
  const pdb = lines.reduce((a, l) => a + l.total, 0);
  const categories = {};
  for (const l of lines) categories[l.category] = (categories[l.category] ?? 0) + l.total;
  const maxGrant = Math.min(r.grantCeiling, Math.floor(pdb * r.maxGrantShareOfPdb));
  // MC must cover whatever the grant does not, and at least the minimum share.
  const minMatching = Math.max(pdb - maxGrant, Math.ceil(pdb * r.minMatchingShareOfPdb));
  const mc = inputs.matchingContribution;
  const declaredMatching = mc.cash + mc.pastExpenditure + mc.inKind + mc.intellectualProperty;
  const ipCap = Math.min(
    Math.floor(declaredMatching * r.ipMatchingCapShare),
    r.ipMatchingCapAbsolute,
  );
  const tranches = r.trancheShares.map((s, i) => ({
    milestone: `M${i}`,
    share: s,
    amount: Math.floor(maxGrant * s),
  }));
  const checks = {
    grantWithinCeiling: maxGrant <= r.grantCeiling,
    grantWithinPdbShare: maxGrant <= pdb * r.maxGrantShareOfPdb,
    declaredMatchingCoversMinimum: declaredMatching >= minMatching,
    ipWithinCap: mc.intellectualProperty <= ipCap,
  };
  const quoteRequired = lines
    .filter((l) => l.basis === 'QUOTE_REQUIRED')
    .reduce((a, l) => a + l.total, 0);
  return {
    pdb,
    categories,
    lines,
    maxGrant,
    minMatching,
    declaredMatching,
    ipCap,
    tranches,
    checks,
    quoteRequiredShare: pdb === 0 ? 0 : quoteRequired / pdb,
    pdbForFullCeiling: Math.ceil(r.grantCeiling / r.maxGrantShareOfPdb),
  };
}

/** Indian-format rupee rendering in lakh with two decimals (1 lakh = 100,000). */
export const lakh = (rupees) => `₹${(rupees / 100000).toFixed(2)} L`;

/** Markdown summary of a computed budget. */
export function budgetMarkdown(result) {
  return [
    `| Category | Amount |`,
    `| --- | ---: |`,
    ...Object.entries(result.categories).map(([k, v]) => `| ${k} | ${lakh(v)} |`),
    `| **Product Development Budget (PDB)** | **${lakh(result.pdb)}** |`,
    '',
    `Maximum admissible grant: **${lakh(result.maxGrant)}**; minimum matching contribution: **${lakh(result.minMatching)}**.`,
    `PDB needed to reach the full grant ceiling: ${lakh(result.pdbForFullCeiling)}. Quote-required share of PDB: ${Math.round(result.quoteRequiredShare * 100)} %.`,
    '',
    `| Tranche | Share | Amount |`,
    `| --- | ---: | ---: |`,
    ...result.tranches.map(
      (t) => `| ${t.milestone} | ${Math.round(t.share * 100)} % | ${lakh(t.amount)} |`,
    ),
    '',
    `Rule checks: ${Object.entries(result.checks)
      .map(([k, v]) => `${k}=${v ? 'PASS' : 'FAIL'}`)
      .join(', ')}.`,
  ].join('\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const path = process.argv[2] ?? 'docs/hpsc/budget-inputs.json';
  const result = computeBudget(JSON.parse(readFileSync(path, 'utf8')));
  console.log(budgetMarkdown(result));
}
