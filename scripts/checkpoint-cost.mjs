// Run this same harness from each clean revision's working directory, sequentially.
// Synthetic comparison only; no government interface or deployment capacity claim.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { snapshot } from '../assurance/sag/package.mjs';
import { sha256, fingerprint, insist } from '../assurance/sag/format.mjs';

const root = process.cwd();
const destination = resolve(process.argv[2]);
const before = snapshot(root);
const { Authority } = await import(pathToFileURL(resolve(root, 'services/control/core.mjs')));
const { comparePolicyRelease } = await import(
  pathToFileURL(resolve(root, 'scripts/policy-release-comparison.mjs'))
);
const original = Authority.prototype.checkpoint;
let calls = 0;
Authority.prototype.checkpoint = function (...args) {
  calls++;
  return original.apply(this, args);
};
try {
  const result = await comparePolicyRelease({ iterations: 20, custody: 'fenced' });
  const after = snapshot(root);
  insist(
    before.commit === after.commit &&
      before.tree === after.tree &&
      fingerprint(before.index) === fingerprint(after.index),
    'SOURCE_CHANGED',
  );
  writeFileSync(
    destination,
    JSON.stringify(
      {
        kind: 'SIEPMU_CHECKPOINT_COST_LAB',
        commit: before.commit,
        tree: before.tree,
        sourceFingerprint: fingerprint(before.index),
        harnessSha256: sha256(readFileSync(fileURLToPath(import.meta.url))),
        checkpointCallsIncludingSetupAndControls: calls,
        limitations: [
          'Single process, shared administrator, synthetic in-memory relay and SQLite storage.',
          'Counter includes setup and negative controls; timed throughput covers the 20-object loop only.',
          'No maximum capacity, sustained-load, independent custody, qualification or superiority claim.',
          'Use the same harness and runtime; alternate baseline and candidate order in fresh processes.',
        ],
        report: result.report,
      },
      null,
      2,
    ) + '\n',
    { flag: 'wx', mode: 0o600 },
  );
} finally {
  Authority.prototype.checkpoint = original;
}
