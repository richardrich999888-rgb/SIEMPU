import test from 'node:test';
import assert from 'node:assert/strict';
import { comparePolicyRelease } from './policy-release-comparison.mjs';

test('negative-control comparison observes fresh-policy denial without claiming retroactive revocation', async () => {
  const { report } = await comparePolicyRelease({ iterations: 3 });
  assert.deepEqual(report.policyExperiment, {
    pendingObjects: 1,
    staleEpochStatus: 409,
    currentPolicyStatus: 409,
    currentPolicyReason: 'POLICY_DENIED',
    newIssuancesAfterRevocation: 0,
    predeliveredReferenceDecrypts: true,
    previouslyReleasedCandidateStillDecrypts: true,
  });
  assert.ok(report.audit.tamperedExportRejected);
  assert.equal(report.measurements.policyRelease.count, 3);
  assert.ok(report.audit.records > 0);
  assert.ok(report.sequentialObjectsPerSecond > 0);
});
