// Explicit external-engine acceptance gate. Not part of npm test; never silently skipped.
// SIEPMU_CLAMAV_CONFIG must name an operator-provisioned JSON constructor configuration.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { ClamAvInspector } from '../../packages/file-inspection/clamav.mjs';

if (!process.env.SIEPMU_CLAMAV_CONFIG)
  throw new Error('SIEPMU_CLAMAV_CONFIG is required; real-engine acceptance was not executed');
const settings = JSON.parse(readFileSync(process.env.SIEPMU_CLAMAV_CONFIG, 'utf8'));
const inspector = new ClamAvInspector(settings);

test('actual configured engine accepts synthetic benign content', async () => {
  const result = await inspector.inspect(Buffer.from('SYNTHETIC_UNCLASSIFIED_BENIGN_FILE'));
  assert.equal(result.status, 'NO_THREAT_DETECTED');
});

test('actual configured engine rejects the standard EICAR test string', async () => {
  // Harmless antivirus test pattern, not live malware. Constructed only in test memory.
  const eicar = Buffer.from(
    'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-' + 'STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
  );
  await assert.rejects(inspector.inspect(eicar), { code: 'FILE_INSPECTION_DETECTED' });
});

test('actual configured engine refuses a compressed member exceeding the inspection limit', async () => {
  const compressed = gzipSync(Buffer.alloc(2 * 1024 * 1024, 65));
  await assert.rejects(inspector.inspect(compressed), { code: 'FILE_INSPECTION_DETECTED' });
});
