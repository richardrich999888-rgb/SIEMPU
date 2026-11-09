import { readFileSync } from 'node:fs';
import { applyLegacyMigration } from '../../scripts/legacy-migration.mjs';
const [requestPath, approvalPath, signingPath, stopPhase] = process.argv.slice(2);
const read = (p) => JSON.parse(readFileSync(p));
await applyLegacyMigration(read(requestPath), {
  approval: read(approvalPath),
  signingKey: read(signingPath),
  onPhase: async (phase) => {
    if (phase === stopPhase) {
      process.send({ phase });
      await new Promise((resolve) => process.once('message', resolve));
    }
  },
});
