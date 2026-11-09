// Independent SQLite connection and process for the compare-and-swap contention test.
import { readFileSync } from 'node:fs';
import { CheckpointCustodian } from '../../services/evidence/custody.mjs';
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const custody = new CheckpointCustodian(config.custody);
process.once('message', () => {
  try {
    const receipt = custody.transferWriter(config.request);
    process.send({ outcome: 'ACCEPTED', generation: receipt.payload.generation });
  } catch (error) {
    process.send({ outcome: 'REJECTED', code: error.message });
  } finally {
    custody.close();
    process.disconnect();
  }
});
process.send({ ready: true });
