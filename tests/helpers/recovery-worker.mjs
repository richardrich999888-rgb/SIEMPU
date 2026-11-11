// Private synthetic fixture configuration; process-crash test helper only.
import { getJson, runRecoveryFixture } from './recovery-rehearsal.mjs';
const [path, phase] = process.argv.slice(2);
try {
  await runRecoveryFixture(getJson(path), {
    onPhase: async (p) => {
      if (p === phase) {
        process.send?.({ phase: p });
        await new Promise(() => {
          setInterval(() => {}, 1000);
        });
      }
    },
  });
  process.send?.({ outcome: 'COMPLETE' });
} catch (error) {
  process.send?.({ outcome: 'REFUSED', error: error.message });
  process.exitCode = 1;
} finally {
  process.disconnect?.();
}
