// Independent OS process / SQLite connection used to measure lock ordering.
import { DatabaseSync } from 'node:sqlite';
const [dbPath, fromUnit, toUnit, missionId, delayString = '0'] = process.argv.slice(2);
const db = new DatabaseSync(dbPath);
db.exec('PRAGMA busy_timeout=10000; PRAGMA foreign_keys=ON;');
process.send?.({ event: 'ready' });
process.once('message', async (message) => {
  if (message?.go !== true) process.exit(2);
  const began = Date.now();
  db.exec('BEGIN IMMEDIATE');
  const acquired = Date.now();
  db.prepare('UPDATE policies SET allow=0 WHERE from_unit=? AND to_unit=? AND mission_id=?').run(
    fromUnit,
    toUnit,
    missionId,
  );
  db.prepare(
    'UPDATE authority SET epoch=epoch+1, revocation_version=revocation_version+1 WHERE id=1',
  ).run();
  process.send?.({ event: 'locked', began, acquired });
  await new Promise((resolve) => setTimeout(resolve, Number(delayString)));
  db.exec('COMMIT');
  const epoch = db.prepare('SELECT epoch FROM authority WHERE id=1').get().epoch;
  process.send?.({ event: 'committed', epoch, waitedMs: acquired - began });
  db.close();
  process.disconnect?.();
});
