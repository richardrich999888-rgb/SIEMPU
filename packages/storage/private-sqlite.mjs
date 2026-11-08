import {
  constants,
  openSync,
  closeSync,
  fstatSync,
  lstatSync,
  realpathSync,
  existsSync,
} from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

// Caller provisions a private directory. This is not a boundary against a hostile
// process running as the same OS user or against a compromised administrator.
export function openPrivateDatabase(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path)
    throw new Error('PRIVATE_DATABASE_PATH');
  const parent = dirname(path),
    directory = lstatSync(parent);
  const owned = (s) => s.uid === process.getuid() && (s.mode & 0o077) === 0;
  if (!directory.isDirectory() || !owned(directory) || realpathSync(parent) !== parent)
    throw new Error('PRIVATE_DATABASE_DIRECTORY');
  for (const name of [path, path + '-wal', path + '-shm', path + '-journal']) {
    if (!existsSync(name)) continue;
    const s = lstatSync(name);
    if (!s.isFile() || s.isSymbolicLink() || !owned(s) || s.nlink !== 1)
      throw new Error('PRIVATE_DATABASE_PERMISSIONS');
  }
  const fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  try {
    const s = fstatSync(fd);
    if (!s.isFile() || !owned(s) || s.nlink !== 1) throw new Error('PRIVATE_DATABASE_PERMISSIONS');
  } finally {
    closeSync(fd);
  }
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;');
  return db;
}

export function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    if (db.isTransaction) db.exec('ROLLBACK');
    throw error;
  }
}
