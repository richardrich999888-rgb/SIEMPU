#!/usr/bin/env node
// Local custodian maintenance only. Does not provide a network administration endpoint.
import {
  constants,
  openSync,
  closeSync,
  fstatSync,
  readSync,
  lstatSync,
  realpathSync,
} from 'node:fs';
import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CheckpointCustodian } from '../services/evidence/custody.mjs';

export function handoverFromFiles(args) {
  if (args.length !== 4)
    throw new Error(
      'Usage: authority-handover CUSTODY_DB AUTHORITY_PUBLIC_KEY CUSTODIAN_PRIVATE_KEY REQUEST_JSON',
    );
  const [database, authorityPath, signingPath, requestPath] = args;
  const read = (path, secret = false) => {
    // Validate and read the same open descriptor. NOFOLLOW rejects final symlinks;
    // NONBLOCK permits rejecting a FIFO without waiting for an attacker-controlled writer.
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const st = fstatSync(fd);
      if (
        !st.isFile() ||
        st.size > 16384 ||
        (secret && ((st.mode & 0o077) !== 0 || st.uid !== process.getuid() || st.nlink !== 1))
      )
        throw new Error('HANDOVER_FILE_INVALID');
      // A file may grow after fstat; bound the actual read as well as its initial size.
      const bytes = Buffer.alloc(16385);
      let length = 0,
        count;
      while (
        length < bytes.length &&
        (count = readSync(fd, bytes, length, bytes.length - length, null))
      )
        length += count;
      if (length > 16384) throw new Error('HANDOVER_FILE_INVALID');
      return JSON.parse(bytes.subarray(0, length).toString('utf8'));
    } finally {
      closeSync(fd);
    }
  };
  // SQLite reopens its path. Require an existing file in an operator-owned private
  // directory; hostile processes with the same UID are outside this maintenance boundary.
  const dbPath = resolve(database),
    parent = dirname(dbPath),
    directory = lstatSync(parent);
  if (
    !directory.isDirectory() ||
    directory.uid !== process.getuid() ||
    directory.mode & 0o077 ||
    realpathSync(parent) !== parent
  )
    throw new Error('HANDOVER_DATABASE_DIRECTORY');
  const dbFile = lstatSync(dbPath);
  if (
    !dbFile.isFile() ||
    dbFile.isSymbolicLink() ||
    dbFile.nlink !== 1 ||
    dbFile.uid !== process.getuid() ||
    dbFile.mode & 0o077
  )
    throw new Error('HANDOVER_DATABASE_REQUIRED');
  const custody = new CheckpointCustodian({
    database: dbPath,
    authorityKey: read(authorityPath),
    signingKey: read(signingPath, true),
    requireFencing: true,
  });
  try {
    return custody.transferWriter(read(requestPath));
  } finally {
    custody.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(handoverFromFiles(process.argv.slice(2)), null, 2));
  } catch {
    console.error(
      'HANDOVER_REJECTED: inspect the reviewed inputs and retained checkpoint; no automatic retry',
    );
    process.exitCode = 1;
  }
}
