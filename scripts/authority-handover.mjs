#!/usr/bin/env node
// Local custodian maintenance only. Does not provide a network administration endpoint.
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CheckpointCustodian } from '../services/evidence/custody.mjs';

export function handoverFromFiles(args) {
  if (args.length !== 4)
    throw new Error(
      'Usage: authority-handover CUSTODY_DB AUTHORITY_PUBLIC_KEY CUSTODIAN_PRIVATE_KEY REQUEST_JSON',
    );
  const [database, authorityPath, signingPath, requestPath] = args;
  const read = (path, secret = false) => {
    const st = statSync(path);
    if (!st.isFile() || st.size > 16384 || (secret && st.mode & 0o077))
      throw new Error('HANDOVER_FILE_INVALID');
    return JSON.parse(readFileSync(path, 'utf8'));
  };
  // Refuse to create a new database accidentally during an intended failover.
  if (!statSync(database).isFile()) throw new Error('HANDOVER_DATABASE_REQUIRED');
  const custody = new CheckpointCustodian({
    database,
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
