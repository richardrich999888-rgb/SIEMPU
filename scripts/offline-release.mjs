import { readFileSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { buildOfflineBundle, installOfflineBundle } from '../packages/release/offline.mjs';
const read = (p) => JSON.parse(readFileSync(p));
const [command, a, b, c] = process.argv.slice(2);
if (command === 'build') {
  if (!process.env.SIEPMU_RELEASE_KEY || statSync(process.env.SIEPMU_RELEASE_KEY).mode & 0o077)
    throw new Error('Supply protected offline release signing key');
  if (
    execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
      encoding: 'utf8',
    }).trim()
  )
    throw new Error('Commit source before packaging');
  const m = buildOfflineBundle({
    source: '.',
    destination: a,
    version: Number(b),
    revision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    signingKey: read(process.env.SIEPMU_RELEASE_KEY),
  });
  console.log(
    JSON.stringify({
      status: 'SIGNED_LAB_BUNDLE',
      revision: m.payload.revision,
      version: m.payload.version,
      files: m.payload.files.length,
    }),
  );
} else if (command === 'install') {
  if (!process.env.SIEPMU_RELEASE_TRUST || !process.env.SIEPMU_RELEASE_LEDGER)
    throw new Error('Supply independently retained release public key and ledger path');
  console.log(
    JSON.stringify(
      installOfflineBundle({
        bundle: a,
        destination: b,
        ledger: process.env.SIEPMU_RELEASE_LEDGER,
        trustedKey: read(process.env.SIEPMU_RELEASE_TRUST),
        initialize: c === '--initialize',
      }),
    ),
  );
} else
  throw new Error(
    'Usage: offline-release.mjs build BUNDLE VERSION | install BUNDLE EMPTY_DEST [--initialize]',
  );
