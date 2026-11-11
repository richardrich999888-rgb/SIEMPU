import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { snapshot } from '../../assurance/sag/package.mjs';
import { fingerprint } from '../../assurance/sag/format.mjs';
const s = snapshot(resolve('.'));
console.log(
  JSON.stringify({
    commit: s.commit,
    tree: s.tree,
    fingerprint: fingerprint(s.index),
    lockfileSha256: createHash('sha256').update(readFileSync('package-lock.json')).digest('hex'),
  }),
);
