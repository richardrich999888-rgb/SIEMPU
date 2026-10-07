import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
const excluded = new Set(['.git', '.data', 'node_modules', 'dist', 'artifacts', 'coverage']);
const rules = [
  ['private PEM key', /-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----/],
  ['GitHub credential', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/],
  ['AWS access identifier', /\bAKIA[A-Z0-9]{16}\b/],
];
let count = 0;
async function walk(dir) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (excluded.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      await walk(p);
      continue;
    }
    if (!e.isFile()) continue;
    if (/\.(sqlite|sqlite-wal|db|key)$/.test(p) || /(?:demo-profiles|server-key)\.json$/.test(p)) {
      console.error(`Forbidden runtime material: ${p}`);
      process.exitCode = 1;
    }
    if (!/\.(mjs|js|json|md|yaml|yml|html|css|txt)$/.test(p)) continue;
    const text = await readFile(p, 'utf8');
    count++;
    for (const [name, regex] of rules)
      if (regex.test(text)) {
        console.error(`Potential ${name}: ${p}; value suppressed`);
        process.exitCode = 1;
      }
    if (
      /\.(mjs|js)$/.test(p) &&
      p !== 'scripts/security.mjs' &&
      /\beval\s*\(|\bnew\s+Function\s*\(|\.innerHTML\s*=/.test(text)
    ) {
      console.error(`Disallowed dynamic execution or HTML assignment: ${p}`);
      process.exitCode = 1;
    }
  }
}
await walk('.');
console.log(
  `Local narrow security rules checked ${count} text files; complete secret scanning and SAST are separate CI jobs.`,
);
