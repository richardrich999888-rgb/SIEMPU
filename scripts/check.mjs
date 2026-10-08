import { readdir, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { isTextPath, textIntegrityViolation } from './text-integrity.mjs';

const excluded = new Set([
  '.git',
  '.data',
  'node_modules',
  'dist',
  'artifacts',
  'coverage',
  'target',
]);
async function walk(dir) {
  const files = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await walk(path)));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}
const files = await walk('.');
let textFiles = 0;
for (const file of files.filter(isTextPath)) {
  const violation = textIntegrityViolation(await readFile(file));
  if (violation) {
    console.error(`Corrupted source text (${violation}): ${file}`);
    process.exitCode = 1;
  }
  textFiles++;
}
let count = 0;
for (const file of files.filter((p) => /\.(mjs|js)$/.test(p))) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exitCode = 1;
  }
  count++;
}
for (const file of files.filter((p) => p.endsWith('.json') && !p.startsWith('docs/'))) {
  try {
    JSON.parse(await readFile(file, 'utf8'));
  } catch {
    console.error(`Invalid JSON: ${file}`);
    process.exitCode = 1;
  }
}
const manifest = JSON.parse(await readFile('package.json', 'utf8'));
if (Object.keys(manifest.dependencies || {}).length) {
  console.error('Unexpected npm runtime dependency: review the zero-dependency boundary.');
  process.exitCode = 1;
}
console.log(
  `Text integrity: ${textFiles} files. Syntax and JSON validation: ${count} JavaScript modules checked. This is not a type checker or SAST.`,
);
