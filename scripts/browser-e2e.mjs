/** Run the real UI against an isolated, disposable three-process deployment. */
import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { provision, startStack } from '../tests/helpers/fixture.mjs';

const fixture = await provision();
let stack;
try {
  stack = await startStack(fixture.dir);
  const exitCode = await new Promise((resolveExit, reject) => {
    const child = spawn(process.execPath, ['apps/unit-client/browser-check.mjs'], {
      cwd: resolve('.'),
      env: {
        ...process.env,
        SIEPMU_URL: stack.baseUrl,
        SIEPMU_BROWSER_PROFILES: join(fixture.dir, 'demo-profiles.json'),
      },
      stdio: 'inherit',
    });
    child.once('error', reject);
    child.once('exit', (code) => resolveExit(code ?? 1));
  });
  process.exitCode = exitCode;
} finally {
  await stack?.stop();
  await rm(fixture.dir, { recursive: true, force: true });
}
