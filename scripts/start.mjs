import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const data = resolve(process.env.SIEPMU_DATA_DIR || '.data');
for (const file of ['control.sqlite', 'server-key.json', 'master.key', 'relay.secret']) {
  if (!existsSync(resolve(data, file))) {
    console.error(
      `Missing provisioned state: ${file}. Run npm run bootstrap first. This command never creates identities implicitly.`,
    );
    process.exit(1);
  }
}
const children = [];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill('SIGTERM');
  const timer = setTimeout(() => {
    for (const child of children) child.kill('SIGKILL');
    process.exit(code);
  }, 5000);
  timer.unref();
  Promise.all(
    children.map((child) =>
      child.exitCode !== null ? Promise.resolve() : new Promise((r) => child.once('exit', r)),
    ),
  ).then(() => process.exit(code));
}
for (const file of [
  'services/relay/server.mjs',
  'services/control/server.mjs',
  'services/web/server.mjs',
]) {
  const child = spawn(process.execPath, [file], {
    stdio: 'inherit',
    env: { ...process.env, SIEPMU_DATA_DIR: data },
  });
  children.push(child);
  child.once('error', () => stop(1));
  child.once('exit', (code) => {
    if (!stopping) stop(code || 1);
  });
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => stop(0));
