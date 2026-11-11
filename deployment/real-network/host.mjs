import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { snapshot } from '../../assurance/sag/package.mjs';

export function startHost(nodeDirectory, { root = resolve('.'), onLog = () => {} } = {}) {
  const directory = resolve(nodeDirectory),
    config = JSON.parse(readFileSync(directory + '/node.json'));
  const source = snapshot(root);
  if (source.commit !== config.source.commit || source.tree !== config.source.tree)
    throw new Error('HOST_SOURCE_MISMATCH');
  const children = new Map();
  const startRole = (role) => {
    const m = config.roles.find((r) => r.role === role);
    if (!m || children.get(role)?.exitCode === null) throw new Error('ROLE_STATE');
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: 'production' };
    for (const [key, value] of Object.entries(m.env))
      env[key] = value.replaceAll('@NODE@', directory);
    const child = spawn(process.execPath, m.command, {
      cwd: root,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.set(role, child);
    for (const stream of [child.stdout, child.stderr])
      stream.on('data', (b) => onLog(role, String(b)));
    child.on('error', () => onLog(role, 'SERVICE_SPAWN_ERROR\n'));
    return child;
  };
  const stopRole = async (role) => {
    const c = children.get(role);
    if (!c || c.exitCode !== null || c.signalCode !== null) return;
    const done = new Promise((r) => c.once('close', r));
    c.kill('SIGTERM');
    const timer = setTimeout(() => c.kill('SIGKILL'), 5000);
    await done;
    clearTimeout(timer);
  };
  for (const m of config.roles) startRole(m.role);
  return {
    children,
    startRole,
    stopRole,
    stop: async () => {
      for (const r of children.keys()) await stopRole(r);
    },
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const host = startHost(process.argv[2], { onLog: (_role, line) => process.stdout.write(line) });
  for (const signal of ['SIGTERM', 'SIGINT'])
    process.once(signal, async () => {
      await host.stop();
      process.exit(0);
    });
  // Hard stop for unattended experiments. Operator starts a fresh bounded session for endurance.
  setTimeout(
    async () => {
      await host.stop();
      process.exit(0);
    },
    2 * 60 * 60 * 1000,
  );
}
