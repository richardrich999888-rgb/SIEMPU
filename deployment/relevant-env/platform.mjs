// Relevant-environment platform control: offline provisioning, per-host state distribution,
// service processes inside Host B's namespace, the adapter inside Host C's namespace, and agent
// invocation on any host. The conductor (this module's caller) runs in the root namespace and
// has NO network path to any host; it acts only by launching processes inside a host namespace.

import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { copyFileSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { HOSTS } from './topology.mjs';
import { prepareSecureLab, seedLabCustodian, labEnvironment } from '../secure/harness.mjs';

const execFileAsync = promisify(execFile);
const ROOT = resolve('.');

/** Fixed ports: every host has its own port space, so no reservation is needed. */
export const PORTS = Object.freeze({
  web: 8443,
  control: 8441,
  relay: 8442,
  checkpoint: 8444,
  collector: 8445,
  adapter: 8446,
});
export const GATEWAY_URL = `https://web:${PORTS.web}`;
const SERVICE_FILES = Object.freeze({
  collector: 'services/monitoring/server.mjs',
  checkpoint: 'services/evidence/server.mjs',
  relay: 'services/relay/server.mjs',
  control: 'services/control/server.mjs',
  web: 'services/web/server.mjs',
});

/** Public descriptor of a user (what other hosts may know). */
export const publicDescriptor = (p) => ({
  username: p.username,
  userId: p.userId,
  deviceId: p.deviceId,
  unitId: p.unitId,
  encryptionPublicKey: p.keys.encryption.publicKey,
  signingPublicKey: p.keys.signing.publicKey,
});

const writePrivate = (path, data) => writeFileSync(path, data, { mode: 0o600 });

/**
 * Builds Host B's authority state and lab PKI, then distributes per-host material.
 * @param {{work: string, authorityDir: string, provisioned: any, profiles: Record<string, any>,
 *   placement: Record<'a'|'b'|'c', string[]>}} input placement: usernames whose private
 *   profiles each host receives.
 */
export async function provisionEnvironment({
  work,
  authorityDir,
  provisioned,
  profiles,
  placement,
}) {
  const lab = prepareSecureLab(authorityDir);
  await seedLabCustodian(authorityDir, lab.independent);
  const env = {
    ...process.env,
    ...labEnvironment(authorityDir, lab.pki, PORTS, {
      web: '127.0.0.1',
      control: '127.0.0.1',
      relay: '127.0.0.1',
      checkpoint: '127.0.0.1',
      collector: '127.0.0.1',
    }),
    // The gateway is the only Host B listener on the external interfaces.
    SIEPMU_WEB_HOST: '0.0.0.0',
    SIEPMU_PUBLIC_ORIGIN: GATEWAY_URL,
  };
  delete env.SIEPMU_ALLOW_REMOTE_HTTP;
  const states = {};
  for (const host of ['a', 'b', 'c']) {
    const dir = join(work, `host-${host}`);
    mkdirSync(join(dir, 'profiles'), { recursive: true, mode: 0o700 });
    copyFileSync(join(lab.pki.dir, 'ca.crt'), join(dir, 'ca.crt'));
    writeFileSync(join(dir, 'authority-public.json'), JSON.stringify(provisioned.serverPublicKey));
    writeFileSync(
      join(dir, 'peers.json'),
      JSON.stringify(
        Object.fromEntries(Object.values(profiles).map((p) => [p.username, publicDescriptor(p)])),
      ),
    );
    for (const username of placement[host])
      writePrivate(join(dir, 'profiles', `${username}.json`), JSON.stringify(profiles[username]));
    states[host] = dir;
  }
  return { lab, env, states };
}

/** Adds newly enrolled users to the hosts that should hold them and refreshes every peers.json. */
export function distributeProfiles(states, profiles, placement) {
  for (const [host, usernames] of Object.entries(placement))
    for (const username of usernames)
      writePrivate(
        join(states[host], 'profiles', `${username}.json`),
        JSON.stringify(profiles[username]),
      );
  for (const dir of Object.values(states)) {
    const peers = JSON.parse(readFileSync(join(dir, 'peers.json'), 'utf8'));
    for (const p of Object.values(profiles)) peers[p.username] = publicDescriptor(p);
    writeFileSync(join(dir, 'peers.json'), JSON.stringify(peers));
  }
}

/** Copies named TLS identities from the lab PKI into a host's tls/ directory. */
export function installIdentities(state, pkiDir, names) {
  mkdirSync(join(state, 'tls'), { recursive: true, mode: 0o700 });
  for (const name of names) {
    writePrivate(join(state, 'tls', `${name}.crt`), readFileSync(join(pkiDir, `${name}.crt`)));
    writePrivate(join(state, 'tls', `${name}.key`), readFileSync(join(pkiDir, `${name}.key`)));
  }
}

/** Starts a Node process inside a host namespace with its output appended to a log file. */
export function startInHost(host, args, env, logFile) {
  const fd = openSync(logFile, 'a');
  return spawn('ip', ['netns', 'exec', HOSTS[host].ns, process.execPath, ...args], {
    cwd: ROOT,
    env,
    stdio: ['ignore', fd, fd],
  });
}

/** Stops a child with SIGTERM, escalating to SIGKILL after a bounded wait. */
export async function stopChild(child, waitMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((r) => child.once('exit', r));
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), waitMs);
  await exited;
  clearTimeout(timer);
}

/** Host B service processes, individually stoppable for fault injection. */
export function createPlatform(env, logDir) {
  const children = new Map();
  const start = (role) => {
    children.set(role, startInHost('b', [SERVICE_FILES[role]], env, join(logDir, `${role}.log`)));
    return children.get(role);
  };
  return {
    children,
    start,
    startAll: () => Object.keys(SERVICE_FILES).forEach(start),
    stop: (role) => stopChild(children.get(role)),
    stopAll: async () => {
      for (const role of ['web', 'control', 'relay', 'checkpoint', 'collector'])
        await stopChild(children.get(role));
    },
    pids: () => Object.fromEntries([...children].map(([role, c]) => [role, c.pid])),
  };
}

/**
 * Runs one agent command inside a host and returns its JSON result. A crash (non-zero exit or
 * unparsable output) becomes {ok:false, crashed:true} so a test records it rather than aborting.
 */
export async function agent(states, host, command, args = {}, timeoutMs = 120000) {
  try {
    const { stdout } = await execFileAsync(
      'ip',
      [
        'netns',
        'exec',
        HOSTS[host].ns,
        process.execPath,
        'deployment/relevant-env/agent.mjs',
        command,
        JSON.stringify(args),
      ],
      {
        cwd: ROOT,
        timeout: timeoutMs,
        maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, SIEPMU_HOST_STATE: states[host], SIEPMU_GATEWAY_URL: GATEWAY_URL },
      },
    );
    return JSON.parse(stdout.trim().split('\n').pop());
  } catch (error) {
    return {
      ok: false,
      crashed: true,
      code: (error.stderr ?? error.message ?? '').toString().slice(0, 1500),
    };
  }
}
