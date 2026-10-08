// Three-host relevant-environment topology on one Linux kernel.
//
//   Host A (siepmu-a)  10.69.1.2 ── veth ── 10.69.1.1  Host B (siepmu-b)  10.69.2.1 ── veth ── 10.69.2.2  Host C (siepmu-c)
//   sender unit                                gateway, authority, relay,                       recipient unit, document
//                                              custodian, collector                              system + adapter, verifier
//
// Each host is a separate Linux network namespace with its own interfaces, routes, loopback,
// /etc/hosts (via /etc/netns/<ns>/hosts) and state directory. Hosts A and C have no route to each
// other; everything goes through Host B's TLS gateway. Internal services on Host B bind Host B's
// own loopback, which no other namespace can reach.
//
// This is namespace isolation on ONE kernel, not separate machines or virtual machines: the
// hosts share the kernel, CPU, clock and file system. Reports must say so.

import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';

/** Host definitions. `links` name this host's interface on each link. */
export const HOSTS = Object.freeze({
  a: { ns: 'siepmu-a', role: 'sender unit', address: '10.69.1.2', gatewayAddress: '10.69.1.1' },
  b: { ns: 'siepmu-b', role: 'platform', address: '10.69.1.1' },
  c: { ns: 'siepmu-c', role: 'recipient unit', address: '10.69.2.2', gatewayAddress: '10.69.2.1' },
});

/** Point-to-point links. The A↔B link is the impaired "WAN" in the network tests. */
export const LINKS = Object.freeze([
  { id: 'ab', left: ['a', 'sa0', '10.69.1.2/24'], right: ['b', 'sb1', '10.69.1.1/24'] },
  { id: 'cb', left: ['c', 'sc0', '10.69.2.2/24'], right: ['b', 'sb2', '10.69.2.1/24'] },
]);

/**
 * Commands that build the topology, in order (pure; no side effects). Each entry is an argv for
 * execFileSync. `hosts` files are written separately (see writeHostsFiles).
 */
export function topologyPlan() {
  const plan = [];
  for (const host of Object.values(HOSTS)) {
    plan.push(['ip', 'netns', 'add', host.ns]);
    plan.push(['ip', '-n', host.ns, 'link', 'set', 'lo', 'up']);
  }
  for (const link of LINKS) {
    const [lh, lif, laddr] = link.left;
    const [rh, rif, raddr] = link.right;
    plan.push(['ip', 'link', 'add', lif, 'type', 'veth', 'peer', 'name', rif]);
    plan.push(['ip', 'link', 'set', lif, 'netns', HOSTS[lh].ns]);
    plan.push(['ip', 'link', 'set', rif, 'netns', HOSTS[rh].ns]);
    plan.push(['ip', '-n', HOSTS[lh].ns, 'addr', 'add', laddr, 'dev', lif]);
    plan.push(['ip', '-n', HOSTS[rh].ns, 'addr', 'add', raddr, 'dev', rif]);
    plan.push(['ip', '-n', HOSTS[lh].ns, 'link', 'set', lif, 'up']);
    plan.push(['ip', '-n', HOSTS[rh].ns, 'link', 'set', rif, 'up']);
  }
  return plan;
}

/**
 * /etc/hosts content per namespace. Units resolve `web` to the address they reach Host B on
 * (A: through the WAN emulator on its own loopback, see wan-relay.mjs); Host B resolves it
 * locally. The certificate SAN is DNS:web, so TLS name checks are real.
 */
export function hostsFiles() {
  return {
    [HOSTS.a.ns]: '127.0.0.1 localhost\n127.0.0.1 web\n',
    [HOSTS.b.ns]: '127.0.0.1 localhost\n127.0.0.1 web\n',
    [HOSTS.c.ns]: `127.0.0.1 localhost\n${HOSTS.c.gatewayAddress} web\n`,
  };
}

const run = (argv) => execFileSync(argv[0], argv.slice(1), { stdio: 'pipe' });

/** True if a namespace with this name already exists. */
function nsExists(ns) {
  try {
    return execFileSync('ip', ['netns', 'list'], { encoding: 'utf8' })
      .split('\n')
      .some((line) => line.split(' ')[0] === ns);
  } catch {
    return false;
  }
}

/** Removes any previous instance (idempotent). */
export function teardown() {
  for (const host of Object.values(HOSTS)) {
    if (nsExists(host.ns)) run(['ip', 'netns', 'del', host.ns]);
    rmSync(`/etc/netns/${host.ns}`, { recursive: true, force: true });
  }
}

/** Builds the topology. Requires root and iproute2; throws on the first failing command. */
export function apply() {
  teardown();
  for (const argv of topologyPlan()) run(argv);
  for (const [ns, content] of Object.entries(hostsFiles())) {
    mkdirSync(`/etc/netns/${ns}`, { recursive: true });
    writeFileSync(`/etc/netns/${ns}/hosts`, content);
  }
}

/** argv prefix that runs a command inside a host's namespace. */
export const inHost = (host) => ['ip', 'netns', 'exec', HOSTS[host].ns];

/** Sets the A↔B link administratively down or up on both ends (a real link outage). */
export function setWanLink(up) {
  const state = up ? 'up' : 'down';
  run(['ip', '-n', HOSTS.a.ns, 'link', 'set', 'sa0', state]);
  run(['ip', '-n', HOSTS.b.ns, 'link', 'set', 'sb1', state]);
}

/**
 * Kernel token-bucket bandwidth limit on both directions of the A↔B link, or removal when
 * `rateKbit` is null. TBF is a real kernel qdisc; burst and latency bound the queue.
 */
export function setWanBandwidth(rateKbit) {
  for (const [ns, dev] of [
    [HOSTS.a.ns, 'sa0'],
    [HOSTS.b.ns, 'sb1'],
  ]) {
    try {
      run(['ip', 'netns', 'exec', ns, 'tc', 'qdisc', 'del', 'dev', dev, 'root']);
    } catch {}
    if (rateKbit !== null)
      run([
        'ip',
        'netns',
        'exec',
        ns,
        'tc',
        'qdisc',
        'add',
        'dev',
        dev,
        'root',
        'tbf',
        'rate',
        `${rateKbit}kbit`,
        'burst',
        '32kbit',
        'latency',
        '400ms',
      ]);
  }
}

/** Kernel netem on the A↔B link (only where the kernel provides sch_netem; see probe()). */
export function setWanNetem(args) {
  for (const [ns, dev] of [
    [HOSTS.a.ns, 'sa0'],
    [HOSTS.b.ns, 'sb1'],
  ]) {
    try {
      run(['ip', 'netns', 'exec', ns, 'tc', 'qdisc', 'del', 'dev', dev, 'root']);
    } catch {}
    if (args)
      run(['ip', 'netns', 'exec', ns, 'tc', 'qdisc', 'add', 'dev', dev, 'root', 'netem', ...args]);
  }
}

/** Interface counters for a host interface (bytes and packets, both directions). */
export function linkCounters(host, dev) {
  const read = (name) =>
    Number(
      execFileSync(
        'ip',
        ['netns', 'exec', HOSTS[host].ns, 'cat', `/sys/class/net/${dev}/statistics/${name}`],
        {
          encoding: 'utf8',
        },
      ).trim(),
    );
  return {
    rxBytes: read('rx_bytes'),
    txBytes: read('tx_bytes'),
    rxPackets: read('rx_packets'),
    txPackets: read('tx_packets'),
  };
}

/**
 * Capability probe: whether this kernel can host the topology and which impairments it supports.
 * Runs in a throwaway namespace and leaves nothing behind.
 */
export function probe() {
  const ns = 'siepmu-probe';
  const result = { namespaces: false, tbf: false, netem: false };
  try {
    if (nsExists(ns)) run(['ip', 'netns', 'del', ns]);
    run(['ip', 'netns', 'add', ns]);
    result.namespaces = true;
    run(['ip', '-n', ns, 'link', 'set', 'lo', 'up']);
    for (const [kind, args] of [
      ['tbf', ['tbf', 'rate', '1mbit', 'burst', '32kbit', 'latency', '400ms']],
      ['netem', ['netem', 'delay', '1ms']],
    ]) {
      try {
        run(['ip', 'netns', 'exec', ns, 'tc', 'qdisc', 'add', 'dev', 'lo', 'root', ...args]);
        run(['ip', 'netns', 'exec', ns, 'tc', 'qdisc', 'del', 'dev', 'lo', 'root']);
        result[kind] = true;
      } catch {}
    }
  } catch {
  } finally {
    try {
      run(['ip', 'netns', 'del', ns]);
    } catch {}
  }
  return result;
}
