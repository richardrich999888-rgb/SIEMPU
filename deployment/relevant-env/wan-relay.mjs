// Userspace WAN emulator on the Host A → Host B path (latency and jitter only).
//
// Used where the kernel lacks sch_netem (see topology.probe). It runs inside Host A's namespace,
// listens on Host A's loopback (where `web` resolves for Host A) and forwards each TCP connection
// to Host B's gateway, delaying every chunk in both directions. Bytes are never reordered or
// dropped: TCP above it would hide loss anyway, so packet loss is NOT emulated here; the hosted
// CI run uses kernel netem for loss. Bandwidth limits and outages are kernel-level (TBF, link
// down) and independent of this relay.
//
// The profile is re-read for every new connection, so a profile change applies to the next
// request (clients open a new TLS connection per request).

import { createServer, connect } from 'node:net';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

/** Upper bounds keep a mistyped profile from stalling a run. */
export const MAX_DELAY_MS = 2000;
export const MAX_JITTER_MS = 1000;

/**
 * Deterministic PRNG (mulberry32): reproducible jitter for a given seed.
 * @param {number} seed 32-bit integer
 * @returns {() => number} uniform in [0, 1)
 */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Validates a profile; throws on anything outside bounds (fail closed). */
export function validateProfile(profile) {
  const { delayMs, jitterMs, seed } = profile ?? {};
  if (
    !Number.isInteger(delayMs) ||
    delayMs < 0 ||
    delayMs > MAX_DELAY_MS ||
    !Number.isInteger(jitterMs) ||
    jitterMs < 0 ||
    jitterMs > MAX_JITTER_MS ||
    jitterMs > delayMs ||
    !Number.isInteger(seed)
  )
    throw new TypeError('Invalid WAN profile');
  return { delayMs, jitterMs, seed };
}

/**
 * Delivery time for the next chunk on one direction of a connection.
 * One-way delay = delayMs + uniform(-jitterMs, +jitterMs); a chunk is never delivered before the
 * previous one on the same direction (in-order, like a single TCP path), so jitter compresses
 * into queueing rather than reordering.
 * @param {number} previousDue delivery time of the previous chunk (ms), or 0
 * @param {number} now arrival time of this chunk (ms)
 */
export function nextDue(previousDue, now, { delayMs, jitterMs }, random) {
  const jitter = jitterMs === 0 ? 0 : Math.round((2 * random() - 1) * jitterMs);
  return Math.max(previousDue, now + delayMs + jitter);
}

/**
 * FIFO of chunks with non-decreasing due times, drained by one timer.
 *
 * Rationale: one setTimeout per chunk is NOT order-preserving in Node. Timers with different
 * durations live in different lists, and two timers that expire in the same millisecond may fire
 * in either order. Reordered TLS records fail authentication (observed as
 * ERR_SSL_DECRYPTION_FAILED_OR_BAD_RECORD_MAC). A single queue makes ordering structural.
 * @param {(chunk: Buffer|null) => void} deliver called in order; null marks end of stream
 * @param {() => number} clock milliseconds
 */
export function createDelayQueue(deliver, clock = Date.now) {
  const queue = [];
  let timer = null;
  const drain = () => {
    timer = null;
    while (queue.length > 0 && queue[0].due <= clock()) deliver(queue.shift().chunk);
    if (queue.length > 0) timer = setTimeout(drain, Math.max(0, queue[0].due - clock()));
  };
  return {
    /** Enqueues a chunk (or null for end) for delivery at `due`; due must not decrease. */
    push(chunk, due) {
      if (queue.length > 0 && due < queue[queue.length - 1].due)
        throw new RangeError('due time decreased');
      queue.push({ chunk, due });
      if (timer === null) timer = setTimeout(drain, Math.max(0, due - clock()));
    },
    /** Drops pending chunks (connection torn down). */
    clear() {
      queue.length = 0;
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
    get length() {
      return queue.length;
    },
  };
}

/** Pipes `from` to `to`, delaying each chunk per the schedule, strictly in order. */
function delayedPipe(from, to, profile, random) {
  let due = 0;
  const queue = createDelayQueue((chunk) => {
    if (chunk === null) to.end();
    else if (to.writable) to.write(chunk);
  });
  from.on('data', (chunk) => {
    due = nextDue(due, Date.now(), profile, random);
    queue.push(chunk, due);
  });
  // End of stream follows the last chunk, never overtaking it.
  from.on('end', () => queue.push(null, Math.max(due, Date.now())));
  from.on('error', () => {
    queue.clear();
    to.destroy();
  });
}

/**
 * Starts the relay.
 * @param {{listenHost: string, listenPort: number, upstreamHost: string, upstreamPort: number,
 *   profilePath: string}} options
 */
export function startWanRelay({ listenHost, listenPort, upstreamHost, upstreamPort, profilePath }) {
  let connections = 0;
  const server = createServer((client) => {
    let profile;
    try {
      profile = validateProfile(JSON.parse(readFileSync(profilePath, 'utf8')));
    } catch {
      client.destroy();
      return;
    }
    const random = mulberry32(profile.seed + connections++);
    const upstream = connect(upstreamPort, upstreamHost);
    delayedPipe(client, upstream, profile, random);
    delayedPipe(upstream, client, profile, random);
    upstream.on('error', () => client.destroy());
  });
  server.listen(listenPort, listenHost);
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [listenHost, listenPort, upstreamHost, upstreamPort, profilePath] = process.argv.slice(2);
  startWanRelay({
    listenHost,
    listenPort: Number(listenPort),
    upstreamHost,
    upstreamPort: Number(upstreamPort),
    profilePath,
  });
  process.on('SIGTERM', () => process.exit(0));
}
