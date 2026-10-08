// Port reservation for laboratory child processes.
//
// Root cause this addresses: binding port 0, closing it and later handing the number to a
// child process is a time-of-check/time-of-use race. Port 0 is drawn from the kernel's
// ephemeral range, the same pool used for the local side of OUTBOUND connections, so any
// socket opened in the gap (for example readiness polling) can take the port and the child
// fails with EADDRINUSE. Ports below the ephemeral range are never assigned to outbound
// sockets, which removes that competitor. A bind check still guards against other listeners.

import { createServer } from 'node:net';
import { readFileSync } from 'node:fs';

/** Lowest port handed out; above common registered service ports used on developer hosts. */
export const RESERVED_PORT_FLOOR = 20000;
/** Linux default ephemeral range, used when the kernel setting cannot be read. */
export const DEFAULT_EPHEMERAL_RANGE = Object.freeze({ low: 32768, high: 60999 });
/** Minimum usable span; below this the host is misconfigured for laboratory use. */
const MINIMUM_SPAN = 1000;
/** Upper bound on bind attempts per reservation before failing closed. */
const MAX_ATTEMPTS = 200;

/**
 * Parses /proc/sys/net/ipv4/ip_local_port_range ("low<TAB>high").
 * @param {string} text
 * @returns {{low: number, high: number}}
 */
export function parseEphemeralRange(text) {
  const match = /^\s*(\d+)\s+(\d+)\s*$/.exec(text);
  if (!match) throw new Error('Unreadable ephemeral port range');
  const low = Number(match[1]),
    high = Number(match[2]);
  if (!(low >= 1 && high <= 65535 && low <= high)) throw new Error('Invalid ephemeral port range');
  return { low, high };
}

/** @returns {{low: number, high: number}} */
export function ephemeralRange() {
  try {
    return parseEphemeralRange(readFileSync('/proc/sys/net/ipv4/ip_local_port_range', 'utf8'));
  } catch {
    return DEFAULT_EPHEMERAL_RANGE;
  }
}

/**
 * Deterministic candidate sequence below the ephemeral range. The start offset is derived
 * from the process ID so that concurrent test processes on one host start apart; the
 * sequence then walks the span linearly (no randomness).
 * @param {{pid: number, ephemeral: {low: number, high: number}, count: number}} input
 * @returns {number[]}
 */
export function portCandidates({ pid, ephemeral, count }) {
  const low = RESERVED_PORT_FLOOR,
    high = ephemeral.low - 1;
  const span = high - low + 1;
  if (span < MINIMUM_SPAN)
    throw new Error('Ephemeral port range leaves no reserved laboratory port span');
  // 7919 is prime, so pid * 7919 spreads neighbouring PIDs across the span.
  const start = (pid * 7919) % span;
  return Array.from({ length: Math.min(count, span) }, (_, i) => low + ((start + i) % span));
}

/** @param {number} port @returns {Promise<boolean>} */
function bindable(port) {
  return new Promise((resolve) => {
    const server = createServer();
    server.once('error', () => resolve(false));
    server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
  });
}

const handedOut = new Set();
let cursor = 0;
let sequence = null;

/**
 * Returns a loopback port outside the ephemeral range that was bindable at reservation time
 * and has not been returned before in this process.
 * @returns {Promise<number>}
 */
export async function reservePort() {
  sequence ??= portCandidates({
    pid: process.pid,
    ephemeral: ephemeralRange(),
    count: Number.MAX_SAFE_INTEGER,
  });
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const port = sequence[cursor];
    cursor = (cursor + 1) % sequence.length;
    if (handedOut.has(port)) continue;
    if (await bindable(port)) {
      handedOut.add(port);
      return port;
    }
  }
  throw new Error('No reservable laboratory port');
}
