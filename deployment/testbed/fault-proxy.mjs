/** Deterministic request-level impairment, NOT tc/netem or packet-loss emulation. */
import { setTimeout as delay } from 'node:timers/promises';

export const FAULT_PROFILES = Object.freeze({
  stable: { delayMs: 0, jitterMs: [0], chunkBytes: 65536, chunkDelayMs: 0 },
  constrained: { delayMs: 25, jitterMs: [0, 10, 5], chunkBytes: 4096, chunkDelayMs: 5 },
  interrupted: { delayMs: 5, jitterMs: [0], chunkBytes: 2048, chunkDelayMs: 1 },
});
export function createFaultProxy({ serverFactory, upstream, fetchImpl, profile = 'stable' }) {
  const destination = new URL(upstream);
  if (destination.protocol !== 'https:') throw new Error('Testbed requires authenticated upstream');
  const p = FAULT_PROFILES[profile];
  if (!p) throw new Error('Unknown deterministic fault profile');
  const state = {
    offline: false,
    failBefore: 0,
    cutAfterBytes: null,
    requestCount: 0,
    upstreamCount: 0,
    responseBytes: 0,
    cuts: 0,
  };
  const server = serverFactory(async (req, res) => {
    state.requestCount++;
    if (state.offline || state.failBefore > 0) {
      if (!state.offline) state.failBefore--;
      state.cuts++;
      req.socket.destroy();
      return;
    }
    try {
      if (!/^\/api\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(req.url)) {
        res.writeHead(400);
        res.end();
        return;
      }
      let size = 0;
      const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 1500000) throw new Error('Bounded request exceeded');
        chunks.push(chunk);
      }
      await delay(p.delayMs + p.jitterMs[(state.requestCount - 1) % p.jitterMs.length]);
      if (state.offline) {
        state.cuts++;
        req.socket.destroy();
        return;
      }
      const headers = {};
      for (const key of ['content-type', 'authorization'])
        if (req.headers[key]) headers[key] = req.headers[key];
      state.upstreamCount++;
      const result = await fetchImpl(new URL(req.url, destination), {
        method: req.method,
        headers,
        ...(size ? { body: Buffer.concat(chunks) } : {}),
      });
      const bytes = Buffer.from(await result.arrayBuffer());
      res.writeHead(result.status, {
        'content-type': result.headers.get('content-type') || 'application/octet-stream',
        'content-length': bytes.length,
      });
      const cut = state.cutAfterBytes;
      state.cutAfterBytes = null;
      for (let i = 0; i < bytes.length; i += p.chunkBytes) {
        const end = Math.min(bytes.length, i + p.chunkBytes, cut ?? Infinity);
        if (end > i) {
          res.write(bytes.subarray(i, end));
          state.responseBytes += end - i;
        }
        if (cut !== null && end >= cut) {
          state.cuts++;
          await delay(5);
          res.destroy();
          return;
        }
        if (p.chunkDelayMs) await delay(p.chunkDelayMs);
      }
      res.end();
    } catch {
      if (!res.headersSent) res.writeHead(503);
      res.end();
    }
  });
  return { server, state };
}
