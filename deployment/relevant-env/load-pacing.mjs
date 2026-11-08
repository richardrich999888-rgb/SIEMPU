// Laboratory offered-load scheduling, shared by every worker of one session.
// This does not change authority limits or retry/refuse handling.
export function createLoadPacer(
  intervalMs,
  { clock = () => performance.now(), wait = (ms) => new Promise((r) => setTimeout(r, ms)) } = {},
) {
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1 || intervalMs > 60000)
    throw new RangeError('LOAD_INTERVAL');
  let next = 0;
  return async (deadline = Infinity) => {
    const slot = Math.max(clock(), next);
    if (slot >= deadline) return false;
    next = slot + intervalMs;
    const delay = slot - clock();
    if (delay > 0) await wait(delay);
    return clock() < deadline;
  };
}
