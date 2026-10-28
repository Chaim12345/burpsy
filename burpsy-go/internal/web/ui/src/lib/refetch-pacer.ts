/**
 * Backpressure for a refetch whose cost grows with the data it returns.
 *
 * The server pushes an "issues changed" event every ~150ms while findings are being recorded, and
 * each one refetches the whole list. With tens of thousands of rows one refetch is milliseconds of
 * network plus a large structured clone, structural sharing and a tree rebuild on the main thread,
 * so back-to-back refetches leave the page no idle time. This does not add a fixed delay: the wait
 * is `factor` times how long the last fetch took, measured here, so a small list refetches at once
 * and a big one yields the thread in proportion to what it cost. Only the gap since the last
 * completion counts, so an invalidation that cancels and restarts the fetch does not extend it.
 */
export type RefetchPacer = <T>(run: () => Promise<T>, signal?: AbortSignal) => Promise<T>;

export function createRefetchPacer(options: { factor?: number; maxWaitMs?: number; now?: () => number } = {}): RefetchPacer {
 const factor = options.factor ?? 6;
 const maxWaitMs = options.maxWaitMs ?? 4000;
 const now = options.now ?? (() => performance.now());
 let lastDone = Number.NEGATIVE_INFINITY;
 let lastCost = 0;
 return async (run, signal) => {
  const wait = Math.min(maxWaitMs, lastCost * factor) - (now() - lastDone);
  if (wait > 0) {
   await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, wait);
    signal?.addEventListener(
     "abort",
     () => {
      clearTimeout(timer);
      reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
     },
     { once: true },
    );
   });
  }
  const started = now();
  try {
   return await run();
  } finally {
   const finished = now();
   lastCost = finished - started;
   lastDone = finished;
  }
 };
}
