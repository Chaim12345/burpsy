/**
 * The command palette's recency ledger (burpsy-react-ui-daj4).
 *
 * Burp's palette floats recently-run commands to the top of the empty-query list, and the
 * omission was felt the moment an operator ran anything a second time: a command used fifty
 * times a session ranked exactly where it did on first open. The ledger records the order in
 * which distinct commands were last run and survives reloads, because a palette habit is a
 * session-long property, not a per-open one.
 *
 * Stored as a monotonically increasing sequence number per action id in localStorage — the
 * same class of preference the workspace store already persists, kept here rather than in the
 * zustand store so the palette stays a leaf with no store import cycle.
 */

const KEY = "burpsy.palette-recency";
const MAX_ENTRIES = 64;

function read(): Record<string, number> {
 try {
  const raw = window.localStorage.getItem(KEY);
  if (!raw) return {};
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
  const record: Record<string, number> = {};
  for (const [id, seq] of Object.entries(parsed as Record<string, unknown>)) {
   if (typeof seq === "number") record[id] = seq;
  }
  return record;
 } catch {
  // A corrupt or unreadable ledger is treated as empty rather than fatal: the palette's
  // ordering is a preference, and a preference that cannot be read must not break the
  // palette the way a thrown read would.
  return {};
 }
}

function write(record: Record<string, number>): void {
 try {
  // Bound the ledger: an operator who never repeats a command would otherwise grow it for
  // the life of the profile. The least-recently-run entries are the ones dropped, and 64
  // covers every command anyone actually cycles through.
  const entries = Object.entries(record).sort((a, b) => a[1] - b[1]).slice(-MAX_ENTRIES);
  window.localStorage.setItem(KEY, JSON.stringify(Object.fromEntries(entries)));
 } catch {
  // localStorage unavailable (private mode, quota): ordering simply never persists.
 }
}

let counter = 0;

/**
 * The current ledger. A test seam: zustand's persist API is unreachable in the unit-test
 * environment (see persistedWorkspace's note in store.ts) and a bare localStorage read has the
 * same problem — so the rule "most-recently-run floats up on an equal rank" is asserted
 * through this read rather than through DOM order in a mounted palette.
 */
export function paletteRecency(): Record<string, number> {
 return read();
}

/** Record that an action just ran. Its sequence number makes it the most recent of all. */
export function recordPaletteUse(actionId: string): void {
 const record = read();
 for (const seq of Object.values(record)) counter = Math.max(counter, seq);
 counter += 1;
 record[actionId] = counter;
 write(record);
}
