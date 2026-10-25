/**
 * One-shot seeds handed from a context menu to the page it navigates to (burpsy-react-ui-gupj).
 *
 * Burp's Engagement tools open another tool *already filled in* with what was right-clicked.
 * burpsy's pages build their forms from local `useState("")`, so a menu row that only navigated
 * would drop the operator on an empty form — the row would look like it worked and the seeding
 * would silently not have happened.
 *
 * Deliberately not part of the app store, and deliberately not persisted:
 *
 *  - A seed is consumed by the next mount of one page and then gone. Putting it in the store
 *    would make it durable state that two pages could disagree about, and every later visit to
 *    Content discovery would arrive pre-filled with a URL from a menu click nobody remembers.
 *  - Persisting it would be worse for the same reason the Intruder menu refuses to persist its
 *    start command: a form that arrives pre-aimed at a host on every page load is a target the
 *    operator did not choose this session.
 *
 * `take` is destructive on purpose. A seed that survived being read would re-fill the form every
 * time the page remounted, overwriting whatever the operator had typed since.
 */

/** The seeds this module carries. A union rather than an open string, so a typo is a type error. */
export type SeedKey = "discovery-target";

const seeds = new Map<SeedKey, string>();

/** Leave a seed for the next mount of the page that reads `key`. */
export function putSeed(key: SeedKey, value: string): void {
  seeds.set(key, value);
}

/**
 * Read and clear the seed, or null when the page was opened directly rather than from a menu.
 *
 * Null is the ordinary case and must not be rendered as an empty seed that "was applied" — the
 * caller uses it as a `useState` initial value, where null simply means the form starts blank.
 */
export function takeSeed(key: SeedKey): string | null {
  const value = seeds.get(key);
  if (value === undefined) return null;
  seeds.delete(key);
  return value;
}

/** Test and teardown helper: drop anything left unconsumed. */
export function clearSeeds(): void {
  seeds.clear();
}
