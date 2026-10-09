/**
 * Expand / collapse a whole branch of a tree (txnw): Burp's site-map "Expand branch" /
 * "Collapse branch" (siteMapTreeExpandBranchMenuItem, BurpClass2547) and the crawl-paths and
 * Inspector "Expand all" / "Collapse all".
 *
 * Expanding is capped. A large site map can hold tens of thousands of nodes, and opening all of
 * them at once renders every one of them (the tree is not virtualized), which freezes the console
 * for exactly the operator who most needed the shortcut. The walk is breadth-first, so the cap
 * keeps the shallow levels — the part an operator reads first — and the caller says how many it
 * left closed. Collapsing is never capped: closing nodes renders fewer rows, not more.
 */

export const EXPAND_CAP = 5000;

export interface BranchWalk {
  /** Keys of the nodes with children, root first, breadth-first, at most `cap` of them. */
  keys: string[];
  /** How many nodes with children the whole branch has. */
  total: number;
  truncated: boolean;
}

export function collectBranch<N>(
  root: N,
  childrenOf: (node: N) => readonly N[] | undefined,
  keyOf: (node: N) => string,
  cap: number = EXPAND_CAP,
): BranchWalk {
  const keys: string[] = [];
  let total = 0;
  const queue: N[] = [root];
  const seen = new Set<string>();
  for (let i = 0; i < queue.length; i += 1) {
    const node = queue[i]!;
    const key = keyOf(node);
    // A cycle in hostile input would otherwise walk forever.
    if (seen.has(key)) continue;
    seen.add(key);
    const children = childrenOf(node) ?? [];
    if (children.length === 0) continue;
    total += 1;
    if (keys.length < cap) keys.push(key);
    queue.push(...children);
  }
  return { keys, total, truncated: total > keys.length };
}

/** The expansion map with every key in `keys` set open or closed. */
export function setExpandedKeys(current: Readonly<Record<string, boolean>>, keys: readonly string[], open: boolean): Record<string, boolean> {
  const next = { ...current };
  for (const key of keys) next[key] = open;
  return next;
}
