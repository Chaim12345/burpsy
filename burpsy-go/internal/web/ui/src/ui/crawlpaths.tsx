import { ChevronDown, ChevronRight, ChevronsDownUp, ChevronsUpDown, CornerDownRight, Link2, Sprout } from "lucide-react";
import { useMemo, useState } from "react";
import { collectBranch } from "../lib/tree-expand";
import type { CrawlFetch, CrawlRun } from "../lib/types.observe";
import { Badge, Button, Empty, type Tone } from "./primitives";

/**
 * The crawl-paths view: how the crawler reached each page, rather than where the page sits in the
 * path hierarchy.
 *
 * Burp offers this as the second of the site map's two views (burpsy-react-ui-tix). burpsy had no
 * such view, and the reason was not a missing component — the edge did not exist. The crawler's
 * frontier carried `foundAt` all along, documented "reporting only", and populated it on every
 * *refusal*: so the graph the crawler declined to walk was reconstructible and the graph it actually
 * walked was not. `Fetch.FoundAt` closes that, and this renders it.
 *
 * # What the two views answer
 *
 * The URL tree answers "what is on this host". This answers "what should have linked to the page I
 * expected and cannot find" — which is a different question, and the one an operator has when a
 * crawl came back smaller than they thought it would.
 *
 * # The three cases this must not flatten
 *
 * A **seed** has no `found_at`, and absent means seed, not unknown provenance. It is rendered with
 * its own marker rather than as a child of nothing.
 *
 * An **orphan** is a fetch whose `found_at` names a URL that is not itself in the fetch set. That is
 * a real state: the parent may have been refused, dropped at a limit, or excluded by the retention
 * query, so the child was reached from a page this run did not retain. Orphans are shown under a
 * heading that says so, because dropping them would understate coverage — the request was made — and
 * re-parenting them to a seed would assert a path that was never walked.
 *
 * A **duplicate** (`duplicate_of`) was fetched but not traversed, so it has no children by design
 * and that is not the same as being a leaf. It is labelled.
 */

interface PathNode {
 fetch: CrawlFetch;
 children: PathNode[];
}

interface CrawlTree {
 seeds: PathNode[];
 /** Fetches whose parent is not in this run's fetch set. Never merged into seeds. */
 orphans: PathNode[];
 /** Total fetches placed, so a caller can state coverage rather than imply it. */
 placed: number;
}

/**
 * Build the reachability forest.
 *
 * Cycles are possible in principle — a page linking back to its own referrer chain — so descent is
 * bounded by a visited set rather than trusting the data to be acyclic. A cycle in the input would
 * otherwise hang the render, and the input comes from a target, not from us.
 */
export function buildCrawlTree(fetches: CrawlFetch[]): CrawlTree {
 const byUrl = new Map<string, PathNode>();
 for (const fetch of fetches) {
  // First occurrence wins: the same URL can appear twice (a redirect and its target), and the
  // first is the one whose edge was followed.
  if (!byUrl.has(fetch.url)) byUrl.set(fetch.url, { fetch, children: [] });
 }

 const seeds: PathNode[] = [];
 const orphans: PathNode[] = [];

 for (const node of byUrl.values()) {
  const parentUrl = node.fetch.found_at;
  if (!parentUrl) {
   seeds.push(node);
   continue;
  }
  const parent = byUrl.get(parentUrl);
  if (!parent || parent === node) {
   // Parent not retained by this run, or a self-edge. Either way this node's path cannot be
   // drawn, and saying so is more use than hiding it.
   orphans.push(node);
   continue;
  }
  parent.children.push(node);
 }

 const byDepthThenUrl = (a: PathNode, b: PathNode) => a.fetch.depth - b.fetch.depth || a.fetch.url.localeCompare(b.fetch.url);

 // Sort every child list once, iteratively, so a deep tree cannot blow the stack on a recursive
 // sort — the depth here is whatever the target's link structure produced.
 const stack = [...seeds, ...orphans];
 const seen = new Set<PathNode>();
 while (stack.length > 0) {
  const node = stack.pop();
  if (!node || seen.has(node)) continue;
  seen.add(node);
  node.children.sort(byDepthThenUrl);
  stack.push(...node.children);
 }

 seeds.sort(byDepthThenUrl);
 orphans.sort(byDepthThenUrl);
 return { seeds, orphans, placed: byUrl.size };
}

function statusTone(status: number): Tone {
 if (status === 0) return "neutral";
 if (status >= 500) return "bad";
 if (status === 401 || status === 403) return "warn";
 if (status >= 400) return "neutral";
 if (status >= 300) return "info";
 return "good";
}

/** The path portion of a URL, for a row label. Falls back to the whole string on a bad URL. */
function shortLabel(url: string): string {
 try {
  const parsed = new URL(url);
  return parsed.pathname + parsed.search || "/";
 } catch {
  return url;
 }
}

function PathRow({
 node,
 indent,
 onSelect,
 collapsed,
 onToggle,
}: {
 node: PathNode;
 indent: number;
 onSelect?: (url: string) => void;
 /** URLs whose children are hidden (txnw). Absent from the set means open, the old default. */
 collapsed: ReadonlySet<string>;
 onToggle: (url: string) => void;
}): JSX.Element {
 const { fetch } = node;
 const isSeed = !fetch.found_at;
 const hasChildren = node.children.length > 0;
 const open = !collapsed.has(fetch.url);
 return (
  <>
   {/* The toggle sits beside the selectable row, not inside it: a button inside a role="button"
          row is nested-interactive, which a screen reader cannot operate. */}
   <div className="crawl-path-line" style={{ paddingLeft: `calc(${indent} * var(--sp-4, 12px))` }}>
    {hasChildren ? (
     <button
      type="button"
      className="tree-toggle"
      aria-expanded={open}
      aria-label={`${open ? "Collapse" : "Expand"} the ${node.children.length} page${node.children.length === 1 ? "" : "s"} reached from ${shortLabel(fetch.url)}`}
      onClick={() => onToggle(fetch.url)}
     >
      {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
     </button>
    ) : (
     <span className="tree-toggle" aria-hidden="true" />
    )}
    <div
     className="crawl-path-row"
     role={onSelect ? "button" : undefined}
     tabIndex={onSelect ? 0 : undefined}
     onClick={onSelect ? () => onSelect(fetch.url) : undefined}
     onKeyDown={
      onSelect
       ? (event) => {
          if (event.key === "Enter" || event.key === " ") {
           event.preventDefault();
           onSelect(fetch.url);
          }
         }
       : undefined
     }
    >
     {/* The icon component takes no title prop, so the tooltip lives on a wrapper. */}
     {isSeed ? (
      <span title="A seed: the crawl was pointed at this">
       <Sprout size={12} aria-hidden="true" />
      </span>
     ) : (
      <CornerDownRight size={12} aria-hidden="true" />
     )}
     <Badge tone={statusTone(fetch.status)}>{fetch.status === 0 ? "no status" : fetch.status}</Badge>
     <code title={fetch.url}>
      {fetch.method === "GET" ? "" : `${fetch.method} `}
      {shortLabel(fetch.url)}
     </code>
     {/* The edge's own label. Shown rather than the parent URL, which is already the row above. */}
     {fetch.link_text ? (
      <span className="cell-dim crawl-path-text">
       <Link2 size={11} aria-hidden="true" /> {fetch.link_text}
      </span>
     ) : null}
     {fetch.duplicate_of ? (
      <Badge tone="neutral" title={`Same contents as ${fetch.duplicate_of}, so its links were not queued again`}>
       duplicate
      </Badge>
     ) : null}
     {fetch.retention_excluded ? (
      <Badge tone="warn" title="Captured and scanned, but the retention query did not match, so it was not traversed">
       not traversed
      </Badge>
     ) : null}
     {hasChildren && !open ? <span className="cell-dim">{node.children.length} hidden</span> : null}
    </div>
   </div>
   {open
    ? node.children.map((child) => (
       <PathRow key={child.fetch.url} node={child} indent={indent + 1} onSelect={onSelect} collapsed={collapsed} onToggle={onToggle} />
      ))
    : null}
  </>
 );
}

export function CrawlPathsView({ runs, onSelect }: { runs: CrawlRun[]; onSelect?: (url: string) => void }): JSX.Element {
 // The most recent run that actually fetched anything. A running crawl with no fetches yet is not
 // the same as a finished one that found nothing, and neither is an absence of crawls.
 const run = useMemo(() => runs.find((candidate) => (candidate.report?.fetches ?? []).length > 0), [runs]);
 const tree = useMemo(() => buildCrawlTree(run?.report?.fetches ?? []), [run]);
 // Burp's crawl-paths "Expand all" / "Collapse all" (BurpClass4683, txnw). Open is the default, as
 // it always was; the set holds the URLs the operator closed.
 const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(() => new Set());
 const toggle = (url: string) =>
  setCollapsed((current) => {
   const next = new Set(current);
   if (next.has(url)) next.delete(url);
   else next.add(url);
   return next;
  });
 const collapseAll = () => {
  const keys = [...tree.seeds, ...tree.orphans].flatMap(
   (root) =>
    collectBranch(
     root,
     (node) => node.children,
     (node) => node.fetch.url,
     Number.POSITIVE_INFINITY,
    ).keys,
  );
  setCollapsed(new Set(keys));
 };

 if (runs.length === 0) {
  return (
   <Empty
    title="No crawl has run"
    detail="Crawl paths show how the crawler reached each page, so there is nothing to show until a crawl has run. Start one from the site map or from a history row."
   />
  );
 }
 if (!run) {
  const running = runs.some((candidate) => candidate.state === "running");
  return (
   <Empty
    title={running ? "The crawl has not fetched anything yet" : "The crawl fetched nothing"}
    detail={
     running
      ? "Paths appear as pages are fetched. An empty view here means not-yet, not that the target is empty."
      : "No request was completed, so there is no path to draw. The crawl's own report says which limit or refusal accounts for that."
    }
   />
  );
 }

 return (
  <div className="crawl-paths">
   <div className="crawl-paths-summary cell-dim">
    Run #{run.task_id} · {tree.placed} fetches · {tree.seeds.length} seed
    {tree.seeds.length === 1 ? "" : "s"}
    {tree.orphans.length > 0 ? ` · ${tree.orphans.length} whose referring page this run did not retain` : ""}
    <span className="crawl-paths-actions">
     <Button variant="quiet" size="small" disabled={collapsed.size === 0} onClick={() => setCollapsed(new Set())}>
      <ChevronsUpDown size={12} />
      Expand all
     </Button>
     <Button variant="quiet" size="small" onClick={collapseAll}>
      <ChevronsDownUp size={12} />
      Collapse all
     </Button>
    </span>
   </div>

   {tree.seeds.map((node) => (
    <PathRow key={node.fetch.url} node={node} indent={0} onSelect={onSelect} collapsed={collapsed} onToggle={toggle} />
   ))}

   {tree.orphans.length > 0 ? (
    <>
     {/* Shown, never dropped and never re-parented. The request was made; its path cannot be
              drawn because the page it was found on was refused, dropped at a limit, or excluded by
              the retention query. Hiding these understates coverage. */}
     <div className="crawl-paths-heading">
      Reached from a page this run did not retain
      <span className="cell-dim"> — refused, dropped at a limit, or excluded by the retention query. The request was still made.</span>
     </div>
     {tree.orphans.map((node) => (
      <PathRow key={node.fetch.url} node={node} indent={0} onSelect={onSelect} collapsed={collapsed} onToggle={toggle} />
     ))}
    </>
   ) : null}
  </div>
 );
}
