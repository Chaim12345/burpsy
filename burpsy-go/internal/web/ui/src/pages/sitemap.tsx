import { ChevronDown, ChevronRight, Columns3, Combine, Crosshair, ExternalLink, Folder, FolderOpen, Globe, Repeat2, Search, ShieldCheck, X } from "lucide-react";
import { useMemo, useState, type KeyboardEvent } from "react";
import { api, copyToClipboard, formatBytes, formatDuration, json, mimeLabel, relativeTime, statusTone } from "../lib/api";
import { useDebounced, useInvalidate, useHistory, useMessage } from "../lib/data";
import { useCrawls, useDeleteSitemap, usePassiveScanBranch, useSitemapDetailed, useStartCrawl } from "../lib/data.observe";
import { useIssuesDetailed } from "../lib/data.attack";
import type { FindingDetail } from "../lib/types.attack";
import { exchangeUrl, useExchangeActions, useSendShortcuts } from "../lib/actions";
import { useApp } from "../lib/store";
import { toast } from "sonner";
import type { SiteNodeDetail as SiteNode } from "../lib/types.observe";
import type { Exchange } from "../lib/types";
import { CrawlLauncher } from "../ui/crawl";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader, RefreshButton, SectionHeading, SplitPane } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, IconButton, Input, Modal, Toolbar, Tooltip } from "../ui/primitives";
import { BucketMenu } from "../ui/column-visibility-menu";
import { Checkbox } from "../ui/primitives";
import { ContextMenu, type MenuGroup } from "../ui/menu";
import { MenuRow, SimpleTable, VirtualTable, type Column } from "../ui/table";
import { CrawlPathsView } from "../ui/crawlpaths";
import { cn } from "../lib/cn";

interface FlatRow {
 node: SiteNode;
 depth: number;
 host: string;
 key: string;
 parentKey: string | null;
 hasChildren: boolean;
 expanded: boolean;
}

/** The two bucket menus, in history's shape (9my): multi-select, empty set = no restriction. The
 * MIME words are mimeLabel's vocabulary — what the Type column already shows — so the filter and
 * the display can never disagree about what a bucket covers. */
const SITEMAP_MIME_BUCKETS = [
 { value: "html", label: "HTML" },
 { value: "json", label: "JSON" },
 { value: "xml", label: "XML" },
 { value: "javascript", label: "JavaScript" },
 { value: "css", label: "CSS" },
 { value: "image", label: "Images" },
];

const SITEMAP_STATUS_BUCKETS = [
 { value: "2", label: "2xx success" },
 { value: "3", label: "3xx redirect" },
 { value: "4", label: "4xx client error" },
 { value: "5", label: "5xx server error" },
];

/** The server states each node's exact identity in `key` — the host for a host node, host + NUL +
 * path below that. This page used to build the same string itself because the server only
 * offered a colliding hash; taking the server's means an expand/collapse key and a server-side
 * node can never disagree about which node is which. */
function nodeKey(node: SiteNode): string {
 return node.key;
}

/**
 * The axes the site-map filter bar can restrict the tree on (burpsy-react-ui-36d). mimes and
 * statuses are the MIME words and status classes ("2", "4", …) checked in the filter menus;
 * the booleans mirror Burp's request-type group. Empty sets mean "no restriction on this axis",
 * so a fresh page hides nothing — the same polarity history's bucket filters use.
 */
export interface SitemapFilter {
 mimes: string[];
 statuses: string[];
 scopeOnly: boolean;
 requestedOnly: boolean;
 paramsOnly: boolean;
 hideNotFound: boolean;
}

export const NO_SITEMAP_FILTER: SitemapFilter = {
 mimes: [],
 statuses: [],
 scopeOnly: false,
 requestedOnly: false,
 paramsOnly: false,
 hideNotFound: false,
};

/** The boolean axes bind every node including folders — a folder can be in scope without anything
 * having requested it, so these are answered per node and failing one prunes the branch. */
function nodeMatchesBooleanAxes(node: SiteNode, f: SitemapFilter): boolean {
 if (f.scopeOnly && !node.in_scope) return false;
 if (f.requestedOnly && !node.requested) return false;
 if (f.paramsOnly && !(node.params && node.params.length > 0)) return false;
 // Burp's "Hide not-found items" drops nodes whose every response was 4xx. A node aggregates its
 // own path's statuses, so this is only meaningful where some response exists.
 if (f.hideNotFound && node.statuses.length > 0 && node.statuses.every((s) => s >= 400 && s < 500)) return false;
 return true;
}

/** Whether one node's own set-aggregation (status classes, MIME words) satisfies the checked
 * buckets. Asked per node AND, via subtreeMatches, of every descendant — a synthesised folder's own
 * Statuses is empty because the folder path was never requested, so the folder-level question is
 * "matches here or matches below". */
function nodeMatchesSetAxes(node: SiteNode, f: SitemapFilter): boolean {
 if (f.statuses.length > 0 && !node.statuses.some((s) => f.statuses.includes(String(s)[0] ?? ""))) return false;
 if (f.mimes.length > 0 && !(node.mimes ?? []).some((m) => f.mimes.includes(m))) return false;
 return true;
}

/** A node (or one of its descendants) matches the term and every checked filter axis. One predicate
 * so the visibility pass and the auto-expand pass agree on what counts as a match. Boolean axes are
 * per-node (a folder is not requested and has no scope answer of its own); set axes are satisfied by
 * the node's own aggregation or by any descendant's. */
export function subtreeMatches(node: SiteNode, term: string, f: SitemapFilter): boolean {
 if (!nodeMatchesBooleanAxes(node, f)) return false;
 if (!nodeMatchesSetAxes(node, f) && !(node.children ?? []).some((child) => subtreeMatches(child, term, f))) return false;
 if (term && !(node.path.toLowerCase().includes(term) || node.segment.toLowerCase().includes(term))) {
  return (node.children ?? []).some((child) => subtreeMatches(child, term, f));
 }
 return true;
}

/** Whether any filter axis is active, so the flatten pass knows to force matching branches open —
 * a match inside a collapsed branch must be reachable, never silently hidden. */
function filterActive(f: SitemapFilter): boolean {
 return f.mimes.length > 0 || f.statuses.length > 0 || f.scopeOnly || f.requestedOnly || f.paramsOnly || f.hideNotFound;
}

/** Flattens the visible tree into a single ordered list, honouring expansion state and the active
 * filter. A node with no match in its whole subtree is dropped entirely rather than shown greyed out. */
function flatten(
 nodes: SiteNode[],
 depth: number,
 host: string,
 parentKey: string | null,
 term: string,
 f: SitemapFilter,
 expanded: Record<string, boolean>,
): FlatRow[] {
 const out: FlatRow[] = [];
 const narrowed = term !== "" || filterActive(f);
 for (const node of nodes) {
  if (!subtreeMatches(node, term, f)) continue;
  const hasChildren = (node.children ?? []).length > 0;
  const rowHost = depth === 0 ? node.path : host;
  // Filtering forces a matching branch open so the match underneath is reachable; otherwise fall
  // back to the operator's own toggle, defaulting to the first two levels expanded.
  const key = nodeKey(node);
  const isExpanded = narrowed ? true : expanded[key] ?? depth < 2;
  out.push({ node, depth, host: rowHost, key, parentKey, hasChildren, expanded: isExpanded });
  if (hasChildren && isExpanded) out.push(...flatten(node.children ?? [], depth + 1, rowHost, key, term, f, expanded));
 }
 return out;
}

interface IndexedNode {
 node: SiteNode;
 host: string;
 depth: number;
}

function buildIndex(nodes: SiteNode[], depth: number, host: string, into: Map<string, IndexedNode>): void {
 for (const node of nodes) {
  const rowHost = depth === 0 ? node.path : host;
  into.set(nodeKey(node), { node, host: rowHost, depth });
  if ((node.children ?? []).length) buildIndex(node.children ?? [], depth + 1, rowHost, into);
 }
}

/** The path an exchange occupies in the tree: its path with any query string removed and its
 * trailing slash normalised away, matching how the server keys a node. */
function treePath(raw: string): string {
 let p = raw.split("?")[0] ?? "/";
 if (!p.startsWith("/")) p = `/${p}`;
 while (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
 return p;
}

/** Burp shows a folder's whole subtree, not just the folder itself, so a node selection matches its
 * own path and every descendant of it. */
function underNode(exchangePath: string, nodePath: string): boolean {
 const p = treePath(exchangePath);
 if (nodePath === "/") return p === "/";
 return p === nodePath || p.startsWith(`${nodePath}/`);
}

function TreeRow({
 row,
 selected,
 cursor,
 onToggle,
 onSelect,
 getMenuGroups,
}: {
 row: FlatRow;
 selected: boolean;
 cursor: boolean;
 onToggle: () => void;
 onSelect: () => void;
 /** Right-click menu per row; Burp's tree menu carries host/branch actions (burpsy-react-ui-gfx). */
 getMenuGroups?: (row: FlatRow) => MenuGroup[];
}): JSX.Element {
 const { node, depth, hasChildren, expanded } = row;
 const isHost = depth === 0;
 // A folder nothing requested is dimmed, the way Burp greys a path it inferred rather than saw.
 const inferred = !isHost && !node.requested;
 // Out-of-scope traffic is still evidence, so it stays in the map and is dimmed rather than hidden.
 // The state is never carried by the dimming alone: it is in the row's accessible name and title
 // too, and hosts — where the decision actually gets made — say it in visible text.
 const outOfScope = !node.in_scope;
 return (
  <ContextMenu groups={getMenuGroups?.(row) ?? []}>
   <div
    role="treeitem"
    aria-level={depth + 1}
    aria-expanded={hasChildren ? expanded : undefined}
    aria-selected={selected}
    aria-label={outOfScope ? `${node.segment || "/"} — out of scope` : undefined}
    tabIndex={-1}
    data-node-key={node.key}
    className={cn("tree-row", selected && "active", outOfScope && "tree-row-out-of-scope")}
    style={{ paddingLeft: `${8 + depth * 14}px`, outline: cursor ? "2px solid var(--accent)" : undefined, outlineOffset: cursor ? -2 : undefined }}
    onClick={onSelect}
   >
    {/* A leaf gets a spacer, not a disabled button. The button was rendered unconditionally and a
          leaf's copy had no children to describe, so it carried no accessible name — a nameless
          control a screen reader still has to announce. Matches how the Issues tree renders its
          leaves. */}
    {hasChildren ? (
     <button
      type="button"
      className="tree-toggle"
      aria-label={expanded ? `Collapse ${node.segment}` : `Expand ${node.segment}`}
      aria-expanded={expanded}
      onClick={(event) => {
       event.stopPropagation();
       onToggle();
      }}
     >
      {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
     </button>
    ) : (
     <span className="tree-toggle" aria-hidden="true" />
    )}
    <span className="tree-row-icon" aria-hidden="true">
     {isHost ? <Globe size={12} /> : hasChildren ? expanded ? <FolderOpen size={12} /> : <Folder size={12} /> : null}
    </span>
    <span
     className={cn("tree-row-label", inferred && "cell-dim")}
     title={`${node.path}${inferred ? " (no request to this path itself)" : ""}${outOfScope ? " — out of scope: the tools will not touch this" : ""}`}
    >
     {node.segment || "/"}
    </span>
    <span className="tree-row-meta">
     {outOfScope && isHost ? <span className="tree-row-scope">out of scope</span> : null}
     {node.subtree_issues ? (
      <span
       className={`sev-dot sev-${(node.worst_severity ?? "").toLowerCase()}`}
       title={`${node.subtree_issues} finding(s) here or below — worst: ${node.worst_severity}`}
       aria-label={`${node.subtree_issues} findings, worst ${node.worst_severity}`}
      />
     ) : null}
     {(node.params ?? []).length ? (
      <span className="cell-dim tree-row-params" title={`Query parameters: ${(node.params ?? []).join(", ")}`}>
       ?{(node.params ?? []).join(",")}
      </span>
     ) : null}
     <span className="tree-row-count cell-num" title="exchanges in this subtree">
      {node.subtree_exchanges || ""}
     </span>
    </span>
   </div>
  </ContextMenu>
 );
}

/** Burp's severity colours for the inline node-findings list (burpsy-react-ui-zzz). */
function findingTone(severity: string): "bad" | "warn" | "info" | "neutral" {
 switch (severity) {
  case "Critical":
  case "High":
   return "bad";
  case "Medium":
   return "warn";
  case "Low":
   return "info";
  default:
   return "neutral";
 }
}

/** Deduplicated absolute URLs for every captured exchange under a tree row (burpsy-react-ui-gfx). */
function urlsUnder(row: FlatRow, exchanges: Exchange[]): string[] {
 const seen = new Set<string>();
 const out: string[] = [];
 for (const ex of exchanges) {
  if (ex.host !== row.host) continue;
  if (row.depth > 0 && !underNode(ex.path, row.node.path)) continue;
  const url = exchangeUrl(ex);
  if (!seen.has(url)) {
   seen.add(url);
   out.push(url);
  }
 }
 return out;
}

export function SiteMapPage(): JSX.Element {
 const setHistoryQuery = useApp((state) => state.setHistoryQuery);
 const setRoute = useApp((state) => state.setRoute);
 // The scope cache, invalidated when a node-aimed add-to-scope lands (dpk): the scope page and the
 // "In scope only" toggles elsewhere must show the new rule without a manual refresh.
 const scopeInvalidate = useInvalidate();
 const startCrawl = useStartCrawl();

 const [filter, setFilter] = useState("");
 // The rest of Burp's filter bar (burpsy-react-ui-36d): MIME buckets, status classes and the
 // request-type toggles. Client-side over the node aggregations the server already sends — the
 // node carries its subtree's methods/statuses/mimes/params, so filtering the tree costs no new
 // endpoint and no response bodies.
 const [sfilter, setSfilter] = useState<SitemapFilter>(NO_SITEMAP_FILTER);
 // Delete host/branch/item (burpsy-react-ui-10e). One confirm modal, the shape history's clear
 // uses; the wording says what actually happens — the branch leaves the map, the exchanges stay.
 // host is the FlatRow's resolved rowHost — the connection's hostname — not node.segment, which
 // for depth>0 rows is the last path component. The server keys suppression on host:port:tls, so
 // sending the segment would silently no-op.
 const [confirmDelete, setConfirmDelete] = useState<undefined | { node: SiteNode; host: string; kind: "host" | "branch" | "item" }>(undefined);
 /**
  * Which of Burp's two site-map views is showing.
  *
  * Kept as page state rather than persisted: the URL view is the one an operator wants on arrival,
  * and a remembered "crawl paths" would greet them with an empty panel on a session where nothing
  * has crawled yet — which reads as a broken site map rather than as a remembered preference.
  */
 const [view, setView] = useState<"urls" | "paths">("urls");
 const crawls = useCrawls();
 const passiveScan = usePassiveScanBranch();
 const [expanded, setExpanded] = useState<Record<string, boolean>>({});
 const [selectedId, setSelectedId] = useState<string | null>(null);
 const [cursorId, setCursorId] = useState<string | null>(null);
 const [selectedExchange, setSelectedExchange] = useState<number | null>(null);
 const [inspector, setInspector] = useState(false);
 const [showIssues, setShowIssues] = useState(false);
 const issues = useIssuesDetailed();

 const debouncedFilter = useDebounced(filter, 250);
 const term = debouncedFilter.trim().toLowerCase();
 // The page-level twin of flatten's `narrowed`: the empty state must name the filter, not the
 // capture, when a checked bucket emptied the tree.
 const narrowed = term !== "" || filterActive(sfilter);

 const runDelete = () => {
  if (!confirmDelete) return;
  const { node, host, kind } = confirmDelete;
  removeNode.mutate(
   { host, port: node.port, tls: node.tls, path: kind === "host" ? "" : node.path, kind },
   {
    onSuccess: ({ kind: doneKind }) => {
     setConfirmDelete(undefined);
     toast.success(doneKind === "host" ? `Suppressed host ${node.segment}` : `Suppressed ${doneKind} ${node.path}`);
    },
    onError: (cause) => toast.error(`Could not delete: ${cause.message}`),
   },
  );
 };

 const { data, error, isFetching, refetch } = useSitemapDetailed();
 const removeNode = useDeleteSitemap();
 // The same cache key the HTTP history tab uses, so selecting a node costs no extra request.
 const { data: history } = useHistory("", 1000);
 const actions = useExchangeActions();
 const tree = data?.tree ?? [];

 const rows = useMemo(() => flatten(tree, 0, "", null, term, sfilter, expanded), [tree, term, sfilter, expanded]);
 const index = useMemo(() => {
  const map = new Map<string, IndexedNode>();
  buildIndex(tree, 0, "", map);
  return map;
 }, [tree]);

 const cursorIndex = useMemo(() => (cursorId === null ? -1 : rows.findIndex((row) => row.key === cursorId)), [rows, cursorId]);

 const toggle = (row: FlatRow) => {
  if (!row.hasChildren) return;
  setExpanded((current) => ({ ...current, [row.key]: !row.expanded }));
 };

 const moveCursor = (delta: number) => {
  if (!rows.length) return;
  const from = cursorIndex < 0 ? 0 : cursorIndex;
  const next = Math.min(rows.length - 1, Math.max(0, from + delta));
  const row = rows[next];
  if (row) setCursorId(row.key);
 };

 const select = (key: string) => {
  setSelectedId(key);
  setCursorId(key);
  // The previous node's exchange is meaningless against a different node's table.
  setSelectedExchange(null);
  setShowIssues(false);
 };

 const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
  const current = cursorIndex >= 0 ? rows[cursorIndex] : undefined;
  switch (event.key) {
   case "ArrowDown":
    event.preventDefault();
    moveCursor(1);
    break;
   case "ArrowUp":
    event.preventDefault();
    moveCursor(-1);
    break;
   case "ArrowRight":
    event.preventDefault();
    if (!current) break;
    if (current.hasChildren && !current.expanded) toggle(current);
    else moveCursor(1);
    break;
   case "ArrowLeft":
    event.preventDefault();
    if (!current) break;
    if (current.hasChildren && current.expanded) toggle(current);
    else if (current.parentKey !== null) setCursorId(current.parentKey);
    break;
   case "Enter":
    event.preventDefault();
    if (current) select(current.key);
    break;
   default:
    break;
  }
 };

 const selected = selectedId === null ? null : (index.get(selectedId) ?? null);

 /** The exchanges the selected node covers: a host node takes everything on that host, a path node
  * takes its own path and its descendants. */
 const nodeExchanges = useMemo<Exchange[]>(() => {
  if (!selected) return [];
  const all = history ?? [];
  if (selected.depth === 0) return all.filter((ex) => ex.host === selected.host);
  return all.filter((ex) => ex.host === selected.host && underNode(ex.path, selected.node.path));
 }, [history, selected]);

 // burpsy-react-ui-zzz: findings attributed to this node's exchanges through occurrence
 // exchange ids - the precise link the tree's severity dots summarise. Host-only matching
 // would credit this node with findings observed on sibling paths.
 const nodeFindings = useMemo<FindingDetail[]>(() => {
  if (!selected || !issues.data) return [];
  const ids = new Set(nodeExchanges.map((ex) => ex.id));
  return (issues.data.findings ?? []).filter((finding) =>
   (finding.occurrences ?? []).some((occurrence) => ids.has(occurrence.exchange_id)),
  );
 }, [selected, issues.data, nodeExchanges]);

 const activeExchange = useMemo(
  () => nodeExchanges.find((ex) => ex.id === selectedExchange) ?? null,
  [nodeExchanges, selectedExchange],
 );
 const request = useMessage(activeExchange?.request);
 const response = useMessage(activeExchange?.response ?? null);

 // Burp's send-to chords are scoped to a table row, not to one tool. Without these, ctrl+R on a
 // selected Site map row reached the browser and reloaded the console — losing the operator's
 // tree position and selection to reach the page that has meant "send to Repeater" for years.
 useSendShortcuts(activeExchange);

 const filterHistory = (entry: IndexedNode) => {
  // Quoted so a path carrying an operator character (`?q=a<b`) reaches the parser as one string
  // value rather than terminating the bare word early; the two escapes the grammar defines are
  // applied so a path containing a quote cannot close the literal and change what is filtered on.
  const literal = entry.node.path.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const query = entry.depth === 0 ? `host = ${entry.host}` : `host = ${entry.host} AND path ~ "${literal}"`;
  setHistoryQuery(query);
  setRoute("history");
 };

 const columns = useMemo<Column<Exchange>[]>(
  () => [
   { accessorKey: "id", header: "#", size: 58, cell: (info) => <span className="cell-num">{info.getValue<number>()}</span> },
   {
    accessorKey: "method",
    header: "Method",
    size: 74,
    cell: (info) => <Badge tone="info">{info.getValue<string>()}</Badge>,
   },
   {
    accessorKey: "path",
    header: "URL",
    size: 300,
    cell: (info) => <code title={info.getValue<string>()}>{info.getValue<string>()}</code>,
   },
   {
    id: "params",
    header: "Params",
    size: 70,
    accessorFn: (row) => (row.path.includes("?") ? "yes" : ""),
    cell: (info) => (info.getValue<string>() ? <Badge tone="info">params</Badge> : <span className="cell-dim">—</span>),
   },
   {
    accessorKey: "status",
    header: "Status",
    size: 78,
    cell: (info) => {
     const value = info.getValue<number | null>();
     return value === null ? <Badge>pending</Badge> : <Badge tone={statusTone(value)}>{value}</Badge>;
    },
   },
   {
    accessorKey: "response_len",
    header: "Length",
    size: 84,
    cell: (info) => <span className="cell-num">{formatBytes(info.getValue<number>())}</span>,
   },
   {
    accessorKey: "mime",
    header: "MIME",
    size: 90,
    // Same dead column as History's, populated by the same fix, and rendered through the same
    // helper so the two pages cannot come to disagree about what an empty MIME means: an em dash
    // when no response arrived, "untyped" when one did and named no Content-Type.
    cell: (info) => <span className="cell-dim">{mimeLabel(info.row.original)}</span>,
   },
   {
    // burpsy-react-ui-esi: History's Comment column over the same exchanges - the note text
    // lives on the row, so this is display, not a second store.
    id: "comment",
    header: "Comment",
    size: 180,
    accessorFn: (row: Exchange) => row.notes ?? "",
    cell: (info) => {
     const text = info.getValue<string>();
     return text === "" ? <span className="cell-dim">—</span> : <span title={text}>{text}</span>;
    },
   },
   {
    accessorKey: "duration_ms",
    header: "Time",
    size: 74,
    cell: (info) => <span className="cell-num">{formatDuration(info.getValue<number>())}</span>,
   },
   {
    accessorKey: "started_ms",
    header: "Age",
    size: 80,
    cell: (info) => <span className="cell-dim">{relativeTime(info.getValue<number>())}</span>,
   },
  ],
  [],
 );

 const treePane = (
  <div className="pane">
   <Toolbar className="pane-toolbar">
    <div className="search-field">
     <Search size={15} />
     <Input aria-label="Filter site map" title="Filter site map" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter by segment or path" />
     {filter ? (
      <IconButton label="Clear filter" size="small" onClick={() => setFilter("")}>
       <X size={13} />
      </IconButton>
     ) : null}
    </div>
    <BucketMenu
     label="Type"
     buckets={SITEMAP_MIME_BUCKETS}
     selected={sfilter.mimes}
     onToggle={(value) =>
      setSfilter((f) => ({ ...f, mimes: f.mimes.includes(value) ? f.mimes.filter((m) => m !== value) : [...f.mimes, value] }))
     }
     onReset={() => setSfilter((f) => ({ ...f, mimes: [] }))}
    />
    <BucketMenu
     label="Status"
     buckets={SITEMAP_STATUS_BUCKETS}
     selected={sfilter.statuses}
     onToggle={(value) =>
      setSfilter((f) => ({
       ...f,
       statuses: f.statuses.includes(value) ? f.statuses.filter((s) => s !== value) : [...f.statuses, value],
      }))
     }
     onReset={() => setSfilter((f) => ({ ...f, statuses: [] }))}
    />
    <Checkbox checked={sfilter.scopeOnly} onCheckedChange={(on) => setSfilter((f) => ({ ...f, scopeOnly: on }))} label="In scope only" />
    <Checkbox checked={sfilter.requestedOnly} onCheckedChange={(on) => setSfilter((f) => ({ ...f, requestedOnly: on }))} label="Requested only" />
    <Checkbox checked={sfilter.paramsOnly} onCheckedChange={(on) => setSfilter((f) => ({ ...f, paramsOnly: on }))} label="Parameterized only" />
    <Checkbox checked={sfilter.hideNotFound} onCheckedChange={(on) => setSfilter((f) => ({ ...f, hideNotFound: on }))} label="Hide not-found" />
    {filterActive(sfilter) ? (
     <IconButton
      label="Clear filters"
      size="small"
      onClick={() => setSfilter(NO_SITEMAP_FILTER)}
     >
      <X size={13} />
     </IconButton>
    ) : null}
   </Toolbar>
   {isFetching && !data ? (
    <Empty title="Loading site map…" detail="Folding captured traffic into a tree." />
   ) : rows.length === 0 ? (
    <Empty
     // "No traffic captured yet" is only true when nothing filters the view: with a bucket checked
     // and a tree that just went empty, that copy would blame the capture for what the filter did.
     title={narrowed ? "No path matches this filter" : "No traffic captured yet"}
     detail={narrowed ? "Relax the filter, or clear it to see the whole map." : "Point a client at the proxy to start building the map."}
    />
   ) : (
    <div
     className="row-list tree-pane"
     role="tree"
     aria-label="Site map"
     tabIndex={0}
     onKeyDown={onKeyDown}
     onFocus={() => {
      if (cursorId === null && rows.length) setCursorId(rows[0]?.key ?? null);
     }}
    >
     {rows.map((row) => (
      <TreeRow
       key={row.key}
       row={row}
       getMenuGroups={(target) => {
        const scope = target.depth === 0 ? "host" : "branch";
        // Delete host/branch/item (burpsy-react-ui-10e), from the node object the tree already
        // holds — the server wants the fields, not the composed key. The confirm modal carries the
        // suppression-not-deletion wording, because "delete" overstates what happens to the bytes.
        const pathPrefix = target.depth === 0 ? undefined : target.node.path;
        // Node-aimed actions (burpsy-react-ui-dpk): each acts on the tree row itself, not on some
        // exchange the operator had to find under it first. Passive scan sends nothing (it re-reads
        // the store); add-to-scope and active crawl hit the server in the same shapes the
        // exchange-level menu already uses, so both share one code path with the row menu.
        return [
         {
          id: "node-scope",
          actions: [
           {
            id: "add-to-scope",
            label: `Add ${target.host} to scope`,
            icon: ShieldCheck,
            onSelect: () => {
             void api<unknown>("/api/scope", json("POST", { action: "include", pattern: target.host }))
              .then(() => {
               toast.success(`${target.host} added to scope`);
               scopeInvalidate([["scope"], ["dashboard"]]);
              })
              .catch((err: unknown) => toast.error(`Could not add to scope: ${err instanceof Error ? err.message : String(err)}`));
            },
           },
          ],
         },
         {
          id: "node-scan",
          actions: [
           {
            id: "passive-branch",
            label: target.depth === 0 ? "Passively scan this host" : "Passively scan this branch",
            onSelect: () => {
             passiveScan.mutate(
              { host: target.host, path_prefix: pathPrefix },
              {
               onSuccess: (result) => {
                if (result.loaded === 0) toast.error(result.summary);
                else if (result.findings > 0) toast.success(result.summary);
                else toast.info(result.summary);
               },
               onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
              },
             );
            },
           },
           {
            id: "active-branch",
            label: target.depth === 0 ? "Actively scan this host (crawl)" : "Actively scan this branch (crawl)",
            onSelect: () => {
             const seed =
              target.depth === 0
               ? `${target.node.tls ? "https" : "http"}://${target.host}:${target.node.port}/`
               : `${target.node.tls ? "https" : "http"}://${target.host}:${target.node.port}${target.node.path}`;
             const retention =
              target.depth === 0
               ? `host = ${target.host}`
               // The node path IS the branch: keep it and everything beneath it. The exchange-level
               // crawlFrom strips the last segment because there path is a FILE the crawl was launched
               // from; here the operator aimed at the branch itself, so stripping one level would
               // widen the keep-filter to the parent ("/mango" becoming `path ~ "/"` — the whole host).
               : `path ~ "${target.node.path.endsWith("/") ? target.node.path : target.node.path + "/"}"`;
             startCrawl.mutate(
              // retention_query is the crawl's keep-path filter — the same DSL clause the
              // exchange-level crawlFrom composes (actions.ts:427), so a branch crawl only
              // keeps what is still under the branch.
              { seeds: [seed], retention_query: retention },
              {
               onSuccess: () => {
                toast.success(`Crawl started from ${scope} ${target.depth === 0 ? target.host : target.node.path}`);
                setRoute("discover");
               },
               onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
              },
             );
            },
           },
          ],
         },
         {
          id: "delete",
          actions: [
           {
            id: "delete-node",
            label: target.depth === 0 ? "Delete host" : "Delete branch",
            onSelect: () => setConfirmDelete({ node: target.node, host: target.host, kind: target.depth === 0 ? "host" : "branch" }),
           },
           ...(target.depth > 0
            ? [
             {
              id: "delete-item",
              label: "Delete this item only",
              onSelect: () => setConfirmDelete({ node: target.node, host: target.host, kind: "item" }),
             },
            ]
            : []),
          ],
         },
         {
          id: "copy",
          actions: [
           {
            id: "copy-urls",
            label: `Copy URLs in this ${scope}`,
            onSelect: () => {
             const urls = urlsUnder(target, history ?? []);
             if (!urls.length) {
              toast.error(`No captured requests under this ${scope}`);
              return;
             }
             void copyToClipboard(urls.join("\n"));
             toast.success(`Copied ${urls.length} URLs from this ${scope}`);
            },
           },
          ],
         },
        ];
       }}
       selected={row.key === selectedId}
       cursor={row.key === cursorId}
       onToggle={() => toggle(row)}
       onSelect={() => select(row.key)}
      />
     ))}
    </div>
   )}
  </div>
 );

 const messagePane = activeExchange ? (
  <div className="tabs-fill">
   <div className="detail-head">
    <div className="detail-head-title">
     <span className="eyebrow">#{activeExchange.id}</span>
     {/* Nested one level under the node heading below, because this pane lives inside that
              one. The <strong> is what carries the type: `.detail-head-title strong` is the
              console's pane-title treatment, and every other detail head in the app uses it. */}
     <h3>
      <strong>
       {activeExchange.tls ? "https" : "http"}://{activeExchange.host}:{activeExchange.port}
       {activeExchange.path}
      </strong>
     </h3>
    </div>
    <div className="detail-actions">
     <Badge tone={statusTone(activeExchange.status)}>{activeExchange.status ?? "pending"}</Badge>
     <Badge>{formatDuration(activeExchange.duration_ms)}</Badge>
     <Button variant="outline" size="small" onClick={() => void actions.sendToRepeater(activeExchange)}>
      <Repeat2 size={13} />
      Repeater
     </Button>
     <Button variant="outline" size="small" onClick={() => actions.sendToIntruder(activeExchange)}>
      <Crosshair size={13} />
      Intruder
     </Button>
     <Button variant="outline" size="small" onClick={() => void actions.sendToComparer(activeExchange, "a")}>
      <Combine size={13} />
      Compare
     </Button>
     <IconButton
      label={inspector ? "Hide Inspector" : "Show Inspector"}
      size="small"
      aria-pressed={inspector}
      onClick={() => setInspector((current) => !current)}
     >
      <Columns3 size={13} />
     </IconButton>
    </div>
   </div>
   <div className={inspector ? "editor-grid-inspected" : "editor-grid"}>
    <HttpEditor
     label="Request"
     readOnly
     value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
     filename={`exchange-${activeExchange.id}-request.txt`}
     menuGroups={actions.menu(activeExchange)}
    />
    <HttpEditor
     label="Response"
     readOnly
     value={
      activeExchange.response === null
       ? "No response was captured for this exchange."
       : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."))
     }
     bodyBase64={response.data?.body_base64}
     filename={`exchange-${activeExchange.id}-response.txt`}
     menuGroups={actions.menu(activeExchange)}
    />
    {inspector ? (
     <Inspector
      raw={request.data?.text ?? ""}
      label="Inspector · request"
      readOnlyNote="This request has already been sent, so it is read-only here. Send it to Repeater to change it and try again."
     />
    ) : null}
   </div>
  </div>
 ) : (
  <Empty
   title="No request selected"
   detail="Choose a row above to read its exact request and response bytes."
  />
 );

 const contentPane = !selected ? (
  <Empty title="No path selected" detail="Choose a host or path in the tree to see the requests captured under it." />
 ) : (
  <div className="pane">
   <div className="detail-head">
    <div className="detail-head-title">
     <span className="eyebrow">{selected.depth === 0 ? "host" : selected.node.requested ? "path" : "folder (never requested directly)"}</span>
     {/* Was an <h3> directly under the page's <h1>, skipping h2 — a heading outline that
              tells a screen-reader user there is a missing level between the page and this pane.
              This is the pane's own heading, so it is the h2. */}
     <h2>
      <strong>
       {selected.host}
       {selected.depth === 0 ? "" : selected.node.path}
      </strong>
     </h2>
    </div>
    <div className="detail-actions">
     {(selected.node.methods ?? []).map((m) => (
      <Badge tone="info" key={m}>
       {m}
      </Badge>
     ))}
     {(selected.node.statuses ?? []).map((s) => (
      <Badge tone={statusTone(s)} key={s}>
       {s}
      </Badge>
     ))}
     <Tooltip
      content={
       nodeFindings.length
        ? "Findings observed on this node's exchanges"
        : "No findings observed on this node's exchanges"
      }
     >
      <Button
       variant="outline"
       size="small"
       disabled={!nodeFindings.length}
       aria-pressed={showIssues}
       onClick={() => setShowIssues((current) => !current)}
      >
       Issues ({nodeFindings.length})
      </Button>
     </Tooltip>
     <Tooltip content="Open the HTTP history tab filtered to this path and everything under it">
      <Button variant="outline" size="small" onClick={() => filterHistory(selected)}>
       <ExternalLink size={13} />
       Filter history
      </Button>
     </Tooltip>
    </div>
   </div>
   {showIssues && nodeFindings.length > 0 ? (
    <Card className="pane-fill">
     <SectionHeading title={`Issues under ${selected.depth === 0 ? selected.host : selected.node.path}`} />
     <SimpleTable headers={["Severity", "Finding", "Host", "Seen"]}>
      {nodeFindings.map((finding) => (
       <MenuRow
        key={finding.id}
        groups={[
         {
          id: "open",
          actions: [
           {
            id: "issues",
            label: "Open in Issues",
            onSelect: () => setRoute("scanner"),
           },
          ],
         },
        ]}
       >
        <td>
         <Badge tone={findingTone(finding.severity)}>{finding.severity}</Badge>
        </td>
        <td title={finding.detail ?? undefined}>{finding.issue_name ?? finding.check_name ?? "Unnamed finding"}</td>
        <td>{finding.host}</td>
        <td>
         <span className="cell-num">{finding.times_seen}×</span>
        </td>
       </MenuRow>
      ))}
     </SimpleTable>
    </Card>
   ) : null}
   <SplitPane
    storageId="sitemap-detail"
    orientation="vertical"
    defaultMasterSize="44"
    className="pane-fill"
    master={
     nodeExchanges.length === 0 ? (
      <Empty
       title="No requests under this node"
       detail={
        selected.node.requested
         ? "The capture holding these exchanges may have rolled over."
         : "Nothing requested this folder itself — open a child node to see its traffic."
       }
      />
     ) : (
      <VirtualTable
       ariaLabel={`Requests under ${selected.node.path}`}
       data={nodeExchanges}
       columns={columns}
       getRowId={(row) => String(row.id)}
       selectedId={selectedExchange === null ? null : String(selectedExchange)}
       onSelect={(row) => setSelectedExchange(row.id)}
       onActivate={(row) => void actions.sendToRepeater(row)}
       menuGroups={(row) => actions.menu(row)}
       rowClassName={(row) => (row.highlight ? cn("row-highlight", `row-highlight-${row.highlight}`) : undefined)}
      />
     )
    }
    detail={messagePane}
   />
  </div>
 );

 return (
  <div className="page-fill">
   <div>
    <PageHeader
     title="Site map"
     actions={
      <>
       {/* Burp's two views (burpsy-react-ui-tix). The URL tree answers "what is on this
                  host"; crawl paths answers "what should have linked to the page I expected and
                  cannot find". Different questions, so a toggle rather than a merged tree. */}
       <div className="chip-row" role="group" aria-label="Site map view">
        <Button
         variant={view === "urls" ? "outline" : "quiet"}
         size="small"
         aria-pressed={view === "urls"}
         onClick={() => setView("urls")}
        >
         URL view
        </Button>
        <Button
         variant={view === "paths" ? "outline" : "quiet"}
         size="small"
         aria-pressed={view === "paths"}
         onClick={() => setView("paths")}
        >
         Crawl paths
        </Button>
       </div>
       {/* Two honest answers, not one smoothed one: under an active filter the first badge counts
           what the tree actually shows (rows are unique node keys), and the capture total stays
           beside it so the gap is visible instead of papered over. History's status bar draws the
           same distinction between filtered, loaded and captured. */}
       <Badge>
        {narrowed
         ? `${new Set(rows.map((r) => r.key)).size.toLocaleString()} of ${(data?.nodes ?? 0).toLocaleString()} nodes`
         : `${(data?.nodes ?? 0).toLocaleString()} nodes`}
       </Badge>
       <Badge>{(data?.exchanges ?? 0).toLocaleString()} exchanges</Badge>
       {data?.in_flight ? <Badge tone="info">{data.in_flight} in flight</Badge> : null}
       {/* Burp's "Passively scan this branch" (burpsy-react-ui-p09). No confirm step: the sweep
                  sends nothing, it re-reads responses the store already holds. Disabled with a
                  reason when nothing is selected, rather than acting on an implied whole-store
                  target — that is what the live audit already does and is not what "this branch"
                  means. */}
       <Tooltip
        content={
         selected
          ? `Re-run the passive checks over ${selected.host}${selected.depth === 0 ? "" : selected.node.path} — sends nothing, reads what is already captured`
          : "Select a host or path in the tree to scan its branch"
        }
       >
        <span>
         <Button
          variant="outline"
          size="small"
          disabled={!selected || passiveScan.isPending}
          onClick={() => {
           if (!selected) return;
           passiveScan.mutate(
            {
             host: selected.host,
             // A host node is the whole host; a path node is its own path and below.
             path_prefix: selected.depth === 0 ? undefined : selected.node.path,
            },
            {
             onSuccess: (result) => {
              // The server's own summary, verbatim: it states the counts WITH their
              // caveats, and rewording it here would be a second wording of the one
              // thing that must not be optimistic.
              if (result.loaded === 0) {
               toast.error(result.summary);
              } else if (result.findings > 0) {
               toast.success(result.summary);
              } else {
               toast.info(result.summary);
              }
             },
             onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
            },
           );
          }}
         >
          <ShieldCheck size={13} />
          {passiveScan.isPending ? "Scanning…" : "Passive scan branch"}
         </Button>
        </span>
       </Tooltip>
       <CrawlLauncher />
       <RefreshButton onClick={() => void refetch()} loading={isFetching} />
      </>
     }
    />
    {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   </div>
   {view === "paths" ? (
    <CrawlPathsView runs={crawls.data?.crawls ?? []} />
   ) : (
    <SplitPane storageId="sitemap" orientation="horizontal" defaultMasterSize="28" minMasterSize="16" master={treePane} detail={contentPane} />
   )}
   <Modal
    open={confirmDelete !== undefined}
    onOpenChange={(open) => {
     if (!open) setConfirmDelete(undefined);
    }}
    title={
     confirmDelete?.kind === "host"
      ? `Delete host ${confirmDelete.node.segment} from the map?`
      : `Delete ${confirmDelete?.kind === "item" ? "item" : "branch"} ${confirmDelete?.node.path ?? ""}?`
    }
    description={
     "The node leaves the site map and stays out, including for re-captured traffic on it. This is a view-level removal: " +
     "the captured exchanges stay — HTTP history, findings and anything saved against them are untouched. A burpsy restart " +
     "rebuilds the map from the store, so the rows return then."
    }
   >
    <div className="detail-actions">
     <Button variant="danger" disabled={removeNode.isPending} onClick={runDelete}>
      {removeNode.isPending ? "Deleting…" : "Delete from the map"}
     </Button>
     <Button variant="outline" onClick={() => setConfirmDelete(undefined)}>
      Keep it
     </Button>
    </div>
   </Modal>
  </div>
 );
}
