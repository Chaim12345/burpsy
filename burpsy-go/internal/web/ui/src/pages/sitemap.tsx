import { ChevronDown, ChevronRight, Columns3, Combine, Crosshair, ExternalLink, Folder, FolderOpen, Globe, Repeat2, Search, ShieldCheck, X } from "lucide-react";
import { useMemo, useState, type KeyboardEvent } from "react";
import { formatBytes, formatDuration, mimeLabel, relativeTime, statusTone } from "../lib/api";
import { useDebounced, useHistory, useMessage } from "../lib/data";
import { useSitemapDetailed } from "../lib/data.observe";
import { useExchangeActions } from "../lib/actions";
import { useApp } from "../lib/store";
import { toast } from "sonner";
import type { SiteNodeDetail as SiteNode } from "../lib/types.observe";
import type { Exchange } from "../lib/types";
import { CrawlLauncher } from "../ui/crawl";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Button, Empty, ErrorNotice, IconButton, Input, Toolbar, Tooltip } from "../ui/primitives";
import { VirtualTable, type Column } from "../ui/table";
import { CrawlPathsView } from "../ui/crawlpaths";
import { useCrawls, usePassiveScanBranch } from "../lib/data.observe";
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

/** The server states each node's exact identity in `key` — the host for a host node, host + NUL +
 * path below that. This page used to build the same string itself because the server only
 * offered a colliding hash; taking the server's means an expand/collapse key and a server-side
 * node can never disagree about which node is which. */
function nodeKey(node: SiteNode): string {
  return node.key;
}

/** A node (or one of its descendants) matches the filter term. Checked once per node so both the
 * visibility pass and the auto-expand pass agree on what counts as a match. */
function subtreeMatches(node: SiteNode, term: string): boolean {
  if (!term) return true;
  if (node.path.toLowerCase().includes(term) || node.segment.toLowerCase().includes(term)) return true;
  return (node.children ?? []).some((child) => subtreeMatches(child, term));
}

/** Flattens the visible tree into a single ordered list, honouring expansion state and the active
 * filter. A node with no match in its whole subtree is dropped entirely rather than shown greyed out. */
function flatten(
  nodes: SiteNode[],
  depth: number,
  host: string,
  parentKey: string | null,
  term: string,
  expanded: Record<string, boolean>,
): FlatRow[] {
  const out: FlatRow[] = [];
  for (const node of nodes) {
    if (!subtreeMatches(node, term)) continue;
    const hasChildren = (node.children ?? []).length > 0;
    const rowHost = depth === 0 ? node.path : host;
    // Filtering forces a matching branch open so the match underneath is reachable; otherwise fall
    // back to the operator's own toggle, defaulting to the first two levels expanded.
    const key = nodeKey(node);
    const isExpanded = term ? true : expanded[key] ?? depth < 2;
    out.push({ node, depth, host: rowHost, key, parentKey, hasChildren, expanded: isExpanded });
    if (hasChildren && isExpanded) out.push(...flatten(node.children ?? [], depth + 1, rowHost, key, term, expanded));
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
}: {
  row: FlatRow;
  selected: boolean;
  cursor: boolean;
  onToggle: () => void;
  onSelect: () => void;
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
  );
}

export function SiteMapPage(): JSX.Element {
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);
  const setRoute = useApp((state) => state.setRoute);

  const [filter, setFilter] = useState("");
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

  const debouncedFilter = useDebounced(filter, 250);
  const term = debouncedFilter.trim().toLowerCase();

  const { data, error, isFetching, refetch } = useSitemapDetailed();
  // The same cache key the HTTP history tab uses, so selecting a node costs no extra request.
  const { data: history } = useHistory("", 1000);
  const actions = useExchangeActions();
  const tree = data?.tree ?? [];

  const rows = useMemo(() => flatten(tree, 0, "", null, term, expanded), [tree, term, expanded]);
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

  const activeExchange = useMemo(
    () => nodeExchanges.find((ex) => ex.id === selectedExchange) ?? null,
    [nodeExchanges, selectedExchange],
  );
  const request = useMessage(activeExchange?.request);
  const response = useMessage(activeExchange?.response ?? null);

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
      </Toolbar>
      {isFetching && !data ? (
        <Empty title="Loading site map…" detail="Folding captured traffic into a tree." />
      ) : rows.length === 0 ? (
        <Empty
          title={term ? "No path matches this filter" : "No traffic captured yet"}
          detail={term ? "Relax the filter, or clear it to see the whole map." : "Point a client at the proxy to start building the map."}
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
        />
        <HttpEditor
          label="Response"
          readOnly
          value={
            activeExchange.response === null
              ? "No response was captured for this exchange."
              : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."))
          }
          filename={`exchange-${activeExchange.id}-response.txt`}
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
          <Tooltip content="Open the HTTP history tab filtered to this path and everything under it">
            <Button variant="outline" size="small" onClick={() => filterHistory(selected)}>
              <ExternalLink size={13} />
              Filter history
            </Button>
          </Tooltip>
        </div>
      </div>
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
              <Badge>{(data?.nodes ?? 0).toLocaleString()} nodes</Badge>
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
    </div>
  );
}
