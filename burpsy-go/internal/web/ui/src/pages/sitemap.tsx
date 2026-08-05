import { ChevronDown, ChevronRight, ExternalLink, Search, X } from "lucide-react";
import { useMemo, useState, type KeyboardEvent } from "react";
import { statusTone } from "../lib/api";
import { useDebounced } from "../lib/data";
import { useSitemapDetailed } from "../lib/data.observe";
import { useApp } from "../lib/store";
import type { SiteNodeDetail as SiteNode } from "../lib/types.observe";
import { PageHeader, RefreshButton } from "../ui/layout";
import { Badge, Button, Empty, ErrorNotice, IconButton, Input, Metric } from "../ui/primitives";
import { DetailList } from "../ui/json";
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

/** The server's node `id` is a hash and can collide, so identity comes from the
 * host plus the full path, which is unique by construction. */
function nodeKey(host: string, node: SiteNode): string {
  return `${host}\u0000${node.path}`;
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
    const key = nodeKey(rowHost, node);
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
    into.set(nodeKey(rowHost, node), { node, host: rowHost, depth });
    if ((node.children ?? []).length) buildIndex(node.children ?? [], depth + 1, rowHost, into);
  }
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
  return (
    <div
      role="treeitem"
      aria-level={depth + 1}
      aria-expanded={hasChildren ? expanded : undefined}
      aria-selected={selected}
      tabIndex={-1}
      data-node-id={node.id}
      className={cn("tree-row", selected && "active")}
      style={{ paddingLeft: `${8 + depth * 16}px`, outline: cursor ? "2px solid var(--accent)" : undefined, outlineOffset: cursor ? -2 : undefined }}
      onClick={onSelect}
    >
      <button
        type="button"
        className="tree-toggle"
        aria-label={hasChildren ? (expanded ? `Collapse ${node.segment}` : `Expand ${node.segment}`) : undefined}
        aria-expanded={hasChildren ? expanded : undefined}
        disabled={!hasChildren}
        onClick={(event) => {
          event.stopPropagation();
          onToggle();
        }}
      >
        {hasChildren ? expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} /> : null}
      </button>
      <span className="tree-row-label" title={node.path}>
        {node.segment || "/"}
      </span>
      <span className="chip-row">
        {(node.methods ?? []).map((method) => (
          <Badge tone="info" key={method}>
            {method}
          </Badge>
        ))}
        {(node.statuses ?? []).map((status) => (
          <Badge tone={statusTone(status)} key={status}>
            {status}
          </Badge>
        ))}
      </span>
      <Badge title="direct / subtree exchanges">
        {node.exchanges}/{node.subtree_exchanges}
      </Badge>
    </div>
  );
}

export function SiteMapPage(): JSX.Element {
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);
  const setRoute = useApp((state) => state.setRoute);

  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [cursorId, setCursorId] = useState<string | null>(null);

  const debouncedFilter = useDebounced(filter, 250);
  const term = debouncedFilter.trim().toLowerCase();

  const { data, error, isFetching, refetch } = useSitemapDetailed();
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
        if (current) setSelectedId(current.key);
        break;
      default:
        break;
    }
  };

  const selected = selectedId === null ? null : (index.get(selectedId) ?? null);

  const filterHistory = (entry: IndexedNode) => {
    const query = entry.depth === 0 ? `host = ${entry.host}` : `host = ${entry.host} AND path ~ ${entry.node.path}`;
    setHistoryQuery(query);
    setRoute("history");
  };

  const treeBody =
    isFetching && !data ? (
      <Empty title="Loading site map…" detail="Folding captured traffic into a tree." />
    ) : rows.length === 0 ? (
      <Empty
        title={term ? "No path matches this filter" : "No traffic captured yet"}
        detail={term ? "Relax the filter, or clear it to see the whole map." : "Point a client at the proxy to start building the map."}
      />
    ) : (
      <div
        className="row-list"
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
            onSelect={() => {
              setSelectedId(row.key);
              setCursorId(row.key);
            }}
          />
        ))}
      </div>
    );

  const detailBody = selected ? (
    <div className="detail-panel">
      <div>
        <span className="eyebrow">selected node</span>
        <h3>
          {selected.host}
          {selected.depth === 0 ? "" : selected.node.path}
        </h3>
      </div>
      <DetailList
        rows={[
          {
            label: "Methods",
            value: (selected.node.methods ?? []).length ? (
              <span className="chip-row">
                {selected.node.methods.map((m) => (
                  <Badge tone="info" key={m}>
                    {m}
                  </Badge>
                ))}
              </span>
            ) : (
              <span className="cell-dim">none observed</span>
            ),
          },
          {
            label: "Statuses",
            value: (selected.node.statuses ?? []).length ? (
              <span className="chip-row">
                {selected.node.statuses.map((s) => (
                  <Badge tone={statusTone(s)} key={s}>
                    {s}
                  </Badge>
                ))}
              </span>
            ) : (
              <span className="cell-dim">none observed</span>
            ),
          },
          { label: "Direct exchanges", value: selected.node.exchanges.toLocaleString() },
          { label: "Subtree exchanges", value: selected.node.subtree_exchanges.toLocaleString() },
        ]}
      />
      <Button variant="outline" size="small" onClick={() => filterHistory(selected)}>
        <ExternalLink size={13} />
        Filter HTTP history by this path
      </Button>
    </div>
  ) : (
    <Empty title="No path selected" detail="Choose a node in the tree to see its methods, statuses, and exchange totals." />
  );

  return (
    <div className="page">
      <PageHeader title="Site map" actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />} />
      <div className="metric-grid">
        <Metric label="Exchanges" value={(data?.exchanges ?? 0).toLocaleString()} />
        <Metric label="Nodes" value={(data?.nodes ?? 0).toLocaleString()} />
        <Metric label="Synced" value={(data?.synced ?? 0).toLocaleString()} />
        <Metric label="In flight" value={data?.in_flight ?? 0} tone={data?.in_flight ? "info" : undefined} />
      </div>
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      <div className="search-field">
        <Search size={15} />
        <Input aria-label="Filter site map" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter by segment or path" />
        {filter ? (
          <IconButton label="Clear filter" size="small" onClick={() => setFilter("")}>
            <X size={13} />
          </IconButton>
        ) : null}
      </div>
      <div className="two-col-wide-left" style={{ height: 460 }}>
        <div className="card card-fill">{treeBody}</div>
        <div className="card card-fill">{detailBody}</div>
      </div>
    </div>
  );
}
