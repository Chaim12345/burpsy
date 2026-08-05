import { useMemo, useState } from "react";
import { FolderTree, Link2, Search, Terminal, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard, formatBytes, formatDuration, relativeTime, statusTone } from "../lib/api";
import { useClearToolLog, useDebounced } from "../lib/data";
import { useToolLogView } from "../lib/data.workbench";
import { useApp } from "../lib/store";
import type { ToolLogRow } from "../lib/types.workbench";
import { DetailList } from "../ui/json";
import { PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Button, Empty, ErrorNotice, IconButton, Input, Modal, Select, Toolbar } from "../ui/primitives";
import { VirtualTable, type Column } from "../ui/table";

/**
 * A logged row records a request one of burpsy's own tools sent. The log carries
 * no TLS flag, so the scheme is inferred from the port — the only honest guess
 * available, and why the URL actions say "as logged".
 */
function rowUrl(row: ToolLogRow): string {
  const scheme = row.port === 443 ? "https" : "http";
  const authority = row.port === 443 || row.port === 80 ? row.host : `${row.host}:${row.port}`;
  return `${scheme}://${authority}${row.path}`;
}

/**
 * The log stores a request line, not the bytes that were sent: no headers, no
 * body. The curl this builds is therefore the request line only, and the menu
 * label says so rather than implying a replayable command.
 */
function rowCurl(row: ToolLogRow): string {
  return `curl -i -X ${row.method || "GET"} ${JSON.stringify(rowUrl(row))}`;
}

export function LoggerPage(): JSX.Element {
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);
  const setRoute = useApp((state) => state.setRoute);

  const [tool, setTool] = useState("");
  const [term, setTerm] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const debouncedTerm = useDebounced(term, 260);
  const { data, error, isFetching, refetch } = useToolLogView(tool, debouncedTerm);
  const clearLog = useClearToolLog();

  const rows = data?.entries ?? [];

  // Selection is held by id so a background refresh cannot drop it.
  const selected = useMemo(() => rows.find((row) => row.id === selectedId) ?? null, [rows, selectedId]);

  // The tool list comes from the server's histogram rather than a hard-coded set,
  // so a tool that starts logging is filterable without a frontend change.
  const tools = useMemo(() => Object.entries(data?.counts ?? {}).sort(([a], [b]) => a.localeCompare(b)), [data]);

  const showInHistory = (expression: string) => {
    setHistoryQuery(expression);
    setRoute("history");
  };

  const columns = useMemo<Column<ToolLogRow>[]>(
    () => [
      {
        accessorKey: "started_ms",
        header: "Age",
        size: 84,
        cell: (info) => <span className="cell-dim">{relativeTime(info.getValue<number>())}</span>,
      },
      { accessorKey: "tool", header: "Tool", size: 96, cell: (info) => <Badge>{info.getValue<string>()}</Badge> },
      {
        id: "authority",
        header: "Authority",
        size: 200,
        accessorFn: (row) => `${row.host}:${row.port}`,
        cell: (info) => <span title={info.getValue<string>()}>{info.getValue<string>()}</span>,
      },
      {
        id: "request",
        header: "Request",
        size: 350,
        accessorFn: (row) => `${row.method} ${row.path}`,
        cell: (info) => <code title={info.getValue<string>()}>{info.getValue<string>()}</code>,
      },
      {
        accessorKey: "status",
        header: "Status",
        size: 80,
        cell: (info) => {
          const value = info.getValue<number | null>();
          return value === null ? <Badge tone="warn">none</Badge> : <Badge tone={statusTone(value)}>{value}</Badge>;
        },
      },
      {
        accessorKey: "response_len",
        header: "Length",
        size: 84,
        cell: (info) => <span className="cell-num">{formatBytes(info.getValue<number>())}</span>,
      },
      {
        accessorKey: "duration_ms",
        header: "Time",
        size: 78,
        cell: (info) => <span className="cell-num">{formatDuration(info.getValue<number>())}</span>,
      },
      {
        accessorKey: "error",
        header: "Error",
        size: 260,
        cell: (info) => {
          const value = info.getValue<string | null>();
          return value ? <span title={value}>{value}</span> : <span className="cell-dim">—</span>;
        },
      },
    ],
    [],
  );

  const detail = selected ? (
    <div className="detail-panel">
      <div className="detail-head">
        <div className="detail-head-title">
          <span className="eyebrow">#{selected.id}</span>
          <strong title={rowUrl(selected)}>
            {selected.method} {rowUrl(selected)}
          </strong>
        </div>
        <div className="detail-actions">
          <Badge>{selected.tool}</Badge>
          <Badge tone={statusTone(selected.status)}>{selected.status ?? "no response"}</Badge>
          <Button variant="outline" size="small" onClick={() => showInHistory(`host = ${selected.host}`)}>
            <FolderTree size={13} />
            Show in history
          </Button>
          <IconButton label="Clear selection" size="small" onClick={() => setSelectedId(null)}>
            <X size={13} />
          </IconButton>
        </div>
      </div>
      <DetailList
        rows={[
          { label: "Sent", value: `${relativeTime(selected.started_ms)} (${new Date(selected.started_ms).toLocaleString()})` },
          { label: "Authority", value: `${selected.host}:${selected.port}` },
          { label: "Path", value: <code>{selected.path}</code> },
          { label: "Duration", value: formatDuration(selected.duration_ms) },
          { label: "Response length", value: formatBytes(selected.response_len) },
          {
            label: "Error",
            value: selected.error ? <span className="bad-text">{selected.error}</span> : "none reported",
          },
        ]}
      />
    </div>
  ) : (
    <Empty
      title="No row selected"
      detail="Choose a logged request to read its timing and error text in full. Right-click a row to copy its URL or jump to the same host in HTTP history."
    />
  );

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Tool log"
          actions={
            <>
              <Badge tone="info">
                {(data?.shown ?? 0).toLocaleString()} of {(data?.total ?? 0).toLocaleString()} shown
              </Badge>
              {/* A log that silently truncates is misleading, so the discard count is
                  always on screen — not only when someone opens a detail pane. */}
              <Badge tone={data && data.dropped > 0 ? "warn" : "neutral"}>
                {(data?.dropped ?? 0).toLocaleString()} dropped
              </Badge>
              <Button variant="danger" onClick={() => setConfirmClear(true)} disabled={!rows.length}>
                <Trash2 size={14} />
                Clear log
              </Button>
              <RefreshButton onClick={() => void refetch()} loading={isFetching} />
            </>
          }
        />
        <Toolbar style={{ marginTop: 10 }}>
          <div className="search-field">
            <Search size={15} />
            <Input
              aria-label="Search the tool log"
              value={term}
              onChange={(event) => setTerm(event.target.value)}
              placeholder="host, path or method"
            />
            {term ? (
              <IconButton label="Clear search" size="small" onClick={() => setTerm("")}>
                <X size={13} />
              </IconButton>
            ) : null}
          </div>
          <Select aria-label="Tool filter" value={tool} onChange={(event) => setTool(event.target.value)} style={{ maxWidth: "var(--w-md)" }}>
            <option value="">All tools</option>
            {tools.map(([name, count]) => (
              <option key={name} value={name}>
                {name} ({count})
              </option>
            ))}
          </Select>
        </Toolbar>
        {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      </div>

      <SplitPane
        storageId="toollog"
        orientation="vertical"
        defaultMasterSize="64"
        master={
          <VirtualTable
            ariaLabel="Requests sent by burpsy's own tools"
            data={rows}
            columns={columns}
            getRowId={(row) => String(row.id)}
            selectedId={selectedId === null ? null : String(selectedId)}
            onSelect={(row) => setSelectedId(row.id)}
            menuGroups={(row) => [
              {
                id: "copy",
                actions: [
                  {
                    id: "url",
                    label: "Copy URL (as logged)",
                    icon: Link2,
                    onSelect: () => {
                      void copyToClipboard(rowUrl(row));
                      toast.success("URL copied");
                    },
                  },
                  {
                    id: "curl",
                    label: "Copy as curl (request line only)",
                    icon: Terminal,
                    onSelect: () => {
                      void copyToClipboard(rowCurl(row));
                      toast.success("curl command copied — the log stores no headers or body");
                    },
                  },
                ],
              },
              {
                id: "history",
                actions: [
                  {
                    id: "host",
                    label: `Show ${row.host} in HTTP history`,
                    icon: FolderTree,
                    onSelect: () => showInHistory(`host = ${row.host}`),
                  },
                  {
                    id: "path",
                    label: `Show ${row.host} ${row.path} in HTTP history`,
                    icon: FolderTree,
                    onSelect: () => showInHistory(`host = ${row.host} AND path ~ ${row.path}`),
                  },
                ],
              },
            ]}
            rowClassName={(row) =>
              row.error !== null || row.status === null || row.status >= 500
                ? "row-flag-bad"
                : row.status >= 400
                  ? "row-flag-warn"
                  : undefined
            }
            loading={isFetching && !data}
            empty={
              <Empty
                title={term || tool ? "No logged request matches" : "Nothing logged yet"}
                detail={
                  term || tool
                    ? "Relax the search or switch back to all tools."
                    : "Repeater, Intruder, Scanner and the crawler record every request they send here, apart from proxy history."
                }
              />
            }
          />
        }
        detail={detail}
      />

      <Modal
        open={confirmClear}
        onOpenChange={setConfirmClear}
        title="Clear the tool log?"
        description="Every recorded request is discarded. Proxy history is untouched, and this cannot be undone."
      >
        <div className="detail-actions">
          <Button
            variant="danger"
            disabled={clearLog.isPending}
            onClick={() =>
              clearLog.mutate(undefined, {
                onSuccess: () => {
                  setSelectedId(null);
                  setConfirmClear(false);
                  toast.success("Tool log cleared");
                },
                onError: (cause) => toast.error(`Could not clear the log: ${cause.message}`),
              })
            }
          >
            <Trash2 size={14} />
            {clearLog.isPending ? "Clearing…" : `Clear ${(data?.total ?? 0).toLocaleString()} entries`}
          </Button>
          <Button variant="outline" onClick={() => setConfirmClear(false)}>
            Keep the log
          </Button>
        </div>
      </Modal>
    </div>
  );
}
