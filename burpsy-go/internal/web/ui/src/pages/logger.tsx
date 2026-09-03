import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { FolderTree, Link2, MessageSquare, Search, Terminal, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { cn } from "../lib/cn";
import { copyToClipboard, downloadText, formatBytes, formatDuration, relativeTime, statusTone, toolLogToCSV } from "../lib/api";
import { useClearToolLog, useDebounced } from "../lib/data";
import { useSetToolLogCapture, useSetToolLogComment, useToolLogView } from "../lib/data.workbench";
import { useApp } from "../lib/store";
import { HIGHLIGHTS, HIGHLIGHT_TONE } from "../lib/types";
import { HIGHLIGHT_ICONS } from "../ui/highlight-icons";
import type { ToolLogRow } from "../lib/types.workbench";
import { DetailList } from "../ui/json";
import { PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Button, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Toolbar } from "../ui/primitives";
import { BucketMenu } from "../ui/column-visibility-menu";
import { VirtualTable, type Column, type VisibilityState } from "../ui/table";

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

/**
 * Reads and writes the hidden-column set for a table under `burpsy.<key>`, so
 * a page opting into `VirtualTable`'s column-visibility capability can persist
 * the operator's choice across reloads. Not part of table.tsx's API surface —
 * that only defines the shape (`VisibilityState`); how it is stored is a page
 * decision, same as `SplitPane`'s `storageId` pattern above.
 */
function useStoredColumnVisibility(key: string): [VisibilityState, (next: VisibilityState) => void] {
 const [visibility, setVisibility] = useState<VisibilityState>(() => {
  try {
   const raw = localStorage.getItem(`burpsy.${key}`);
   return raw ? (JSON.parse(raw) as VisibilityState) : {};
  } catch {
   return {};
  }
 });

 const update = (next: VisibilityState) => {
  setVisibility(next);
  try {
   localStorage.setItem(`burpsy.${key}`, JSON.stringify(next));
  } catch {
   // Storage can be unavailable (private mode, quota); the in-memory choice still applies.
  }
 };

 return [visibility, update];
}

export function LoggerPage(): JSX.Element {
 const setHistoryQuery = useApp((state) => state.setHistoryQuery);
 const setRoute = useApp((state) => state.setRoute);

 const [tool, setTool] = useState("");
 const [term, setTerm] = useState("");
 const [selectedId, setSelectedId] = useState<number | null>(null);
 const [confirmClear, setConfirmClear] = useState(false);
 const [annotatedOnly, setAnnotatedOnly] = useState(false);
 const [captureOpen, setCaptureOpen] = useState(false);
 const [capStatus, setCapStatus] = useState<string[]>([]);
 const [capTerm, setCapTerm] = useState("");
 const [capRegex, setCapRegex] = useState(false);
 const [capCase, setCapCase] = useState(false);
 const [capNegate, setCapNegate] = useState(false);
 const [capScopeOnly, setCapScopeOnly] = useState(false);
 const [capCapacity, setCapCapacity] = useState("");
 const [columnVisibility, setColumnVisibility] = useStoredColumnVisibility("logger.columns");

 const debouncedTerm = useDebounced(term, 260);
 const { data, error, isFetching, refetch } = useToolLogView(tool, debouncedTerm);
 const clearLog = useClearToolLog();
 const setCapture = useSetToolLogCapture();
 const setAnnotation = useSetToolLogComment();

 const rows = data?.entries ?? [];

 // Method and status-class filters run client-side over the loaded rows: the
 // server's filter arm is tool-only, and these two are the rest of Burp
 // Logger's everyday set. Distinct methods come from the data, so a new verb
 // needs no frontend change — the same trick the tool list uses.
 const [method, setMethod] = useState("");
 const [statusClass, setStatusClass] = useState("");
 const methods = useMemo(
  () => [...new Set(rows.map((row) => row.method))].sort(),
  [rows],
 );
 const filteredRows = useMemo(
  () =>
   rows.filter((row) => {
    if (method && row.method !== method) return false;
    if (statusClass) {
     if (row.status === null) return false;
     const classDigit = Math.floor(row.status / 100);
     if (String(classDigit) !== statusClass) return false;
    }
    if (annotatedOnly && !row.comment && !row.highlight) return false;
    return true;
   }),
  [rows, method, statusClass, annotatedOnly],
 );

 // Selection is held by id so a background refresh cannot drop it.
 const selected = useMemo(() => filteredRows.find((row) => row.id === selectedId) ?? null, [filteredRows, selectedId]);

 // The comment draft follows the selection (so opening the editor from the row menu or the
 // detail pane always starts from the row's saved text), but is otherwise ordinary editing
 // state. The effect keys on the selection id and its saved comment, not on every refetch,
 // so typing is never clobbered by a background refresh.
 const [commentDraft, setCommentDraft] = useState("");
 const selectedComment = selected?.comment ?? "";
 useEffect(() => {
  setCommentDraft(selectedComment);
 }, [selected?.id, selectedComment]);

 // The tool list comes from the server's histogram rather than a hard-coded set,
 // so a tool that starts logging is filterable without a frontend change.
 const tools = useMemo(() => Object.entries(data?.counts ?? {}).sort(([a], [b]) => a.localeCompare(b)), [data]);

 // The capture axis rides on the same tool names. A tool that is not capturing
 // has its requests sent and deliberately discarded; the checkbox is how the
 // operator turns it back on, and `uncaptured` says how much has been lost.
 const capturing = data?.capturing ?? {};
 const uncaptured = data?.uncaptured ?? {};
 const uncapturedTotal = data?.uncaptured_total ?? 0;
 // The capture filter in force, echoed by the server so the panel renders what the log
 // enforces rather than a second copy of it that could drift from the truth.
 const inForce = data?.filter;
 const scopeAttached = data?.scope_attached ?? false;
 const capacity = data?.capacity ?? 0;
 const filteredTotal = data?.filtered_total ?? 0;
 // Saves the whole capture filter in one round trip (burpsy-react-ui-72k9). An absent axis
 // is untouched server-side, so the toggle-only POST the page already issues and this save
 // never fight. A bad regex comes back 400 with the old filter still in force.
 const saveCaptureFilter = () => {
  const body: {
   filter?: { status: number[]; term: string; regex: boolean; case_sensitive: boolean; negate: boolean; scope_only: boolean };
   capacity?: number;
  } = {};
  if (capStatus.length || capTerm || capScopeOnly) {
   body.filter = {
    status: capStatus.map(Number),
    term: capTerm,
    regex: capRegex,
    case_sensitive: capCase,
    negate: capNegate,
    scope_only: capScopeOnly,
   };
  }
  const parsed = Number.parseInt(capCapacity, 10);
  if (Number.isFinite(parsed) && parsed > 0 && parsed !== capacity) body.capacity = parsed;
  setCapture.mutate(body, {
   onSuccess: () => {
    setCaptureOpen(false);
    toast.success("Capture filter saved — rows it refuses are discarded, not hidden");
   },
   onError: (cause) => toast.error(`Could not save the capture filter: ${cause.message}`),
  });
 };

 const captureToggle = (name: string) => (on: boolean) =>
  setCapture.mutate(
   { tool: name, on },
   {
    onError: (cause) => toast.error(`Could not ${on ? "capture" : "stop capturing"} ${name}: ${cause.message}`),
   },
  );

 const showInHistory = (expression: string) => {
  setHistoryQuery(expression);
  setRoute("history");
 };

 // One mutation per annotation action (burpsy-react-ui-5da). The PATCH carries the whole
 // annotation; an empty highlight clears. Unknown ids 404 and the toast says so.
 const annotate = (row: ToolLogRow, comment: string, highlight: string, done: string) =>
  setAnnotation.mutate(
   { id: row.id, comment, highlight },
   {
    onSuccess: () => toast.success(done),
    onError: (cause) => toast.error(`Could not annotate #${row.id}: ${cause.message}`),
   },
  );

 const columns = useMemo<Column<ToolLogRow>[]>(
  () => [
   {
    id: "highlight",
    header: "#",
    size: 40,
    // Burp's annotation column: the colour swatch (or an em dash when unpainted). Hidden
    // from the menu like Age — it is the row's identity marker in the annotation model.
    enableHiding: false,
    accessorFn: (row) => row.highlight,
    cell: (info) => {
     const value = info.getValue<string>();
     return value ? (
      <span className="menu-swatch" style={{ "--swatch-color": `var(--highlight-${value})` } as CSSProperties} title={value} />
     ) : (
      <span className="cell-dim">—</span>
     );
    },
   },
   {
    accessorKey: "started_ms",
    header: "Age",
    size: 84,
    // The only column that always identifies which log entry a row is, so
    // — like an id column — it stays off the show/hide menu.
    enableHiding: false,
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
    // A row with no response gets an em dash, the same mark the Error column
    // uses for "nothing to report". It must not be formatted as 0 B: this
    // column showed "0 B" on every row until the server started sending a
    // real count, and a column of zeroes reads as "every response was
    // empty" rather than as an unimplemented field.
    cell: (info) => {
     const value = info.getValue<number | null>();
     return value === null ? <span className="cell-dim">—</span> : <span className="cell-num">{formatBytes(value)}</span>;
    },
   },
   {
    accessorKey: "duration_ms",
    header: "Time",
    size: 78,
    cell: (info) => <span className="cell-num">{formatDuration(info.getValue<number>())}</span>,
   },
   {
    accessorKey: "comment",
    header: "Comment",
    size: 220,
    cell: (info) => {
     const value = info.getValue<string>();
     return value ? <span title={value}>{value}</span> : <span className="cell-dim">—</span>;
    },
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
     {
      label: "Response length",
      value: selected.response_len === null ? "no response received" : formatBytes(selected.response_len),
     },
     {
      label: "Error",
      value: selected.error ? <span className="bad-text">{selected.error}</span> : "none reported",
     },
     {
      label: "Highlight",
      value: selected.highlight ? <Badge tone={HIGHLIGHT_TONE[selected.highlight]}>{selected.highlight}</Badge> : "none",
     },
    ]}
   />
   {/* The comment editor (burpsy-react-ui-5da): double-click on Burp's Comment column becomes
          the detail pane's always-visible input here. Saving PATCHes the whole annotation; an
          empty draft clears, so clearing is deleting the text, not a separate menu act. */}
   <div className="annotation-editor">
    <Input
     aria-label="Comment on this log entry"
     value={commentDraft}
     onChange={(event) => setCommentDraft(event.target.value)}
     placeholder="Add a comment…"
    />
    <Button
     variant="outline"
     size="small"
     disabled={setAnnotation.isPending || commentDraft === (selected.comment ?? "")}
     onClick={() => annotate(selected, commentDraft, selected.highlight, commentDraft ? "Comment saved" : "Comment cleared")}
    >
     <MessageSquare size={13} />
     Save comment
    </Button>
   </div>
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
       {/* The honest-counting half of the capture axis: requests that were sent
                  and deliberately not kept read as a real number here, never as a short
                  log. Shown whenever any tool has capture off. */}
       {uncapturedTotal > 0 ? (
        <Badge tone="bad">
         {uncapturedTotal.toLocaleString()} sent, not captured
        </Badge>
       ) : null}
       <Button
        variant="outline"
        onClick={() => {
         // Exports the loaded (filtered) view — the same rule History's button follows.
         if (filteredRows.length === 0) {
          toast.error("No log entries to export");
          return;
         }
         downloadText("toollog.csv", toolLogToCSV(filteredRows), "text/csv");
         toast.success(`Exported ${filteredRows.length} log entries to CSV`);
        }}
       >
        Export CSV
       </Button>
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
     <Select aria-label="Method filter" value={method} onChange={(event) => setMethod(event.target.value)} style={{ maxWidth: "var(--w-xs)" }}>
      <option value="">Any method</option>
      {methods.map((name) => (
       <option key={name} value={name}>
        {name}
       </option>
      ))}
     </Select>
     <Select aria-label="Status class filter" value={statusClass} onChange={(event) => setStatusClass(event.target.value)} style={{ maxWidth: "var(--w-xs)" }}>
      <option value="">Any status</option>
      <option value="2">2xx</option>
      <option value="3">3xx</option>
      <option value="4">4xx</option>
      <option value="5">5xx</option>
      <option value="0">no response</option>
     </Select>
     {/* Burp pairs annotation with a filter (filter/view.html: "Filter by annotation — show
              only items that have been annotated, either by a comment or highlight"). Here that
              is one toggle over both fields, since the two are one act of attention. */}
     <Checkbox checked={annotatedOnly} onCheckedChange={setAnnotatedOnly} label="Annotated only" />
    </Toolbar>
    {/* Capture axis — the second, destructive axis Burp Logger keeps separate
            from display. Each checkbox controls whether that tool's requests are
            recorded at all; switching off means the next requests are sent and not
            kept, and the per-tool `uncaptured` count states the loss rather than
            letting it read as an empty log. Shown as its own quietly-labelled row
            so it can never be mistaken for one of the display filters above. */}
    <div className="toolbar capture-axis" style={{ marginTop: 4 }}>
     <span className="cell-dim" aria-hidden="true">
      Capture
     </span>
     <Button variant="quiet" size="small" aria-expanded={captureOpen} onClick={() => setCaptureOpen((open) => !open)}>
      <FolderTree size={13} />
      Filter settings
      {inForce && (inForce.status.length > 0 || inForce.term || inForce.scope_only) ? " (active)" : ""}
     </Button>
     {filteredTotal > 0 ? (
      <Badge tone="warn">{filteredTotal.toLocaleString()} refused by filter</Badge>
     ) : null}
     {tools.map(([name]) => {
      const on = capturing[name] !== false;
      return (
       <Checkbox
        key={name}
        checked={on}
        onCheckedChange={captureToggle(name)}
        label={uncaptured[name] ? `${name} (${uncaptured[name].toLocaleString()} not captured)` : name}
       />
      );
     })}
    </div>
    {captureOpen ? (
     <div className="toolbar capture-filter-panel" role="group" aria-label="Capture filter settings">
      {/* Every axis here is destructive and labelled so: unlike the display filters
            above, refusing a row means the log never sees it at all. */}
      <BucketMenu
       label="Status"
       buckets={[
        { value: "2", label: "2xx" },
        { value: "3", label: "3xx" },
        { value: "4", label: "4xx" },
        { value: "5", label: "5xx" },
       ]}
       selected={capStatus}
       onToggle={(value) => setCapStatus((current) => (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]))}
       onReset={() => setCapStatus([])}
      />
      <div className="search-field">
       <Search size={15} />
       <Input aria-label="Capture filter search term" value={capTerm} onChange={(event) => setCapTerm(event.target.value)} placeholder="capture only matching (method, host, path)" style={{ minWidth: 220 }} />
      </div>
      <Checkbox checked={capRegex} onCheckedChange={setCapRegex} label="Regex" />
      <Checkbox checked={capCase} onCheckedChange={setCapCase} label="Case sensitive" />
      <Checkbox checked={capNegate} onCheckedChange={setCapNegate} label="Negative" />
      <Checkbox checked={capScopeOnly} onCheckedChange={setCapScopeOnly} label={scopeAttached ? "In-scope only" : "In-scope only (no scope loaded — inert)"} />
      <Field label="Capture limit (rows)">
       <Input
        aria-label="Capture limit in rows"
        value={capCapacity}
        onChange={(event) => setCapCapacity(event.target.value)}
        placeholder={String(capacity)}
        style={{ maxWidth: "var(--w-xs)" }}
        inputMode="numeric"
       />
      </Field>
      <div className="detail-actions">
       <Button size="small" onClick={saveCaptureFilter} disabled={setCapture.isPending}>
        Save capture filter
       </Button>
       <Button
        variant="outline"
        size="small"
        onClick={() => {
         setCapStatus([]);
         setCapTerm("");
         setCapRegex(false);
         setCapCase(false);
         setCapNegate(false);
         setCapScopeOnly(false);
        }}
       >
        Reset axes (not yet saved)
       </Button>
      </div>
     </div>
    ) : null}
    {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   </div>

   <SplitPane
    storageId="toollog"
    orientation="vertical"
    defaultMasterSize="64"
    master={
     <VirtualTable
      ariaLabel="Requests sent by burpsy's own tools"
      data={filteredRows}
      columns={columns}
      getRowId={(row) => String(row.id)}
      selectedId={selectedId === null ? null : String(selectedId)}
      onSelect={(row) => setSelectedId(row.id)}
      enableColumnVisibility
      columnVisibility={columnVisibility}
      onColumnVisibilityChange={setColumnVisibility}
      menuGroups={(row) => [
       {
        id: "annotate",
        actions: [
         {
          id: "comment",
          label: row.comment ? "Edit comment" : "Add comment",
          icon: MessageSquare,
          onSelect: () => {
           setSelectedId(row.id);
          },
         },
        ],
       },
       {
        id: "colours",
        actions: HIGHLIGHTS.map((name) => {
         // "none" is the picker sentinel; the wire value for no highlight is "",
         // the same translation the history page's menu does.
         const wire = name === "none" ? "" : name;
         return {
          id: name,
          label: name === "none" ? "Clear highlight" : name.charAt(0).toUpperCase() + name.slice(1),
          icon: HIGHLIGHT_ICONS[name],
          disabled: row.highlight === wire,
          onSelect: () => annotate(row, row.comment, wire, wire === "" ? `Highlight cleared on #${row.id}` : `#${row.id} highlighted ${wire}`),
         };
        }),
       },
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
       cn(
        row.error !== null || row.status === null || row.status >= 500
         ? "row-flag-bad"
         : row.status >= 400
          ? "row-flag-warn"
          : undefined,
        // Same per-colour tint classes the history and site-map tables use, so a
        // highlighted row looks the same in every tool (see styles.css Task 5).
        row.highlight ? cn("row-highlight", `row-highlight-${row.highlight}`) : undefined,
       )
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
