import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { FolderTree, Link2, MessageSquare, Search, ShieldCheck, Terminal, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { cn } from "../lib/cn";
import { useExchangeActions } from "../lib/actions";
import { distinctHosts } from "../lib/actions-many";
import { sanitizeSettings } from "../lib/filter-presets";
import { FilterPresetsMenu } from "../ui/filter-presets";
import { copyToClipboard, downloadText, formatBytes, formatDuration, relativeTime, statusTone, toolLogToCSV } from "../lib/api";
import { useClearToolLog, useDebounced, useMessage } from "../lib/data";
import { useExchange } from "../lib/data.observe";
import { useSetToolLogCapture, useSetToolLogComment, useToolLogView } from "../lib/data.workbench";
import { useHistoryExtractors, useHistoryExtractValues, type ExtractValues } from "../lib/data.extractors";
import { extractorColumnId, extractorSignature } from "../lib/extractors";
import { ExtractorCell } from "../ui/extractor-manager";
import { useApp } from "../lib/store";
import { HIGHLIGHTS, HIGHLIGHT_TONE, highlightName } from "../lib/types";
import { HIGHLIGHT_ICONS } from "../ui/highlight-icons";
import type { ToolLogRow } from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { DetailList } from "../ui/json";
import { PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Button, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Toolbar } from "../ui/primitives";
import { BucketMenu } from "../ui/column-visibility-menu";
import { VirtualTable, type Column, type VisibilityState } from "../ui/table";

/**
 * A logged row records a request burpsy made or relayed — one of its own tools, or
 * the proxy listener (burpsy-react-ui-6dt). The log carries
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
 * The bytes behind a logged row, resolved on demand through the row's exchange
 * link: /api/exchange for the id pair, /api/message for each half — the same
 * exchange-id-then-fetch pattern wshistory and repeater use when they start
 * from an id. The log never stores its own copy of the bytes; the traffic store
 * holds them once and Burp's capture limit manages that, so a second copy would
 * double the memory a capture setting accounts for.
 *
 * The link can dangle — a row restored from an older database against a
 * traffic store that no longer holds that exchange — and a dangling link is
 * shown as exactly that ("no longer in the traffic store"), not as an empty
 * editor, which would read as "this exchange was empty".
 */
function LogBytesViewer({ row }: { row: ToolLogRow }): JSX.Element {
 const exchangeId = row.exchange;
 if (exchangeId === null) {
  return (
   <Empty
    title="No message bytes for this row"
    detail="This row has timing and error text only: the send never produced a stored exchange (a transport failure, or a row standing for a whole run such as an audit). Rows logged before bytes were linked carry no exchange either."
   />
  );
 }

 return <LinkedBytes exchangeId={exchangeId} rowId={row.id} />;
}

function LinkedBytes({ exchangeId, rowId }: { exchangeId: number; rowId: number }): JSX.Element {
 const exchange = useExchange(exchangeId);
 const request = useMessage(exchange.data?.request);
 const response = useMessage(exchange.data?.response ?? null);

 if (exchange.isFetching && !exchange.data) {
  return <Empty title="Loading message bytes…" detail={`Resolving exchange #${exchangeId} in the traffic store.`} />;
 }
 if (exchange.error || !exchange.data) {
  return (
   <Empty
    title="Message bytes unavailable"
    detail={`This row points at exchange #${exchangeId}, which is no longer in the traffic store. The metadata above is everything the log still holds for it.`}
   />
  );
 }
 const requestText = request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.");
 const responseText =
  exchange.data.response === null
   ? "No response was captured for this exchange."
   : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."));
 return (
  <div className="editor-grid" style={{ minHeight: 240 }}>
   <HttpEditor
    label="Request"
    readOnly
    value={requestText}
    bodyBase64={request.data?.body_base64}
    filename={`toollog-${rowId}-request.txt`}
   />
   <HttpEditor
    label="Response"
    readOnly
    value={responseText}
    bodyBase64={exchange.data.response === null ? undefined : response.data?.body_base64}
    requestPath={exchange.data.path}
    filename={`toollog-${rowId}-response.txt`}
   />
  </div>
 );
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
 // Burp's "Capture by MIME type" (burpsy-react-ui-73vm), as the EXCLUSION list the server holds:
 // each entry is a media type whose rows are refused, so an empty box captures everything. Held as
 // text because the set is open — core.MimeEssence produces whatever a target actually serves, not
 // Burp's fixed category list — and split on save.
 const [capMime, setCapMime] = useState("");
 const [capCase, setCapCase] = useState(false);
 const [capNegate, setCapNegate] = useState(false);
 const [capScopeOnly, setCapScopeOnly] = useState(false);
 const [capCapacity, setCapCapacity] = useState("");
 const [columnVisibility, setColumnVisibility] = useStoredColumnVisibility("logger.columns");

 // Burp Logger's view filter (filter/view.html), judged by the server over rows already recorded and
 // reversible — unlike the Capture row below, which decides what is recorded at all (uvpb).
 const [viewScopeOnly, setViewScopeOnly] = useState(false);
 const [viewHasResponse, setViewHasResponse] = useState(false);
 const [viewParameterized, setViewParameterized] = useState(false);
 const [viewMime, setViewMime] = useState("");
 const [viewExt, setViewExt] = useState("");
 const debouncedTerm = useDebounced(term, 260);
 const debouncedMime = useDebounced(viewMime, 260);
 const debouncedExt = useDebounced(viewExt, 260);
 const { data, error, isFetching, refetch } = useToolLogView(tool, debouncedTerm, 1_000, {
  scopeOnly: viewScopeOnly,
  hasResponse: viewHasResponse,
  parameterized: viewParameterized,
  mime: debouncedMime,
  ext: debouncedExt,
 });
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
 const methods = useMemo(() => [...new Set(rows.map((row) => row.method))].sort(), [rows]);
 const filteredRows = useMemo(
  () =>
   rows.filter((row) => {
    if (method && row.method !== method) return false;
    if (statusClass) {
     if (row.status === null) return false;
     const classDigit = Math.floor(row.status / 100);
     if (String(classDigit) !== statusClass) return false;
    }
    if (annotatedOnly && !row.comment && !highlightName(row.highlight)) return false;
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
   filter?: {
    status: number[];
    term: string;
    regex: boolean;
    case_sensitive: boolean;
    negate: boolean;
    scope_only: boolean;
    mime: string[];
   };
   capacity?: number;
  } = {};
  const mimeList = capMime
   .split(",")
   .map((t) => t.trim().toLowerCase())
   .filter(Boolean);
  if (capStatus.length || capTerm || capScopeOnly || mimeList.length) {
   body.filter = {
    status: capStatus.map(Number),
    term: capTerm,
    regex: capRegex,
    case_sensitive: capCase,
    negate: capNegate,
    scope_only: capScopeOnly,
    mime: mimeList,
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

 // Scope writes go through the same handler History's menu uses, so the toast and the scope-query
 // refresh are the same wherever the operator adds a host from.
 const { addHostsToScope } = useExchangeActions();
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

 // Custom extractor columns (n3sy): the SAME saved definitions HTTP history and Intruder use, run
 // against each row's linked exchange — no second extractor model. A row with no linked exchange (a
 // transport failure, a whole-run row) has no response to read and shows a dash.
 const extractorsQuery = useHistoryExtractors();
 const savedExtractors = useMemo(() => extractorsQuery.data?.extractors ?? [], [extractorsQuery.data]);
 const extractorSig = useMemo(() => extractorSignature(savedExtractors), [savedExtractors]);
 const extractIdsKey = useMemo(
  () =>
   [...new Set(filteredRows.filter((row) => row.exchange !== null && row.response_len !== null).map((row) => row.exchange as number))]
    .sort((a, b) => a - b)
    .join(","),
  [filteredRows],
 );
 const debouncedExtractIdsKey = useDebounced(extractIdsKey, 300);
 const extractIds = useMemo(
  () => (debouncedExtractIdsKey === "" ? [] : debouncedExtractIdsKey.split(",").map(Number)),
  [debouncedExtractIdsKey],
 );
 const extractValues = useHistoryExtractValues(extractIds, extractorSig, savedExtractors.length > 0);
 const extractValuesMap: ExtractValues | undefined = extractValues.data;
 const extractLoading = savedExtractors.length > 0 && extractIds.length > 0 && (extractValues.isPending || extractValues.isPlaceholderData);
 const extractFailed = extractValues.isError;

 const columns = useMemo<Column<ToolLogRow>[]>(
  () => [
   {
    id: "highlight",
    header: "#",
    size: 40,
    // Burp's annotation column: the colour swatch (or an em dash when unpainted). Hidden
    // from the menu like Age — it is the row's identity marker in the annotation model.
    enableHiding: false,
    accessorFn: (row) => highlightName(row.highlight),
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
   ...savedExtractors.map(
    (extractor): Column<ToolLogRow> => ({
     id: extractorColumnId(extractor.name),
     header: extractor.name,
     size: 150,
     sortUndefined: "last",
     accessorFn: (row: ToolLogRow) => {
      const value = row.exchange === null ? undefined : extractValuesMap?.[String(row.exchange)]?.[extractor.name];
      return value == null ? undefined : value;
     },
     cell: (info) => {
      const row = info.row.original;
      return (
       <ExtractorCell
        value={row.exchange === null ? undefined : extractValuesMap?.[String(row.exchange)]?.[extractor.name]}
        hasResponse={row.exchange !== null && row.response_len !== null}
        loading={extractLoading}
        failed={extractFailed}
        noResponseTitle="This log row has no stored exchange to read"
       />
      );
     },
    }),
   ),
  ],
  [savedExtractors, extractValuesMap, extractLoading, extractFailed],
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
      value: highlightName(selected.highlight) ? (
       <Badge tone={HIGHLIGHT_TONE[highlightName(selected.highlight)] ?? "neutral"}>{highlightName(selected.highlight)}</Badge>
      ) : (
       "none"
      ),
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
   {/* The bytes behind the row, when the send produced a stored exchange (burpsy-react-ui-5bl):
          shown under the metadata and the annotation editor rather than instead of them, because the
          timings and the error text are the log's own contribution and stay readable while the
          editors load. */}
   <LogBytesViewer row={selected} />
  </div>
 ) : (
  <Empty
   title="No row selected"
   detail="Choose a logged request to read its timing, error text and — where the send produced a stored exchange — its request and response bytes. Right-click a row to copy its URL or jump to the same host in HTTP history."
  />
 );

 return (
  <div className="page-fill">
   <div>
    <PageHeader
     title="Tool log"
     settingsSection="logging"
     actions={
      <>
       <Badge tone="info">
        {(data?.shown ?? 0).toLocaleString()} of {(data?.total ?? 0).toLocaleString()} shown
       </Badge>
       {/* A log that silently truncates is misleading, so the discard count is
                  always on screen — not only when someone opens a detail pane. */}
       <Badge tone={data && data.dropped > 0 ? "warn" : "neutral"}>{(data?.dropped ?? 0).toLocaleString()} dropped</Badge>
       {/* The honest-counting half of the capture axis: requests that were sent
                  and deliberately not kept read as a real number here, never as a short
                  log. Shown whenever any tool has capture off. */}
       {uncapturedTotal > 0 ? <Badge tone="bad">{uncapturedTotal.toLocaleString()} sent, not captured</Badge> : null}
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
     <Select
      aria-label="Method filter"
      value={method}
      onChange={(event) => setMethod(event.target.value)}
      style={{ maxWidth: "var(--w-xs)" }}
     >
      <option value="">Any method</option>
      {methods.map((name) => (
       <option key={name} value={name}>
        {name}
       </option>
      ))}
     </Select>
     <Select
      aria-label="Status class filter"
      value={statusClass}
      onChange={(event) => setStatusClass(event.target.value)}
      style={{ maxWidth: "var(--w-xs)" }}
     >
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
     {/* Burp Logger's view filter axes (uvpb) — reversible, judged by the server against the scope as
         it is now. Not to be confused with the Capture row below, which decides what is recorded. */}
     <Checkbox checked={viewScopeOnly} onCheckedChange={setViewScopeOnly} label="In-scope only" />
     <Checkbox checked={viewHasResponse} onCheckedChange={setViewHasResponse} label="Hide items without responses" />
     <Checkbox checked={viewParameterized} onCheckedChange={setViewParameterized} label="Parameterized only" />
     <Input
      aria-label="Show only these MIME types"
      title="Show only these response MIME types, comma-separated (e.g. text/html,application/json)"
      value={viewMime}
      onChange={(event) => setViewMime(event.target.value)}
      placeholder="MIME types"
      style={{ maxWidth: "var(--w-sm)" }}
     />
     <Input
      aria-label="Show only these file extensions"
      title="Show only these file extensions, comma-separated (e.g. js,json)"
      value={viewExt}
      onChange={(event) => setViewExt(event.target.value)}
      placeholder="extensions"
      style={{ maxWidth: "var(--w-xs)" }}
     />
     {/* Saved display filters (mntt), including the view filter axes above (3dyy). The capture
         filter below is server configuration with its own Save button, and is not part of a
         display preset. */}
     <FilterPresetsMenu
      table="logger"
      current={{ tool, term, annotatedOnly, method, statusClass, viewScopeOnly, viewHasResponse, viewParameterized, viewMime, viewExt }}
      apply={(next) => {
       const v = sanitizeSettings("logger", next).settings;
       setTool(v.tool as string);
       setTerm(v.term as string);
       setAnnotatedOnly(v.annotatedOnly as boolean);
       setMethod(v.method as string);
       setStatusClass(v.statusClass as string);
       setViewScopeOnly(v.viewScopeOnly as boolean);
       setViewHasResponse(v.viewHasResponse as boolean);
       setViewParameterized(v.viewParameterized as boolean);
       setViewMime(v.viewMime as string);
       setViewExt(v.viewExt as string);
      }}
     />
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
     {filteredTotal > 0 ? <Badge tone="warn">{filteredTotal.toLocaleString()} refused by filter</Badge> : null}
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
       <Input
        aria-label="Capture filter search term"
        value={capTerm}
        onChange={(event) => setCapTerm(event.target.value)}
        placeholder="capture only matching (method, host, path)"
        style={{ minWidth: 220 }}
       />
      </div>
      <Checkbox checked={capRegex} onCheckedChange={setCapRegex} label="Regex" />
      <Checkbox checked={capCase} onCheckedChange={setCapCase} label="Case sensitive" />
      <Checkbox checked={capNegate} onCheckedChange={setCapNegate} label="Negative" />
      <Checkbox
       checked={capScopeOnly}
       onCheckedChange={setCapScopeOnly}
       label={scopeAttached ? "In-scope only" : "In-scope only (no scope loaded — inert)"}
      />
      <Field
       label="Exclude MIME types"
       hint="Comma-separated media types to refuse: an exact type/subtype, or type/* for a whole family — e.g. image/*, font/woff2. Empty captures everything. A pattern that is neither shape is refused with the reason rather than quietly kept, and a row whose response declared no type is never refused by this."
      >
       <Input
        aria-label="Exclude MIME types from capture"
        value={capMime}
        onChange={(event) => setCapMime(event.target.value)}
        placeholder="image/*, font/woff2"
        style={{ minWidth: 240 }}
       />
      </Field>
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
         setCapMime("");
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
      ariaLabel="Requests burpsy made or relayed"
      docTopic="logger"
      data={filteredRows}
      columns={columns}
      getRowId={(row) => String(row.id)}
      selectedId={selectedId === null ? null : String(selectedId)}
      onSelect={(row) => setSelectedId(row.id)}
      // Multi-row selection (fe16). Logger rows are log entries, not captured exchanges — many
      // carry no exchange id at all — so the N-row menu is the part that needs only what the log
      // holds: the URLs as logged, and their hosts for scope.
      multiSelect
      menuGroupsMany={(rows) => {
       const hosts = distinctHosts(rows);
       return [
        {
         id: "selection",
         title: `${rows.length.toLocaleString()} selected items`,
         actions: [
          {
           id: "copy-urls",
           label: `Copy URLs as logged (${rows.length.toLocaleString()})`,
           icon: Link2,
           onSelect: () => {
            void copyToClipboard(rows.map(rowUrl).join("\n"));
            toast.success(`Copied ${rows.length} URLs`);
           },
          },
          {
           id: "scope",
           label: hosts.length === 1 ? `Add ${hosts[0]} to scope` : `Add ${hosts.length} hosts to scope`,
           icon: ShieldCheck,
           hint: hosts.length > 1 ? hosts.join(", ") : undefined,
           onSelect: () => void addHostsToScope(hosts),
          },
         ],
        },
       ];
      }}
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
          disabled: highlightName(row.highlight) === wire,
          onSelect: () =>
           annotate(row, row.comment, wire, wire === "" ? `Highlight cleared on #${row.id}` : `#${row.id} highlighted ${wire}`),
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
        // Burp: "You can directly add URLs to scope from the Target site map, Proxy history, and
        // Logger" (desktop/testing-workflow/test-scope.html). History and the site map had it
        // through the shared exchange menu; Logger builds its own menu and did not (pahd). The
        // same handler as History's, so the rule written and the toast are the same.
        id: "scope",
        actions: [
         {
          id: "scope",
          label: `Add ${row.host} to scope`,
          icon: ShieldCheck,
          onSelect: () => void addHostsToScope([row.host]),
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
        row.error !== null || row.status === null || row.status >= 500 ? "row-flag-bad" : row.status >= 400 ? "row-flag-warn" : undefined,
        // Same per-colour tint classes the history and site-map tables use, so a
        // highlighted row looks the same in every tool (see styles.css Task 5).
        highlightName(row.highlight) ? cn("row-highlight", `row-highlight-${highlightName(row.highlight)}`) : undefined,
       )
      }
      loading={isFetching && !data}
      empty={
       <Empty
        title={term || tool ? "No logged request matches" : "Nothing logged yet"}
        detail={
         term || tool
          ? "Relax the search or switch back to all tools."
          : "Every request burpsy makes or relays is recorded here — Repeater, Intruder, Scanner, Sequencer, extensions (a plugin's http.send), the crawler and the proxy listener. HTTP history is the same traffic seen as browser requests."
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
