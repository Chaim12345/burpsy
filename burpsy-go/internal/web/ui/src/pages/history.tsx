import { useEffect, useMemo, useState } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { Columns3, Combine, Crosshair, HelpCircle, Repeat2, Search, X } from "lucide-react";
import { toast } from "sonner";
import { useExchangeActions, exchangeUrl } from "../lib/actions";
import { formatBytes, formatDuration, relativeTime, statusTone } from "../lib/api";
import { useDebounced, useHistory, useMessage } from "../lib/data";
import { useApp } from "../lib/store";
import type { Exchange } from "../lib/types";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Button, Empty, ErrorNotice, IconButton, Input, Modal, Select, Toolbar, Tooltip } from "../ui/primitives";
import { VirtualTable, type Column } from "../ui/table";

const STATUS_BUCKETS = [
  { value: "all", label: "All statuses" },
  { value: "2", label: "2xx success" },
  { value: "3", label: "3xx redirect" },
  { value: "4", label: "4xx client" },
  { value: "5", label: "5xx server" },
  { value: "none", label: "No response" },
];

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function QueryHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Filter syntax" description="The filter box is sent to the server as a query expression.">
      <div className="prose">
        {[
          "host = api.example.com",
          "host ~ example          (substring match)",
          "status = 500",
          "status >= 400",
          "method = POST",
          "path ~ /admin",
          "body ~ password",
          'host = api.example.com AND status >= 400',
          "method = POST OR method = PUT",
        ].join("\n")}
      </div>
      <p className="field-hint">
        The fields are host, status, method, path, mime and body — every term needs an operator and a value. host and
        mime ignore case; method and path do not. Clear the box to return to the full capture.
      </p>
    </Modal>
  );
}

export function HistoryPage(): JSX.Element {
  const historyQuery = useApp((state) => state.historyQuery);
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);
  const historyFocus = useApp((state) => state.historyFocus);
  const focusExchange = useApp((state) => state.focusExchange);

  const [term, setTerm] = useState(historyQuery);
  const [status, setStatus] = useState("all");
  const [method, setMethod] = useState("all");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [limit, setLimit] = useState(500);
  const [inspector, setInspector] = useState(true);

  const debouncedTerm = useDebounced(term, 260);
  const { data, error, isFetching, refetch } = useHistory(debouncedTerm, limit);
  const actions = useExchangeActions();

  // Another page asked to filter here (for example "filter by this host").
  useEffect(() => {
    if (!historyQuery) return;
    setTerm(historyQuery);
    setHistoryQuery("");
  }, [historyQuery, setHistoryQuery]);

  // Another page asked to reveal one exchange.
  useEffect(() => {
    if (historyFocus === null) return;
    setSelectedId(historyFocus);
    focusExchange(null);
  }, [historyFocus, focusExchange]);

  const rows = useMemo(() => {
    const all = data ?? [];
    return all.filter((row) => {
      if (method !== "all" && row.method !== method) return false;
      if (status === "all") return true;
      if (status === "none") return row.status === null;
      return row.status !== null && String(row.status).startsWith(status);
    });
  }, [data, method, status]);

  // Selection is held by id, not by object identity, so a background refresh
  // cannot silently drop the operator's selection.
  const selected = useMemo(() => rows.find((row) => row.id === selectedId) ?? null, [rows, selectedId]);

  // Burp's signature bindings, on the selected row. ctrl+R overrides the browser's
  // reload: for a Burp user that combination means "send to Repeater" and nothing else.
  useHotkeys(
    "mod+r",
    (event) => {
      if (!selected) return;
      event.preventDefault();
      void actions.sendToRepeater(selected);
    },
    { enableOnFormTags: false },
    [selected, actions],
  );
  useHotkeys(
    "mod+i",
    (event) => {
      if (!selected) return;
      event.preventDefault();
      actions.sendToIntruder(selected);
    },
    { enableOnFormTags: false },
    [selected, actions],
  );

  const request = useMessage(selected?.request);
  const response = useMessage(selected?.response ?? null);

  const columns = useMemo<Column<Exchange>[]>(
    () => [
      { accessorKey: "id", header: "#", size: 62, cell: (info) => <span className="cell-num">{info.getValue<number>()}</span> },
      {
        accessorKey: "method",
        header: "Method",
        size: 74,
        cell: (info) => <Badge tone="info">{info.getValue<string>()}</Badge>,
      },
      {
        id: "authority",
        header: "Host",
        size: 190,
        accessorFn: (row) => `${row.host}:${row.port}`,
        cell: (info) => <span title={info.getValue<string>()}>{info.getValue<string>()}</span>,
      },
      {
        accessorKey: "path",
        header: "Path",
        size: 330,
        cell: (info) => <code title={info.getValue<string>()}>{info.getValue<string>()}</code>,
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
        accessorKey: "mime",
        header: "Type",
        size: 92,
        cell: (info) => <span className="cell-dim">{info.getValue<string | undefined>() || "—"}</span>,
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
        accessorKey: "started_ms",
        header: "Age",
        size: 84,
        cell: (info) => <span className="cell-dim">{relativeTime(info.getValue<number>())}</span>,
      },
    ],
    [],
  );

  const detail = selected ? (
    <div className="tabs-fill">
      <div className="detail-head">
        <div className="detail-head-title">
          <span className="eyebrow">#{selected.id}</span>
          <strong title={exchangeUrl(selected)}>
            {selected.method} {exchangeUrl(selected)}
          </strong>
        </div>
        <div className="detail-actions">
          <Badge tone={statusTone(selected.status)}>{selected.status ?? "pending"}</Badge>
          <Badge>{formatDuration(selected.duration_ms)}</Badge>
          <Badge>{selected.protocol}</Badge>
          <Button variant="outline" size="small" onClick={() => void actions.sendToRepeater(selected)}>
            <Repeat2 size={13} />
            Repeater
          </Button>
          <Button variant="outline" size="small" onClick={() => actions.sendToIntruder(selected)}>
            <Crosshair size={13} />
            Intruder
          </Button>
          <Button variant="outline" size="small" onClick={() => void actions.sendToComparer(selected, "a")}>
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
          <IconButton label="Clear selection" size="small" onClick={() => setSelectedId(null)}>
            <X size={13} />
          </IconButton>
        </div>
      </div>
      <div className={inspector ? "editor-grid-inspected" : "editor-grid"}>
        <HttpEditor
          label="Request"
          readOnly
          value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
          filename={`exchange-${selected.id}-request.txt`}
        />
        <HttpEditor
          label="Response"
          readOnly
          value={
            selected.response === null
              ? "No response was captured for this exchange."
              : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."))
          }
          filename={`exchange-${selected.id}-response.txt`}
        />
        {inspector ? <Inspector raw={request.data?.text ?? ""} label="Inspector · request" /> : null}
      </div>
    </div>
  ) : (
    <Empty
      title="No exchange selected"
      detail="Choose a row to read its exact request and response bytes. Arrow keys move through the table; right-click a row for send-to actions."
    />
  );

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="HTTP history"
          actions={
            <>
              <Badge tone={rows.length === data?.length ? "neutral" : "info"}>
                {rows.length.toLocaleString()}
                {data && rows.length !== data.length ? ` / ${data.length.toLocaleString()}` : ""} rows
              </Badge>
              <RefreshButton onClick={() => void refetch()} loading={isFetching} />
            </>
          }
        />
        <Toolbar style={{ marginTop: 10 }}>
          <div className="search-field">
            <Search size={15} />
            <Input
              aria-label="Filter history"
              value={term}
              onChange={(event) => setTerm(event.target.value)}
              placeholder="host = api.example AND status >= 400"
            />
            {term ? (
              <IconButton label="Clear filter" size="small" onClick={() => setTerm("")}>
                <X size={13} />
              </IconButton>
            ) : null}
            <Tooltip content="Filter syntax">
              <button type="button" className="icon-button icon-button-sm" aria-label="Filter syntax" onClick={() => setHelpOpen(true)}>
                <HelpCircle size={13} />
              </button>
            </Tooltip>
          </div>
          <Select aria-label="Status filter" value={status} onChange={(event) => setStatus(event.target.value)} style={{ maxWidth: "var(--w-sm)" }}>
            {STATUS_BUCKETS.map((bucket) => (
              <option key={bucket.value} value={bucket.value}>
                {bucket.label}
              </option>
            ))}
          </Select>
          <Select aria-label="Method filter" value={method} onChange={(event) => setMethod(event.target.value)} style={{ maxWidth: "var(--w-xs)" }}>
            <option value="all">All methods</option>
            {METHODS.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </Select>
          <Select
            aria-label="Row limit"
            value={String(limit)}
            onChange={(event) => setLimit(Number(event.target.value))}
            style={{ maxWidth: "var(--w-xs)" }}
          >
            {[200, 500, 1000, 5000].map((value) => (
              <option key={value} value={value}>
                last {value}
              </option>
            ))}
          </Select>
        </Toolbar>
        {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      </div>

      <SplitPane
        storageId="history"
        orientation="vertical"
        defaultMasterSize="46"
        master={
          <VirtualTable
            ariaLabel="Captured HTTP exchanges"
            data={rows}
            columns={columns}
            getRowId={(row) => String(row.id)}
            selectedId={selectedId === null ? null : String(selectedId)}
            onSelect={(row) => setSelectedId(row.id)}
            onActivate={(row) => void actions.sendToRepeater(row)}
            menuGroups={(row) =>
              actions.menu(row, [
                {
                  id: "inspect",
                  actions: [
                    {
                      id: "copy-response",
                      label: "Copy response bytes",
                      onSelect: () => {
                        if (row.response === null) {
                          toast.error("This exchange has no response");
                          return;
                        }
                        setSelectedId(row.id);
                      },
                    },
                  ],
                },
              ])
            }
            rowClassName={(row) =>
              row.status !== null && row.status >= 500 ? "row-flag-bad" : row.status !== null && row.status >= 400 ? "row-flag-warn" : undefined
            }
            loading={isFetching && !data}
            empty={
              <Empty
                title={term ? "No exchange matches this filter" : "No traffic captured yet"}
                detail={
                  term
                    ? "Relax the filter, or clear it to see the whole capture."
                    : "Point a client at the proxy and install the CA certificate to start capturing HTTPS."
                }
              />
            }
          />
        }
        detail={detail}
      />
      <QueryHelp open={helpOpen} onOpenChange={setHelpOpen} />
    </div>
  );
}
