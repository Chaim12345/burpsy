import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { ArrowDownLeft, ArrowRightLeft, ArrowUpRight, Combine, Copy, ExternalLink, FileCode2, FileOutput, X } from "lucide-react";
import { copyToClipboard, downloadText, formatBytes, relativeTime } from "../lib/api";
import { useWsConnections, useWsHistory } from "../lib/data";
import { useExchange, useWsMessageDetailed } from "../lib/data.observe";
import { useMessage } from "../lib/data";
import { useApp } from "../lib/store";
import { useExchangeActions, useSendShortcuts } from "../lib/actions";
import type { WsConnection, WsRow } from "../lib/types";
import type { WsMessageDetail } from "../lib/types.observe";
import { HttpEditor } from "../ui/editor";
import { PageHeader, RefreshButton } from "../ui/layout";
import { Badge, Empty, ErrorNotice, IconButton, Input, Metric, Select, Tabs, TabsContent, TabsList, TabsTrigger, Toolbar } from "../ui/primitives";
import { ContextMenu, type MenuGroup } from "../ui/menu";
import { DetailList } from "../ui/json";
import { VirtualTable, type Column } from "../ui/table";

/** "→ out" / "← in" reads faster in a dense list than the wire's snake_case direction. */
function directionBadge(direction: string): JSX.Element {
 return direction === "client_to_server" ? (
  <Badge tone="info">
   <ArrowUpRight size={11} /> sent
  </Badge>
 ) : (
  <Badge tone="good">
   <ArrowDownLeft size={11} /> recv
  </Badge>
 );
}

function ConnectionRow({
 conn,
 selected,
 onSelect,
 onClear,
 menuGroups,
}: {
 conn: WsConnection;
 selected: boolean;
 onSelect: () => void;
 /** Called instead of onSelect when an already-selected row is clicked: the second click is the
  * deselect, so the promise the empty state makes ("clear the selection to see every frame") has
  * an affordance in the same place the selection was made. */
 onClear: () => void;
 menuGroups: MenuGroup[];
}): JSX.Element {
 const row = (
  <button
   type="button"
   className={selected ? "list-row active" : "list-row"}
   onClick={selected ? onClear : onSelect}
   aria-pressed={selected}
  >
   <div className="list-row-text">
    <strong title={`${conn.host}:${conn.port}${conn.path}`}>
     {conn.host}:{conn.port}
     {conn.path}
    </strong>
    <small>
     {conn.sent} sent · {conn.received} recv · {relativeTime(conn.last_ms)}
    </small>
   </div>
   <Badge>{conn.messages}</Badge>
  </button>
 );
 return <ContextMenu groups={menuGroups}>{row}</ContextMenu>;
}

/** Renders one frame's payload. A frame is one of three disjoint shapes on the wire — text, hex, or
 * a close frame's {code, reason} — and each gets its own presentation rather than a generic dump. */
function PayloadView({ message, isFetching }: { message: WsMessageDetail | undefined; isFetching: boolean }): JSX.Element {
 if (isFetching && !message) return <Empty title="Loading payload…" detail="Fetching the frame's bytes." />;
 if (!message) return <Empty title="No frame selected" detail="Pick a row from the frame table to inspect its payload." />;

 if (message.close) {
  return (
   <div className="detail-panel">
    <DetailList
     rows={[
      { label: "Close code", value: <Badge tone="warn">{message.close.code}</Badge> },
      { label: "Reason", value: message.close.reason || <span className="cell-dim">(no reason given)</span> },
     ]}
    />
   </div>
  );
 }

 if (message.truncated) {
  return (
   <div className="tabs-fill">
    <div className="notice notice-warn">{message.dropped} byte(s) were dropped from this frame; showing only what was kept.</div>
    <HttpEditor
     views={false}
     label={message.opcode === "text" ? "Text payload" : "Hex payload"}
     readOnly
     value={message.opcode === "text" ? message.text : message.hex}
     filename={`ws-message-${message.id}.${message.opcode === "text" ? "txt" : "hex"}`}
    />
   </div>
  );
 }

 return (
  <HttpEditor
   views={false}
   label={message.opcode === "text" ? "Text payload" : "Hex payload"}
   readOnly
   value={message.opcode === "text" ? message.text : message.hex}
   filename={`ws-message-${message.id}.${message.opcode === "text" ? "txt" : "hex"}`}
  />
 );
}

export function WebSocketPage(): JSX.Element {
 const focusExchange = useApp((state) => state.focusExchange);
 const setRoute = useApp((state) => state.setRoute);
 const setComparerSlot = useApp((state) => state.setComparerSlot);
 const setDecoderSeed = useApp((state) => state.setDecoderSeed);
 const actions = useExchangeActions();

 const [selectedExchange, setSelectedExchange] = useState<number | null>(null);
 const [selectedFrameId, setSelectedFrameId] = useState<number | null>(null);
 // The frame-list filter (burpsy-react-ui-5k4): direction, opcode and payload substring.
 // Server-side on /api/ws/history, because a frame's payload bytes are not on the row — a
 // client-side substring filter would run over rows that do not carry the payload and could
 // only ever hide the one frame whose detail fetch had landed. The query key composes with
 // the connection the page already narrows by, so the two halves of the URL (exchange, filter)
 // stay one statement of what is listed.
 const [dirFilter, setDirFilter] = useState<"" | "client_to_server" | "server_to_client">("");
 const [opcodeFilter, setOpcodeFilter] = useState("");
 const [payloadFilter, setPayloadFilter] = useState("");
 const [debouncedPayload, setDebouncedPayload] = useState("");
 useEffect(() => {
  const timer = setTimeout(() => setDebouncedPayload(payloadFilter), 250);
  return () => clearTimeout(timer);
 }, [payloadFilter]);

 const connections = useWsConnections();
 const history = useWsHistory(selectedExchange, {
  direction: dirFilter,
  opcode: opcodeFilter,
  payload: debouncedPayload,
 });
 const frame = useWsMessageDetailed(selectedFrameId);
 // Fetched only for the connection currently under the pointer, so a right-click on any other
 // connection still gets the minimal id-only menu rather than blocking on a fetch.
 const exchangeDetail = useExchange(selectedExchange);
 // The upgrade handshake: the exchange behind a WebSocket connection IS the HTTP request that
 // opened it, so its message ids render through the ordinary message endpoint. Burp shows this
 // pair for every WS connection; without it there is no way to see what negotiated the socket.
 const handshakeRequest = useMessage(exchangeDetail.data?.request ?? null);
 const handshakeResponse = useMessage(exchangeDetail.data?.response ?? null);

 const conns = connections.data ?? [];

 const totals = useMemo(
  () =>
   conns.reduce(
    (acc, c) => ({ frames: acc.frames + c.messages, sent: acc.sent + c.sent, received: acc.received + c.received }),
    { frames: 0, sent: 0, received: 0 },
   ),
  [conns],
 );

 const rows = history.data?.rows ?? [];
 const selectedFrame = useMemo(() => rows.find((row) => row.id === selectedFrameId) ?? null, [rows, selectedFrameId]);

 // The send-to chords, on the connection's own exchange. Burp scopes them to a table row rather
 // than to one tool; without them ctrl+R here reached the browser and reloaded the console.
 useSendShortcuts(exchangeDetail.data ?? null);

 const columns = useMemo<Column<WsRow>[]>(
  () => [
   { accessorKey: "id", header: "#", size: 54, cell: (info) => <span className="cell-num">{info.getValue<number>()}</span> },
   {
    accessorKey: "direction",
    header: "Dir",
    size: 82,
    cell: (info) => directionBadge(info.getValue<string>()),
   },
   { accessorKey: "opcode", header: "Opcode", size: 78, cell: (info) => <code>{info.getValue<string>()}</code> },
   {
    accessorKey: "len",
    header: "Length",
    size: 110,
    cell: (info) => {
     const row = info.row.original;
     return (
      <span className="cell-num">
       {formatBytes(info.getValue<number>())}
       {row.truncated ? (
        <Badge tone="warn" style={{ marginLeft: 6 }}>
         truncated
        </Badge>
       ) : null}
      </span>
     );
    },
   },
   { accessorKey: "at_ms", header: "Age", size: 90, cell: (info) => <span className="cell-dim">{relativeTime(info.getValue<number>())}</span> },
  ],
  [],
 );

 /**
  * A frame's own actions.
  *
  * # Why some entries appear only on the selected frame
  *
  * A frame's payload is not on the row — `WsRow` carries id, direction, opcode, length and time,
  * and the bytes come from a separate per-frame fetch. Right-clicking selects the row, which
  * starts that fetch, so the first right-click on a new frame has no payload in hand yet. The
  * payload actions are therefore offered when the bytes have arrived and withheld when they have
  * not, exactly as the connection menu beside it already withholds the full exchange matrix —
  * a "Copy payload" that silently copied nothing would be worse than one that is not there yet.
  *
  * # What is deliberately absent
  *
  * Comment and highlight. `/api/ws/message/` is GET-only (api_ws.go:184) and a WebSocket frame
  * has no `notes` or `highlight` field on the wire, so there is nothing to write them to. They
  * are not stubbed here: a colour that vanished on the next poll is a worse answer than no
  * colour. Tracked on burpsy-react-ui-nmv as needing the backend fields first.
  */
 const menuForFrame = (row: WsRow): MenuGroup[] => {
  const payload = selectedFrameId === row.id && frame.data && !frame.data.close ? frame.data : null;
  const isText = payload?.opcode === "text";
  const bytes = payload === null ? "" : isText ? payload.text : payload.hex;
  const label = `ws frame #${row.id} ${row.direction === "client_to_server" ? "sent" : "recv"}`;
  return [
   {
    id: "payload",
    title: payload ? (isText ? "Text payload" : "Hex payload") : "Select this frame to act on its payload",
    actions:
     payload === null
      ? []
      : [
       {
        id: "copy-payload",
        label: isText ? "Copy payload text" : "Copy payload as hex",
        icon: Copy,
        onSelect: () => {
         void copyToClipboard(bytes);
         toast.success("Payload copied");
        },
       },
       {
        id: "decoder",
        label: "Send payload to Decoder",
        icon: FileOutput,
        onSelect: () => {
         setDecoderSeed({ label, input: bytes });
         setRoute("decoder");
        },
       },
       {
        id: "compare-a",
        label: "Send payload to Comparer (A)",
        icon: Combine,
        onSelect: () => {
         setComparerSlot("a", bytes);
         setRoute("comparer");
        },
       },
       {
        id: "compare-b",
        label: "Send payload to Comparer (B)",
        icon: ArrowRightLeft,
        onSelect: () => {
         setComparerSlot("b", bytes);
         setRoute("comparer");
        },
       },
       {
        id: "save",
        label: "Save payload to file",
        icon: FileCode2,
        onSelect: () => downloadText(`ws-message-${row.id}.${isText ? "txt" : "hex"}`, bytes),
       },
      ],
   },
   {
    id: "frame",
    actions: [
     {
      id: "copy-id",
      label: `Copy frame id (#${row.id})`,
      icon: Copy,
      onSelect: () => void copyToClipboard(String(row.id)),
     },
     {
      id: "copy-summary",
      label: "Copy frame summary",
      icon: Copy,
      onSelect: () => {
       void copyToClipboard(
        `#${row.id} ${row.direction} ${row.opcode} ${row.len}B ${new Date(row.at_ms).toISOString()}`,
       );
       toast.success("Frame summary copied");
      },
     },
     ...(selectedExchange === null
      ? []
      : [
       {
        id: "show-history",
        label: `Show connection exchange #${selectedExchange} in HTTP history`,
        icon: ExternalLink,
        onSelect: () => {
         focusExchange(selectedExchange);
         setRoute("history");
        },
       },
      ]),
    ],
   },
  ];
 };

 const menuFor = (conn: WsConnection): MenuGroup[] => {
  // A full Exchange (method, protocol, request/response ids) is only in hand for whichever
  // connection is currently selected and has finished loading — everyone else gets the id-only menu.
  if (selectedExchange === conn.exchange && exchangeDetail.data) return actions.menu(exchangeDetail.data);
  return [
   {
    id: "exchange",
    actions: [
     {
      id: "copy-id",
      label: `Copy exchange id (#${conn.exchange})`,
      icon: Copy,
      onSelect: () => void copyToClipboard(String(conn.exchange)),
     },
     {
      id: "show-history",
      label: "Show this exchange in HTTP history",
      icon: ExternalLink,
      onSelect: () => {
       focusExchange(conn.exchange);
       setRoute("history");
      },
     },
    ],
   },
  ];
 };

 const connectionsList =
  conns.length === 0 ? (
   <Empty title="No upgrades observed" detail="WebSocket connections appear here once a client upgrades through the proxy." />
  ) : (
   <div className="row-list">
    {conns.map((conn) => (
     <ConnectionRow
      key={conn.exchange}
      conn={conn}
      selected={selectedExchange === conn.exchange}
      onSelect={() => {
       setSelectedExchange(conn.exchange);
       setSelectedFrameId(null);
      }}
      onClear={() => {
       setSelectedExchange(null);
       setSelectedFrameId(null);
      }}
      menuGroups={menuFor(conn)}
     />
    ))}
   </div>
  );

 const selectedConn = conns.find((c) => c.exchange === selectedExchange) ?? null;
 const hasFilter = dirFilter !== "" || opcodeFilter !== "" || payloadFilter.trim() !== "";

 return (
  <div className="page-fill">
   <div>
    <PageHeader
     title="WebSocket traffic"
     actions={<RefreshButton onClick={() => void connections.refetch()} loading={connections.isFetching} />}
    />
    <div className="metric-grid" style={{ marginTop: 10 }}>
     <Metric label="Connections" value={conns.length} detail="observed" />
     <Metric label="Frames" value={totals.frames.toLocaleString()} detail="total" />
     <Metric label="Sent" value={totals.sent.toLocaleString()} detail="client → server" />
     <Metric label="Received" value={totals.received.toLocaleString()} detail="server → client" />
    </div>
    {connections.error ? <ErrorNotice error={connections.error} onRetry={() => void connections.refetch()} /> : null}
    {history.error ? <ErrorNotice error={history.error} onRetry={() => void history.refetch()} /> : null}
   </div>

   <div className="three-col ws-columns">
    <div className="card card-fill">{connectionsList}</div>

    <div className="card-fill">
     <Toolbar>
      <Select
       aria-label="Filter by direction"
       value={dirFilter}
       onChange={(event) => setDirFilter(event.target.value as "" | "client_to_server" | "server_to_client")}
       style={{ maxWidth: "var(--w-xs)" }}
      >
       <option value="">Both directions</option>
       <option value="client_to_server">Sent</option>
       <option value="server_to_client">Received</option>
      </Select>
      <Select
       aria-label="Filter by opcode"
       value={opcodeFilter}
       onChange={(event) => setOpcodeFilter(event.target.value)}
       style={{ maxWidth: "var(--w-xs)" }}
      >
       <option value="">Any opcode</option>
       <option value="text">text</option>
       <option value="binary">binary</option>
       <option value="ping">ping</option>
       <option value="pong">pong</option>
       <option value="close">close</option>
      </Select>
      <Input
       aria-label="Filter frames"
       value={payloadFilter}
       onChange={(event) => setPayloadFilter(event.target.value)}
       placeholder="Filter frames…"
      />
      {hasFilter ? (
       <IconButton
        label="Clear frame filters"
        size="small"
        onClick={() => {
         setDirFilter("");
         setOpcodeFilter("");
         setPayloadFilter("");
        }}
       >
        <X size={13} />
       </IconButton>
      ) : null}
     </Toolbar>
     <VirtualTable
      ariaLabel="WebSocket frames"
      data={rows}
      columns={columns}
      getRowId={(row) => String(row.id)}
      selectedId={selectedFrameId === null ? null : String(selectedFrameId)}
      onSelect={(row) => setSelectedFrameId(row.id)}
      menuGroups={menuForFrame}
      rowClassName={(row) => (row.truncated ? "row-flag-warn" : undefined)}
      loading={history.isFetching && !history.data}
      empty={
       <Empty
        title={
         hasFilter
          ? "No frames match the filters"
          : selectedExchange === null
           ? "No WebSocket traffic captured yet"
           : "No frames on this connection"
        }
        detail={
         hasFilter
          ? "Clear the filters to see the frames this connection holds."
          : selectedExchange === null
           ? "Point a client at the proxy and upgrade a connection to start capturing frames."
           : "Select another connection, or clear the selection to see every frame."
        }
       />
      }
     />
    </div>

    <div className="card-fill">
     {selectedFrame || selectedExchange !== null ? (
      <Tabs defaultValue="frame" className="tabs-fill">
       <div className="detail-head">
        <TabsList>
         <TabsTrigger value="frame">Frame</TabsTrigger>
         <TabsTrigger value="handshake" disabled={selectedExchange === null}>
          Handshake
         </TabsTrigger>
        </TabsList>
        <div className="detail-actions">
         {selectedFrame ? (
          <>
           <span className="eyebrow">#{selectedFrame.id}</span>
           <Badge>{formatBytes(selectedFrame.len)}</Badge>
           <IconButton label="Clear frame selection" size="small" onClick={() => setSelectedFrameId(null)}>
            <X size={13} />
           </IconButton>
          </>
         ) : selectedExchange !== null ? (
          <IconButton
           label="Clear connection selection"
           size="small"
           title="Clear the selection to see every frame"
           onClick={() => {
            setSelectedExchange(null);
            setSelectedFrameId(null);
           }}
          >
           <X size={13} />
          </IconButton>
         ) : null}
        </div>
       </div>
       <TabsContent value="frame" className="tabs-fill">
        {selectedFrame ? (
         <PayloadView message={frame.data} isFetching={frame.isFetching} />
        ) : (
         <Empty title="No frame selected" detail="Choose a row in the frame table to read its exact payload." />
        )}
       </TabsContent>
       <TabsContent value="handshake" className="tabs-fill">
        {selectedConn ? (
         <div className="editor-grid tabs-fill">
          <HttpEditor
           views={false}
           label={`Upgrade request — ${selectedConn.host}:${selectedConn.port}${selectedConn.path}`}
           readOnly
           value={handshakeRequest.data?.text ?? ""}
           filename={`ws-handshake-${selectedConn.exchange}-request.txt`}
           menuGroups={exchangeDetail.data ? actions.menu(exchangeDetail.data) : undefined}
           placeholder={handshakeRequest.isLoading ? "Loading handshake…" : "No request bytes captured."}
          />
          <HttpEditor
           views={false}
           label={`Upgrade response — ${selectedConn.host}:${selectedConn.port}${selectedConn.path}`}
           readOnly
           value={handshakeResponse.data?.text ?? ""}
           filename={`ws-handshake-${selectedConn.exchange}-response.txt`}
           menuGroups={exchangeDetail.data ? actions.menu(exchangeDetail.data) : undefined}
           placeholder={
            selectedConn.exchange === null || handshakeResponse.data === undefined
             ? handshakeResponse.isLoading
              ? "Loading handshake…"
              : "No response bytes captured."
             : "The upgrade was not answered through the proxy."
           }
          />
         </div>
        ) : null}
       </TabsContent>
      </Tabs>
     ) : (
      <Empty title="No connection selected" detail="Pick a connection on the left to see its frames and the HTTP handshake that opened it." />
     )}
    </div>
   </div>
  </div>
 );
}
