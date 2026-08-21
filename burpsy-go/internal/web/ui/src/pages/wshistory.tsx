import { useMemo, useState } from "react";
import { ArrowDownLeft, ArrowUpRight, Copy, ExternalLink, X } from "lucide-react";
import { copyToClipboard, formatBytes, relativeTime } from "../lib/api";
import { useWsConnections, useWsHistory } from "../lib/data";
import { useExchange, useWsMessageDetailed } from "../lib/data.observe";
import { useMessage } from "../lib/data";
import { useApp } from "../lib/store";
import { useExchangeActions } from "../lib/actions";
import type { WsConnection, WsRow } from "../lib/types";
import type { WsMessageDetail } from "../lib/types.observe";
import { HttpEditor } from "../ui/editor";
import { PageHeader, RefreshButton } from "../ui/layout";
import { Badge, Empty, ErrorNotice, IconButton, Metric, Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/primitives";
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
  menuGroups,
}: {
  conn: WsConnection;
  selected: boolean;
  onSelect: () => void;
  menuGroups: MenuGroup[];
}): JSX.Element {
  const row = (
    <button type="button" className={selected ? "list-row active" : "list-row"} onClick={onSelect}>
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
  const actions = useExchangeActions();

  const [selectedExchange, setSelectedExchange] = useState<number | null>(null);
  const [selectedFrameId, setSelectedFrameId] = useState<number | null>(null);

  const connections = useWsConnections();
  const history = useWsHistory(selectedExchange);
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
            menuGroups={menuFor(conn)}
          />
        ))}
      </div>
    );

  const selectedConn = conns.find((c) => c.exchange === selectedExchange) ?? null;

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
          <VirtualTable
            ariaLabel="WebSocket frames"
            data={rows}
            columns={columns}
            getRowId={(row) => String(row.id)}
            selectedId={selectedFrameId === null ? null : String(selectedFrameId)}
            onSelect={(row) => setSelectedFrameId(row.id)}
            rowClassName={(row) => (row.truncated ? "row-flag-warn" : undefined)}
            loading={history.isFetching && !history.data}
            empty={
              <Empty
                title={selectedExchange === null ? "No WebSocket traffic captured yet" : "No frames on this connection"}
                detail={
                  selectedExchange === null
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
                      placeholder={handshakeRequest.isLoading ? "Loading handshake…" : "No request bytes captured."}
                    />
                    <HttpEditor
                      views={false}
                      label={`Upgrade response — ${selectedConn.host}:${selectedConn.port}${selectedConn.path}`}
                      readOnly
                      value={handshakeResponse.data?.text ?? ""}
                      filename={`ws-handshake-${selectedConn.exchange}-response.txt`}
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
