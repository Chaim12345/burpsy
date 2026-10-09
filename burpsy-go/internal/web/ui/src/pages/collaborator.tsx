/**
 * The Collaborator tab: the out-of-band interaction channel and the blind-XSS
 * callback listener — two surfaces over one operational question, "did a payload
 * we planted somewhere we cannot see call home?". Burp keeps Collaborator as its
 * own tool tab; the blind-XSS listener is this engine's second channel and reads
 * as a section here rather than pretending to be a separate tool, because an
 * operator triages both from one place.
 *
 * The honest states are first-class: an unconfigured channel renders the reason
 * and what it gates, never an empty interaction table that would read as
 * "nothing called back".
 */
import { useMemo, useState, type CSSProperties } from "react";
import { Check, Copy, Plus, RefreshCw, X } from "lucide-react";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, IconButton, Input, Metric, Select, Toolbar } from "../ui/primitives";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { SimpleTable } from "../ui/table";
import { HIGHLIGHTS } from "../lib/types";
import {
  useBlindXSS,
  useCollaboratorInteraction,
  useCollaboratorInteractions,
  useCollaboratorStatus,
  useMintBlindXSSPayload,
  useMintPayload,
  usePollNow,
  useSetCollaboratorServer,
  useCollaboratorHealth,
  useUnsetCollaboratorServer,
  type CollaboratorHealthReport,
  type CollaboratorInteractionRow,
} from "../lib/data.collab";
import { api, copyToClipboard, downloadText } from "../lib/api";
import { collaboratorToCSV, type CollaboratorExportRow } from "../lib/collaborator-csv";
import { useApp } from "../lib/store";
import { toast } from "sonner";

function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

/**
 * The annotated row's accent border. `--highlight-<name>` is the shared token vocabulary
 * History and Organizer paint rows with (styles.css's row-highlight-* rules), each one bound
 * to a distinct hex value. `--accent-<name>` was never defined per colour — only the plain
 * `--accent`/`--accent-bright`/`--accent-strong`/`--accent-contrast` tokens exist — so every
 * named highlight fell through to the same fallback and rendered as one colour. Exported as a
 * pure function so the token choice is unit-testable without a DOM.
 */
export function highlightBorderStyle(highlight: string | undefined): CSSProperties | undefined {
  if (!highlight || highlight === "none") return undefined;
  return { borderLeft: `3px solid var(--highlight-${highlight}, var(--accent))` };
}

export function CollaboratorPage(): JSX.Element {
  const status = useCollaboratorStatus();
  const interactions = useCollaboratorInteractions();
  const blindxss = useBlindXSS();
  const mint = useMintPayload();
  const [batchCount, setBatchCount] = useState(1);
  const poll = usePollNow();
  const mintBX = useMintBlindXSSPayload();
  const setServer = useSetCollaboratorServer();
  const health = useCollaboratorHealth();
  const unsetServer = useUnsetCollaboratorServer();
  const [selected, setSelected] = useState<number | null>(null);
  const [serverInput, setServerInput] = useState("");
  const [clientPath, setClientPath] = useState("");

  if (status.isLoading) return <LoadingPanel label="Loading collaborator state" />;
  if (status.error || !status.data)
    return <ErrorNotice error={status.error ?? new Error("Collaborator state unavailable")} onRetry={() => void status.refetch()} />;

  const s = status.data;

  return (
    <div className="stack">
      <PageHeader
        title="Collaborator"
        description="Out-of-band interactions and blind-XSS callbacks — payloads planted where the scanner cannot watch."
        actions={
          <>
            <Badge tone={s.configured ? "good" : "warn"}>{s.configured ? "channel configured" : "not configured"}</Badge>
            <RefreshButton onClick={() => void status.refetch()} loading={status.isFetching} />
          </>
        }
      />
      {/* Burp's configPanelCollaboratorServer. Until this existed the capability was reachable only
          via -collaborator-server at startup, so forgetting the flag gated 26 corpus checks off for
          the whole session and the only remedy was a restart — which costs the operator their
          captured traffic. */}
      <Card>
        <SectionHeading
          title="Interaction server"
          detail={
            s.configured
              ? "Change where out-of-band callbacks are collected. Refused once a channel has registered, because payloads already handed out belong to the current domain."
              : "No interaction server is set, so every out-of-band check refuses and no address can be handed out. Set one here instead of restarting."
          }
        />
        <div className="form-grid" style={{ marginTop: 8 }}>
          <label htmlFor="collab-server">Server</label>
          <Input
            id="collab-server"
            aria-label="Interaction server URL"
            placeholder="https://oast.example — or the word: public"
            value={serverInput}
            onChange={(e) => setServerInput(e.target.value)}
          />
          <label htmlFor="collab-client">Client binary</label>
          <Input
            id="collab-client"
            aria-label="Path to the interactsh-client binary"
            placeholder="optional — path to interactsh-client, else found on PATH"
            value={clientPath}
            onChange={(e) => setClientPath(e.target.value)}
          />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
          <Button
            size="small"
            disabled={serverInput.trim() === "" || setServer.isPending}
            onClick={() =>
              setServer.mutate(
                { server: serverInput.trim(), client_path: clientPath.trim() || undefined },
                {
                  onSuccess: (next) =>
                    // "Configured" and "reachable" are deliberately different claims. The provider is
                    // lazy: nothing has contacted the server yet, and whether it answers — or whether
                    // interactsh-client can even be found — is discovered when a payload is first
                    // minted. Saying "connected" here would be a guess presented as a fact.
                    toast.success(
                      next.default_pool
                        ? "Configured: interactsh public pool. Generate a payload to register a channel."
                        : `Configured: ${next.server}. Generate a payload to register a channel.`,
                    ),
                  onError: (failure: unknown) =>
                    toast.error(failure instanceof Error ? failure.message : "Setting the interaction server failed"),
                },
              )
            }
          >
            {setServer.isPending ? "Setting…" : "Set server"}
          </Button>
          {s.configured ? (
            <>
              {/* Burp's "Run health check" (8e3n): a negative out-of-band result means something only
                  if the callbacks actually come back, which is what this checks end to end. */}
              <Button
                size="small"
                variant="outline"
                disabled={health.isPending}
                onClick={() =>
                  health.mutate(undefined, {
                    onError: (failure: unknown) =>
                      toast.error(failure instanceof Error ? failure.message : "The health check could not run"),
                  })
                }
              >
                {health.isPending ? "Checking… (up to 30s)" : "Run health check"}
              </Button>
              {/* Burp's "Don't use Burp Collaborator". With a registered channel, the payloads already
                  handed out would point at a server nobody polls, so the operator is told how many first. */}
              <Button
                size="small"
                variant="outline"
                disabled={unsetServer.isPending}
                onClick={() => {
                  const open = Boolean(s.domain);
                  if (
                    open &&
                    !window.confirm(
                      `Stop using Collaborator? The channel on ${s.domain} is closed, and the ${s.payloads.length} payload address(es) minted from it will point at a server nobody polls — a late callback to them is lost.`,
                    )
                  )
                    return;
                  unsetServer.mutate(
                    { discardOpenChannel: open },
                    {
                      onSuccess: (result) => {
                        health.reset();
                        toast.success(
                          result.orphaned_payloads > 0
                            ? `Collaborator is off. ${result.orphaned_payloads} payload address(es) are no longer polled.`
                            : "Collaborator is off. Out-of-band checks will refuse until a server is set.",
                        );
                      },
                      onError: (failure: unknown) =>
                        toast.error(failure instanceof Error ? failure.message : "Turning Collaborator off failed"),
                    },
                  );
                }}
              >
                Don&apos;t use Collaborator
              </Button>
            </>
          ) : null}
          <span style={{ fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>
            <code>public</code> uses interactsh's own pool — third-party, and your callback data lands
            there. Hosting a private server is out of scope for burpsy; driving its client is not.
          </span>
        </div>
        {s.domain ? (
          <div className="notice" style={{ marginTop: 8 }}>
            A channel is registered on <code>{s.domain}</code>, so the server can no longer be changed
            from here: the payload addresses already handed out — and the findings that reference them
            — belong to that domain, and repointing would leave them at a server nobody is polling.
            To change it, choose <strong>Don&apos;t use Collaborator</strong> first, which says how many
            payloads that orphans, then set the new server.
          </div>
        ) : null}
        {health.data ? <HealthReport report={health.data} /> : null}
      </Card>

      <Card>
        <SectionHeading
          title="Interaction channel"
          detail={
            s.configured
              ? `${s.default_pool ? "Using the interactsh public pool." : s.server ?? ""}${
                  s.identity_kept
                    ? s.resumed
                      ? " Resumed the identity saved by an earlier run, so payloads minted before the restart are still polled."
                      : " The identity is kept across restarts, so payloads minted here stay polled after one."
                    : " The identity is not kept: a restart orphans every payload minted here."
                }`
              : s.hint
          }
          actions={
            <>
              <label
                className="field-label"
                style={{ display: "flex", alignItems: "center", gap: 4, fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}
                title="Payloads to generate (burpsy-react-ui-v8q): one per injection point when a request needs the same probe in many places. Bounded at 100 by the server."
              >
                count
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={batchCount}
                  onChange={(e) => setBatchCount(Math.max(1, Math.min(100, Number(e.target.value) || 1)))}
                  style={{ width: 56 }}
                />
              </label>
              <Button
                size="small"
                disabled={!s.configured || mint.isPending}
                onClick={() =>
                  mint.mutate({ count: batchCount }, {
                    onSuccess: (payload) => {
                      void copyToClipboard(payload.address + (payload.addresses.length > 1 ? `\n${payload.addresses.slice(1).join("\n")}` : ""));
                      toast.success(
                        payload.addresses.length > 1
                          ? `${payload.addresses.length} payloads copied`
                          : `Payload ${payload.address} copied`,
                      );
                    },
                    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Minting a payload failed"),
                  })
                }
              >
                <Plus size={13} /> Copy payload{batchCount > 1 ? "s" : ""}
              </Button>
              <Button
                variant="outline"
                size="small"
                disabled={!s.configured || poll.isPending}
                onClick={() =>
                  poll.mutate(undefined, {
                    onSuccess: (read) =>
                      toast.success(read.interactions > 0 ? `${read.interactions} new interaction(s)` : "No new interactions"),
                    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Polling failed"),
                  })
                }
              >
                <RefreshCw size={13} /> Poll now
              </Button>
            </>
          }
        />
        {s.configured ? (
          <div className="metric-grid wide">
            <Metric label="State" value={s.state} tone={s.state === "running" ? "good" : "warn"} />
            <Metric label="Domain" value={s.domain ?? "—"} />
            <Metric label="Payloads" value={s.payloads.length} />
            <Metric label="Interactions" value={s.interactions?.total ?? 0} tone={(s.interactions?.total ?? 0) > 0 ? "bad" : undefined} />
            <Metric
              label="Last read"
              value={s.last_read ? (s.last_read.ok ? formatTime(s.last_read.at_ms) : s.last_read.error ?? "failed") : "never"}
            />
            <Metric label="Gated checks" value={s.gated_checks ?? 0} detail={s.gated_checks ? "refusing OOB verdicts" : undefined} />
          </div>
        ) : (
          <Empty
            title="No collaborator channel"
            detail={s.hint || "Start the server with -collaborator-server public (or an interactsh server URL) to mint payloads and collect interactions."}
          />
        )}
      </Card>

      {s.configured ? (
        <InteractionsTable
          rows={interactions.data ?? []}
          loading={interactions.isLoading}
          selected={selected}
          onSelect={setSelected}
        />
      ) : null}
      {selected !== null ? <InteractionDetail id={selected} onClose={() => setSelected(null)} /> : null}

      <Card>
        <SectionHeading
          title="Blind XSS callbacks"
          detail="Plant the script tag where a scanner cannot reach; a rendered payload calls home with its page context. An outstanding payload is stated as outstanding, never as clean."
          actions={
            <Button
              size="small"
              disabled={!blindxss.data?.configured || mintBX.isPending}
              onClick={() =>
                mintBX.mutate(undefined, {
                  onSuccess: (payload) => {
                    void copyToClipboard(payload.payload.script_tag);
                    toast.success("Script tag copied — plant it in a form field or header");
                  },
                  onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Minting failed"),
                })
              }
            >
              <Plus size={13} /> Copy script tag
            </Button>
          }
        />
        {!blindxss.data ? (
          <LoadingPanel label="Loading blind-XSS state" />
        ) : !blindxss.data.configured ? (
          <Empty title="No blind-XSS listener" detail={blindxss.data.reason || "Start the server with -blindxss 0.0.0.0:8088 to mint callback payloads."} />
        ) : blindxss.data.payloads.length === 0 ? (
          <Empty title="No payloads minted" detail="Mint a script tag and plant it; the state above says how many are outstanding." />
        ) : (
          <SimpleTable headers={["Token", "Script URL", "State", "Hits", "Last hit"]}>
            {blindxss.data.payloads.map((payload) => (
              <tr key={payload.token}>
                <td className="mono">
                  <IconButton
                    label={`Copy payload ${payload.token}`}
                    size="small"
                    onClick={() => void copyToClipboard(payload.script_tag).then(() => toast.success("Script tag copied"))}
                  >
                    <Copy size={12} />
                  </IconButton>{" "}
                  {payload.token.slice(0, 12)}
                </td>
                <td className="mono cell-dim">{payload.script_url}</td>
                <td>
                  <Badge tone={payload.outstanding ? "warn" : undefined}>{payload.outstanding ? "outstanding" : "fired"}</Badge>
                </td>
                <td>
                  <Badge tone={payload.hits.length > 0 ? "bad" : undefined}>{payload.hits.length}</Badge>
                </td>
                <td className="cell-dim">{payload.hits.length ? formatTime(Date.parse(payload.hits[payload.hits.length - 1]!.receivedAt)) : "—"}</td>
              </tr>
            ))}
          </SimpleTable>
        )}
      </Card>
    </div>
  );
}

/**
 * The interaction table's triage controls (burpsy-react-ui-8o6): protocol filter covering
 * every protocol the OOB client models — dns, http, smtp and ldap, one more than Burp's
 * three buttons — a search box over the row's own text, mark-as-read, and a per-interaction
 * comment/highlight pair. Read state and annotations live in the workspace store (this
 * browser's view of the operator's review progress, like the Inspector dock), because the
 * channel is a subprocess-appended log nothing in this process owns; the unread count on
 * the tool tab itself rides the tab-attention work (burpsy-react-ui-xvo).
 */
const HEALTH_TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = {
  ok: "good",
  error: "bad",
  not_triggered: "warn",
  healthy: "good",
  degraded: "warn",
  failed: "bad",
};

/** Burp's health-check results: the capture rows decide, and the connection rows explain them. */
function HealthReport({ report }: { report: CollaboratorHealthReport }): JSX.Element {
  const row = (item: CollaboratorHealthReport["connections"][number]) => (
    <tr key={item.name}>
      <td>{item.name}</td>
      <td>
        <Badge tone={HEALTH_TONE[item.status] ?? "neutral"}>{item.status.replace("_", " ")}</Badge>
      </td>
      <td className="cell-num">{item.latency_ms === null ? "—" : `${item.latency_ms} ms`}</td>
      <td className="cell-dim">{item.detail}</td>
    </tr>
  );
  return (
    <div style={{ marginTop: 12 }}>
      <SectionHeading
        title="Health check"
        detail={`${report.address} · waited ${(report.waited_ms / 1000).toFixed(1)}s for callbacks`}
        actions={<Badge tone={HEALTH_TONE[report.status] ?? "neutral"}>{report.status}</Badge>}
      />
      <p className="field-hint">{report.summary}.</p>
      <SimpleTable headers={["Interaction came back through polling", "Result", "After", "Detail"]}>
        {report.captures.map(row)}
      </SimpleTable>
      <SimpleTable headers={["Connection", "Result", "Took", "Detail"]}>{report.connections.map(row)}</SimpleTable>
      <p className="field-hint">{report.polling}.</p>
    </div>
  );
}

function InteractionsTable({
  rows,
  loading,
  selected,
  onSelect,
}: {
  rows: CollaboratorInteractionRow[];
  loading: boolean;
  selected: number | null;
  onSelect: (id: number) => void;
}): JSX.Element {
  const read = useApp((state) => state.collaboratorRead);
  const markRead = useApp((state) => state.markCollaboratorRead);
  const annotations = useApp((state) => state.collaboratorAnnotations);
  const setAnnotation = useApp((state) => state.setCollaboratorAnnotation);

  const [protocol, setProtocol] = useState("all");
  const [term, setTerm] = useState("");
  const [hideRead, setHideRead] = useState(false);
  const [annotating, setAnnotating] = useState<number | null>(null);

  const protocols = useMemo(() => {
    const seen = new Set<string>();
    for (const row of rows) seen.add(row.type);
    return [...seen].sort();
  }, [rows]);

  const filtered = useMemo(() => {
    const needle = term.trim().toLowerCase();
    return rows.filter((row) => {
      if (protocol !== "all" && row.type !== protocol) return false;
      if (hideRead && read.includes(row.id)) return false;
      if (!needle) return true;
      const annotation = annotations[row.id];
      const haystack = `${row.interaction_id} ${row.type} ${row.q_type ?? ""} ${row.client_ip} ${row.payload ?? ""} ${annotation?.comment ?? ""}`.toLowerCase();
      return haystack.includes(needle);
    });
  }, [rows, protocol, term, hideRead, read, annotations]);

  if (loading) return <LoadingPanel label="Loading interactions" />;
  if (!rows.length)
    return (
      <Card>
        <SectionHeading title="Interactions" />
        <Empty
          title="No interactions recorded"
          detail="Mint a payload, plant it where the target renders or resolves it, and poll. An empty table with a configured channel means nothing has called back yet."
        />
      </Card>
    );

  const unread = rows.filter((row) => !read.includes(row.id)).length;

  return (
    <Card>
      <SectionHeading
        title="Interactions"
        detail="A DNS interaction means the payload address was resolved; HTTP means something rendered or fetched it."
        actions={
          <Badge tone={unread > 0 ? "warn" : undefined}>
            {unread > 0 ? `${unread} unread` : "all read"}
          </Badge>
        }
      />
      <Toolbar>
        <Select
          aria-label="Filter by protocol"
          value={protocol}
          onChange={(event) => setProtocol(event.target.value)}
          style={{ maxWidth: "var(--w-xs)" }}
        >
          <option value="all">All protocols</option>
          {protocols.map((p) => (
            <option key={p} value={p}>
              {p.toUpperCase()}
            </option>
          ))}
        </Select>
        <Input
          aria-label="Search interactions"
          value={term}
          onChange={(event) => setTerm(event.target.value)}
          placeholder="Search id, type, IP, payload, comment…"
          style={{ maxWidth: "var(--w-lg)" }}
        />
        <Checkbox label="Hide read" checked={hideRead} onCheckedChange={setHideRead} />
        <Button
          variant="outline"
          size="small"
          disabled={unread === 0}
          onClick={() => rows.forEach((row) => markRead(row.id))}
        >
          <Check size={13} />
          Mark all read
        </Button>
        {/* Burp's "Export as CSV" (aw2y): the rows this table shows now, with their bytes as Base64 and
            this console's comments. The bytes are fetched on click rather than carried on every poll. */}
        <Button
          variant="outline"
          size="small"
          disabled={filtered.length === 0}
          onClick={() => {
            const shown = new Set(filtered.map((row) => row.id));
            api<{ rows: CollaboratorExportRow[] }>("/api/collaborator/interactions?full=1")
              .then((full) => {
                const rows = (full?.rows ?? []).filter((row) => shown.has(row.id));
                const comments = Object.fromEntries(rows.map((row) => [row.id, annotations[row.id]?.comment]));
                downloadText("collaborator-interactions.csv", collaboratorToCSV(rows, comments), "text/csv");
                toast.success(`Exported ${rows.length} interaction(s)`);
              })
              .catch((failure: unknown) =>
                toast.error(failure instanceof Error ? failure.message : "Exporting the interactions failed"),
              );
          }}
        >
          Export shown as CSV
        </Button>
      </Toolbar>
      <SimpleTable headers={["#", "Type", "Client IP", "Payload", "Time", "Read", "Note", ""]}>
        {filtered.map((row) => {
          const isRead = read.includes(row.id);
          const annotation = annotations[row.id];
          return (
            <tr
              key={row.id}
              className={`${row.id === selected ? "selected-row" : ""} ${isRead ? "cell-dim" : ""}`}
              style={highlightBorderStyle(annotation?.highlight)}
            >
              <td className="cell-num">{row.id}</td>
              <td>
                <Badge tone={row.type === "dns" ? undefined : "bad"}>{row.type.toUpperCase()}</Badge>
                {row.q_type ? <span className="cell-dim"> {row.q_type}</span> : null}
              </td>
              <td className="mono">{row.client_ip}</td>
              <td className="mono cell-dim">{row.payload ?? "—"}</td>
              <td className="cell-dim">{formatTime(row.at_ms)}</td>
              <td>
                {isRead ? (
                  <span className="cell-dim">read</span>
                ) : (
                  <IconButton label={`Mark interaction ${row.id} as read`} size="small" onClick={() => markRead(row.id)}>
                    <Check size={12} />
                  </IconButton>
                )}
              </td>
              <td>
                {annotating === row.id ? (
                  <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                    <Input
                      aria-label={`Annotation comment for interaction ${row.id}`}
                      defaultValue={annotation?.comment ?? ""}
                      style={{ maxWidth: 180 }}
                      onKeyDown={(event) => {
                        if (event.key !== "Enter") return;
                        const input = event.target as HTMLInputElement;
                        setAnnotation(row.id, { comment: input.value, highlight: annotation?.highlight ?? "none" });
                        setAnnotating(null);
                        toast.success(input.value ? "Annotation saved" : "Annotation cleared");
                      }}
                    />
                    <Select
                      aria-label={`Highlight colour for interaction ${row.id}`}
                      defaultValue={annotation?.highlight ?? "none"}
                      style={{ maxWidth: 90 }}
                      onChange={(event) => {
                        const colour = event.target.value;
                        setAnnotation(row.id, { comment: annotation?.comment ?? "", highlight: colour });
                      }}
                    >
                      {HIGHLIGHTS.map((colour) => (
                        <option key={colour} value={colour}>
                          {colour}
                        </option>
                      ))}
                    </Select>
                    <IconButton label={`Finish annotating interaction ${row.id}`} size="small" onClick={() => setAnnotating(null)}>
                      <X size={12} />
                    </IconButton>
                  </div>
                ) : (
                  <Button
                    variant="outline"
                    size="small"
                    onClick={() => {
                      markRead(row.id);
                      setAnnotating(row.id);
                    }}
                  >
                    {annotation?.comment ? `✎ ${annotation.comment.slice(0, 18)}` : "Annotate"}
                  </Button>
                )}
              </td>
              <td>
                <Button variant="outline" size="small" onClick={() => onSelect(row.id)}>
                  Open
                </Button>
              </td>
            </tr>
          );
        })}
      </SimpleTable>
      {filtered.length === 0 ? (
        <p className="field-hint">No interaction matches this filter — clear the protocol or search to see all {rows.length}.</p>
      ) : null}
    </Card>
  );
}

function InteractionDetail({ id, onClose }: { id: number; onClose: () => void }): JSX.Element {
  const detail = useCollaboratorInteraction(id);
  if (detail.isLoading || !detail.data) return <LoadingPanel label="Loading interaction" />;
  const d = detail.data;
  return (
    <Card>
      <SectionHeading
        title={`Interaction #${d.id} — ${d.type.toUpperCase()} from ${d.client_ip}`}
        actions={
          <Button variant="outline" size="small" onClick={onClose}>
            Close
          </Button>
        }
      />
      <div className="metric-grid wide">
        <Metric label="Correlation ID" value={d.correlation_id} />
        <Metric label="Client IP" value={d.client_ip} />
        <Metric label="IP means" value={d.client_ip_means} />
        <Metric label="Time" value={new Date(d.at_ms).toLocaleString()} />
      </div>
      {d.raw_request ? (
        <pre className="mono" style={{ whiteSpace: "pre-wrap", maxHeight: "16rem", overflow: "auto" }}>
          {d.raw_request}
        </pre>
      ) : (
        <p className="cell-dim">No request body — DNS interactions carry a query, not a request.{d.q_type ? ` Query type: ${d.q_type}.` : ""}</p>
      )}
    </Card>
  );
}
