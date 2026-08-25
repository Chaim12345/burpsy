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
import { useState } from "react";
import { Copy, Plus, RefreshCw } from "lucide-react";
import { Badge, Button, Card, Empty, ErrorNotice, IconButton, Metric } from "../ui/primitives";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { SimpleTable } from "../ui/table";
import {
  useBlindXSS,
  useCollaboratorInteraction,
  useCollaboratorInteractions,
  useCollaboratorStatus,
  useMintBlindXSSPayload,
  useMintPayload,
  usePollNow,
  type CollaboratorInteractionRow,
} from "../lib/data.collab";
import { copyToClipboard } from "../lib/api";
import { toast } from "sonner";

function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

export function CollaboratorPage(): JSX.Element {
  const status = useCollaboratorStatus();
  const interactions = useCollaboratorInteractions();
  const blindxss = useBlindXSS();
  const mint = useMintPayload();
  const poll = usePollNow();
  const mintBX = useMintBlindXSSPayload();
  const [selected, setSelected] = useState<number | null>(null);

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
      <Card>
        <SectionHeading
          title="Interaction channel"
          detail={s.configured ? (s.default_pool ? "Using the interactsh public pool." : s.server ?? undefined) : s.hint}
          actions={
            <>
              <Button
                size="small"
                disabled={!s.configured || mint.isPending}
                onClick={() =>
                  mint.mutate(undefined, {
                    onSuccess: (payload) => {
                      void copyToClipboard(payload.address);
                      toast.success(`Payload ${payload.address} copied`);
                    },
                    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Minting a payload failed"),
                  })
                }
              >
                <Plus size={13} /> Copy payload
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

      {s.configured ? <InteractionsTable rows={interactions.data ?? []} loading={interactions.isLoading} selected={selected} onSelect={setSelected} /> : null}
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

  return (
    <Card>
      <SectionHeading title="Interactions" detail="A DNS interaction means the payload address was resolved; HTTP means something rendered or fetched it." />
      <SimpleTable headers={["#", "Type", "Client IP", "Payload", "Time", ""]}>
        {rows.map((row) => (
          <tr key={row.id} className={row.id === selected ? "selected-row" : undefined}>
            <td className="cell-num">{row.id}</td>
            <td>
              <Badge tone={row.type === "dns" ? undefined : "bad"}>{row.type.toUpperCase()}</Badge>
              {row.q_type ? <span className="cell-dim"> {row.q_type}</span> : null}
            </td>
            <td className="mono">{row.client_ip}</td>
            <td className="mono cell-dim">{row.payload ?? "—"}</td>
            <td className="cell-dim">{formatTime(row.at_ms)}</td>
            <td>
              <Button variant="outline" size="small" onClick={() => onSelect(row.id)}>
                Open
              </Button>
            </td>
          </tr>
        ))}
      </SimpleTable>
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
