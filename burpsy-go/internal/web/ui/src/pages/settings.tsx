import { useState } from "react";
import { Download, Plus, Radar, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { formatBytes, formatCount, formatDuration } from "../lib/api";
import { useStats } from "../lib/data";
import {
  useCaCert,
  useEventHubStats,
  useProtocols,
  useScopeView,
  useSendFrameProgram,
  useUpdateScope,
} from "../lib/data.policy";
import { useApp, type Density, type Theme } from "../lib/store";
import type { FrameProgramResponse } from "../lib/types.policy";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, LinkButton, Metric, Modal, Select, Switch, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";
import { ClientCertificatesSection, PlatformAuthSection } from "./settings.network";

const THEMES: { value: Theme; label: string }[] = [
  { value: "system", label: "Follow the system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

const DENSITIES: { value: Density; label: string }[] = [
  { value: "comfortable", label: "Comfortable" },
  { value: "compact", label: "Compact" },
];

export function ScopeSection(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useScopeView();
  const update = useUpdateScope();
  const [kind, setKind] = useState<"include" | "exclude">("include");
  const [pattern, setPattern] = useState("");
  const [confirmClear, setConfirmClear] = useState(false);

  const run = (
    body: Parameters<typeof update.mutate>[0],
    message: string,
  ) =>
    update.mutate(body, {
      onSuccess: () => toast.success(message),
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Scope change failed"),
    });

  return (
    <Card>
      <SectionHeading
        title="Scope"
        detail="What the proxy is allowed to touch. Every change here is persisted immediately."
        actions={
          <>
            {data ? <Badge tone={data.allow_all ? "warn" : "good"}>{data.allow_all ? "everything in scope" : "restricted"}</Badge> : null}
            <Button variant="outline" size="small" onClick={() => setConfirmClear(true)} disabled={!data || data.empty}>
              <Trash2 size={13} />
              Clear scope
            </Button>
            <RefreshButton onClick={() => void refetch()} loading={isFetching} />
          </>
        }
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading scope" /> : null}

      <div className="notice">
        <span>
          A scope rule matches on a host pattern only — this build&apos;s scope API has no port, protocol or path
          arm, so those are not offered here. An empty scope means everything is in scope.
        </span>
      </div>

      <Toolbar>
        <Field label="Rule kind" hint="Excludes win over includes.">
          {(id) => (
            <Select
              id={id}
              value={kind}
              onChange={(event) => setKind(event.target.value === "exclude" ? "exclude" : "include")}
              style={{ maxWidth: "var(--w-sm)" }}
            >
              <option value="include">Include</option>
              <option value="exclude">Exclude</option>
            </Select>
          )}
        </Field>
        <Field label="Host pattern" hint="For example api.example.com or *.example.com.">
          {(id) => (
          <Input
            id={id}
            value={pattern}
            placeholder="api.example.com"
            onChange={(event) => setPattern(event.target.value)}
            onKeyDown={(event) => {
              if (event.key !== "Enter" || !pattern.trim()) return;
              run({ action: kind, pattern: pattern.trim() }, `${kind}d ${pattern.trim()}`);
              setPattern("");
            }}
          />
          )}
        </Field>
        <Button
          disabled={!pattern.trim() || update.isPending}
          onClick={() => {
            run({ action: kind, pattern: pattern.trim() }, `${kind}d ${pattern.trim()}`);
            setPattern("");
          }}
        >
          <Plus size={13} />
          Add rule
        </Button>
      </Toolbar>

      {data && data.rules.length === 0 ? (
        <Empty
          title="No scope rules"
          detail="Every host is in scope. Add an include rule to bound what the proxy, scanner and crawler will touch."
        />
      ) : null}
      {data && data.rules.length > 0 ? (
        <SimpleTable headers={["Kind", "Host pattern", ""]}>
          {data.rules.map((rule, index) => (
            <tr key={`${rule.kind}-${rule.host ?? ""}-${index}`}>
              <td>
                <Badge tone={rule.kind === "Exclude" ? "bad" : "good"}>{rule.kind}</Badge>
              </td>
              <td>
                <code>{rule.host ?? "any host"}</code>
              </td>
              <td>
                <IconButton
                  label={`Remove ${rule.kind} rule for ${rule.host ?? "any host"}`}
                  size="small"
                  disabled={rule.host === null || update.isPending}
                  onClick={() =>
                    rule.host === null
                      ? undefined
                      : run(
                          { action: "remove", kind: rule.kind === "Exclude" ? "exclude" : "include", pattern: rule.host },
                          `Removed ${rule.host}`,
                        )
                  }
                >
                  <Trash2 size={13} />
                </IconButton>
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}

      <Modal
        open={confirmClear}
        onOpenChange={setConfirmClear}
        title="Clear every scope rule?"
        description="With no rules left, every host is in scope again."
      >
        <div className="page-actions">
          <Button variant="outline" onClick={() => setConfirmClear(false)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={() => {
              run({ action: "clear" }, "Scope cleared");
              setConfirmClear(false);
            }}
          >
            <Trash2 size={13} />
            Clear scope
          </Button>
        </div>
      </Modal>
    </Card>
  );
}

function ProtocolSection(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useProtocols();
  const probe = useSendFrameProgram();
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [tls, setTls] = useState(true);
  const [result, setResult] = useState<FrameProgramResponse | null>(null);

  const downgrades = Object.entries(data?.downgrades ?? {});

  const runProbe = () => {
    const parsedPort = Number(port.trim());
    if (!host.trim() || !Number.isInteger(parsedPort) || parsedPort <= 0) {
      toast.error("A probe needs a host and a port");
      return;
    }
    probe.mutate(
      // No frames: the preface goes out and the reply is read, which is what
      // reports the negotiated protocol. Still authorised against scope server-side.
      { host: host.trim(), port: parsedPort, tls, preface: true, read_for_ms: 750, frames: [] },
      {
        onSuccess: (response) => {
          setResult(response);
          if (response.error) toast.error(response.error);
          else toast.success(`Negotiated ${response.negotiated || "nothing"} with ${host.trim()}`);
        },
        onError: (failure: unknown) => {
          setResult(null);
          toast.error(failure instanceof Error ? failure.message : "Probe failed");
        },
      },
    );
  };

  return (
    <Card>
      <SectionHeading
        title="Protocols"
        detail="How this tool's own senders reached their targets — proxied traffic is reported in HTTP history."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading protocol report" /> : null}
      {data && !data.enabled ? (
        <div className="notice notice-warn">
          <span>{data.hint ?? "No sender is wired, so nothing has been sent from this process."}</span>
        </div>
      ) : null}

      {data?.enabled ? (
        <>
          {data.summary ? <p className="field-hint">{data.summary}</p> : null}
          <div className="metric-grid wide">
            <Metric label="Sent as HTTP/2" value={formatCount(data.sent_as_http2)} />
            <Metric label="Sent as HTTP/1.1" value={formatCount(data.sent_as_http1)} />
            <Metric label="Rewrites" value={formatCount(data.rewrites)} detail="Requests altered to fit the protocol" />
            <Metric label="Discovery handshakes" value={formatCount(data.discovery_handshakes)} />
            <Metric label="ALPN cache hits" value={formatCount(data.cache_hits)} />
          </div>

          {downgrades.length ? (
            <SimpleTable headers={["Downgrade reason", "Count"]}>
              {downgrades.map(([reason, count]) => (
                <tr key={reason}>
                  <td>{reason}</td>
                  <td>
                    <span className="cell-num">{formatCount(count)}</span>
                  </td>
                </tr>
              ))}
            </SimpleTable>
          ) : (
            <p className="field-hint">No downgrades recorded: nothing fell back from HTTP/2 for a stated reason.</p>
          )}

          {data.authorities?.length ? (
            <SimpleTable headers={["Authority", "State", "Negotiated"]}>
              {data.authorities.map((authority) => (
                <tr key={authority.authority}>
                  <td>
                    <code>{authority.authority}</code>
                  </td>
                  <td>
                    <Badge tone={authority.state === "h2" ? "good" : "neutral"}>{authority.state}</Badge>
                  </td>
                  <td>
                    <span className="cell-dim">{authority.negotiated || "—"}</span>
                  </td>
                </tr>
              ))}
            </SimpleTable>
          ) : (
            <Empty title="No authority has been probed" detail="Send a request from Repeater, or probe one below." />
          )}
        </>
      ) : null}

      <SectionHeading
        title="Negotiation probe"
        detail="Opens a connection, sends the HTTP/2 preface and nothing else, then reports what came back."
      />
      <Toolbar>
        <Field label="Host">
          {(id) => <Input id={id} value={host} placeholder="api.example.com" onChange={(event) => setHost(event.target.value)} />}
        </Field>
        <Field label="Port">
          {(id) => (
            <Input
              id={id}
              value={port}
              inputMode="numeric"
              onChange={(event) => setPort(event.target.value)}
              style={{ maxWidth: "var(--w-xs)" }}
            />
          )}
        </Field>
        <Field label="TLS" htmlFor="protocol-probe-tls">
          <Switch id="protocol-probe-tls" label="Use TLS for the probe" checked={tls} onCheckedChange={setTls} />
        </Field>
        <Button onClick={runProbe} disabled={probe.isPending}>
          <Radar size={13} />
          {probe.isPending ? "Probing…" : "Probe negotiation"}
        </Button>
      </Toolbar>
      {result ? (
        <>
          <Toolbar>
            <Badge tone={result.error ? "bad" : "good"}>{result.verdict}</Badge>
            <Badge>negotiated {result.negotiated || "nothing"}</Badge>
            <Badge>{formatDuration(result.duration_ms)}</Badge>
            <Badge tone={result.read_ended ? "warn" : "neutral"}>{result.read_ended ? "peer closed" : "still open"}</Badge>
            <Badge>{formatBytes(result.reply.octets)} read</Badge>
          </Toolbar>
          {result.refusals.length ? (
            <div className="notice notice-warn">
              <span>Scope refused this probe: {result.refusals.join("; ")}</span>
            </div>
          ) : null}
          {result.violations.length ? (
            <div className="notice notice-warn">
              <span>Protocol violations observed: {result.violations.join("; ")}</span>
            </div>
          ) : null}
          {result.reply.frames.length ? (
            <SimpleTable headers={["Frame", "Flags", "Stream", "Length"]}>
              {result.reply.frames.map((frame, index) => (
                <tr key={`${frame.type}-${index}`}>
                  <td>
                    <Badge tone="info">{frame.type}</Badge>
                  </td>
                  <td>
                    <span className="cell-num">0x{frame.flags.toString(16).padStart(2, "0")}</span>
                  </td>
                  <td>
                    <span className="cell-num">{frame.stream}</span>
                  </td>
                  <td>
                    <span className="cell-num">{formatBytes(frame.len)}</span>
                  </td>
                </tr>
              ))}
            </SimpleTable>
          ) : (
            <p className="field-hint">The peer sent no complete frame back.</p>
          )}
        </>
      ) : null}
    </Card>
  );
}

function AppearanceSection(): JSX.Element {
  const theme = useApp((state) => state.theme);
  const setTheme = useApp((state) => state.setTheme);
  const density = useApp((state) => state.density);
  const setDensity = useApp((state) => state.setDensity);

  return (
    <Card>
      <SectionHeading title="Appearance" detail="Stored in this browser; it does not travel with the capture." />
      <div className="form-grid">
        <Field label="Theme" hint="System follows the operating system's light or dark preference.">
          {(id) => (
            <Select id={id} value={theme} onChange={(event) => setTheme(event.target.value as Theme)}>
              {THEMES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Table density" hint="Compact fits roughly a quarter more rows on screen.">
          {(id) => (
            <Select id={id} value={density} onChange={(event) => setDensity(event.target.value as Density)}>
              {DENSITIES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
    </Card>
  );
}

function CertificateSection(): JSX.Element {
  const { data, error, isFetching, refetch } = useCaCert();

  return (
    <Card>
      <SectionHeading
        title="Certificate"
        detail="A client that does not trust this CA cannot be intercepted on HTTPS at all."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} label="Re-check" />}
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {data && !data.available ? (
        <div className="notice notice-warn">
          <span>{data.detail}</span>
        </div>
      ) : null}
      {/* No link while the route answers 404: a download that cannot succeed sends the
          operator looking for the fault in their browser instead of in burpsy's flags. */}
      {data?.available ? (
        <Toolbar>
          <LinkButton href="/ca.crt" download="burpsy-ca.crt">
            <Download size={14} />
            Download burpsy-ca.crt
          </LinkButton>
          <Badge tone="good">certificate available</Badge>
        </Toolbar>
      ) : null}
      <div className="prose">
        {[
          "1. Download burpsy-ca.crt above.",
          "2. Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import, and tick “Trust this CA to identify websites”.",
          "3. Chrome / Edge / Safari use the OS store: macOS → Keychain Access → System → drag the file in → set it to “Always Trust”. Windows → certlm.msc → Trusted Root Certification Authorities → Certificates → Import. Linux → copy to /usr/local/share/ca-certificates/ and run update-ca-certificates.",
          "4. Point the client's HTTP and HTTPS proxy at burpsy, then reload a page and check HTTP history.",
        ].join("\n")}
      </div>
      <p className="field-hint">
        Trust this CA in the browser you test with, never in one you use for anything else: while it is trusted,
        burpsy can read that browser&apos;s TLS traffic.
      </p>
    </Card>
  );
}

function DiagnosticsSection(): JSX.Element {
  const stats = useStats();
  const events = useEventHubStats();
  const pending = Object.entries(events.data?.pending ?? {}).filter(([, count]) => count > 0);

  return (
    <Card>
      <SectionHeading
        title="Diagnostics"
        detail="What the store holds, and whether the live event stream is actually delivering."
        actions={
          <RefreshButton
            onClick={() => {
              void stats.refetch();
              void events.refetch();
            }}
            loading={stats.isFetching || events.isFetching}
          />
        }
      />
      {stats.error ? <ErrorNotice error={stats.error} onRetry={() => void stats.refetch()} /> : null}
      {events.error ? <ErrorNotice error={events.error} onRetry={() => void events.refetch()} /> : null}
      <div className="metric-grid wide">
        <Metric label="Exchanges" value={formatCount(stats.data?.exchanges)} />
        <Metric label="Messages" value={formatCount(stats.data?.messages)} />
        <Metric label="Stored bytes" value={stats.data ? formatBytes(stats.data.stored_bytes) : "—"} />
        <Metric label="Stream subscribers" value={formatCount(events.data?.subscribers)} />
        <Metric
          label="Fan-out"
          value={events.data ? (events.data.fanout_running ? "running" : "idle") : "—"}
          tone={events.data?.fanout_running ? "good" : "neutral"}
        />
        <Metric label="Frames sent" value={formatCount(events.data?.frames)} detail="Coalesced change frames" />
        <Metric label="Changes announced" value={formatCount(events.data?.changes)} />
        <Metric label="Merges" value={formatCount(events.data?.merges)} detail="Signals folded into one frame" />
        <Metric
          label="Coalesce window"
          value={events.data ? formatDuration(events.data.window_ms) : "—"}
          detail="Bursts inside this window become one frame"
        />
      </div>
      {pending.length ? (
        <SimpleTable headers={["Kind pending delivery", "Count"]}>
          {pending.map(([kind, count]) => (
            <tr key={kind}>
              <td>{kind}</td>
              <td>
                <span className="cell-num">{formatCount(count)}</span>
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : (
        <p className="field-hint">Nothing is waiting to be delivered to a subscriber.</p>
      )}
    </Card>
  );
}

export function SettingsPage(): JSX.Element {
  return (
    <div className="page">
      <PageHeader
        title="Settings"
        description="Protocol reporting, network credentials, appearance, the CA certificate, and the console's own diagnostics. Scope lives under Target."
      />
      <ProtocolSection />
      <PlatformAuthSection />
      <ClientCertificatesSection />
      <AppearanceSection />
      <CertificateSection />
      <DiagnosticsSection />
    </div>
  );
}
