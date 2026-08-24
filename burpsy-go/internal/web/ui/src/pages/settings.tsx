import { useState } from "react";
import { Download, Plus, Radar, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { formatBytes, formatCount, formatDuration } from "../lib/api";
import { useStats } from "../lib/data";
import { useScannerConfigs } from "../lib/data.attack";
import { useCaCert, useEventHubStats, useProtocols, useScopeView, useSendFrameProgram, useUpdateScope, usePassthrough, useAddPassthrough, useRemovePassthrough } from "../lib/data.policy";
import { useApp, type Density, type Theme } from "../lib/store";
import { SHORTCUT_GROUPS } from "../lib/shortcuts";
import type { FrameProgramResponse } from "../lib/types.policy";
import { DetailList } from "../ui/json";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Kbd, LinkButton, Metric, Modal, Select, Switch, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

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
          A rule matches a host pattern, optionally narrowed to one port or a path prefix — the full
          rule table with both arms lives under Target &rarr; Scope. There is no protocol arm in this
          build&apos;s scope engine. An empty scope means everything is in scope.
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

function ProxySettingsSection(): JSX.Element {
  const stats = useStats();

  return (
    <Card>
      <SectionHeading
        title="Proxy"
        detail="What the server has captured so far, and where its listeners are bound."
        actions={
          <RefreshButton onClick={() => void stats.refetch()} loading={stats.isFetching} />
        }
      />
      {stats.error ? <ErrorNotice error={stats.error} onRetry={() => void stats.refetch()} /> : null}
      <div className="metric-grid wide">
        <Metric label="Proxy listener" value={stats.data?.proxy_bind ?? "—"} />
        <Metric label="Web console" value={stats.data?.web_bind ?? "—"} />
        <Metric label="TLS interception" value={stats.data == null ? "—" : stats.data.tls_interception ? "On" : "Off"} tone={stats.data?.tls_interception ? "good" : "neutral"} />
        <Metric label="Exchanges captured" value={formatCount(stats.data?.exchanges)} />
        <Metric label="Messages stored" value={formatCount(stats.data?.messages)} />
        <Metric label="Stored on disk" value={stats.data ? formatBytes(stats.data.stored_bytes) : "—"} />
      </div>
    </Card>
  );
}

function TlsPassthroughSection(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = usePassthrough();
  const add = useAddPassthrough();
  const remove = useRemovePassthrough();
  const [pattern, setPattern] = useState("");

  const fail = (failure: unknown) =>
    toast.error(failure instanceof Error ? failure.message : "Passthrough change failed");

  return (
    <Card>
      <SectionHeading
        title="TLS passthrough"
        detail="Hosts the proxy relays without intercepting. Edits apply immediately and survive a restart."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading passthrough rules" /> : null}

      <div className="notice">
        <span>
          A matching connection is relayed untouched — burpsy never sees its plaintext and it never appears in HTTP
          history. Patterns may carry a leading <code>*.</code> wildcard subdomain. Removal matches the exact
          pattern: <code>*.bank.test</code> and <code>bank.test</code> are separate rules.
        </span>
      </div>

      <Toolbar>
        <Field label="Host pattern" hint="e.g. internal.bank.test or *.cdn.example">
          {(id) => (
            <Input
              id={id}
              value={pattern}
              onChange={(event) => setPattern(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && pattern.trim() && !add.isPending) {
                  add.mutate(pattern.trim(), { onSuccess: () => toast.success(`Added ${pattern.trim()}`), onError: fail });
                  setPattern("");
                }
              }}
              placeholder="internal.bank.test"
              style={{ maxWidth: "var(--w-sm)" }}
            />
          )}
        </Field>
        <Button
          disabled={!pattern.trim() || add.isPending}
          onClick={() => {
            add.mutate(pattern.trim(), { onSuccess: () => toast.success(`Added ${pattern.trim()}`), onError: fail });
            setPattern("");
          }}
        >
          <Plus size={13} />
          Add rule
        </Button>
      </Toolbar>

      {data && data.patterns.length === 0 ? (
        <Empty
          title="No passthrough rules"
          detail="Every TLS connection is intercepted (while -intercept-tls is on). Add a host pattern to relay it untouched."
        />
      ) : null}
      {data && data.patterns.length > 0 ? (
        <SimpleTable headers={["Host pattern", ""]}>
          {data.patterns.map((entry) => (
            <tr key={entry}>
              <td>
                <code>{entry}</code>
              </td>
              <td>
                <IconButton
                  label={`Remove passthrough rule ${entry}`}
                  size="small"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(entry, { onSuccess: () => toast.success(`Removed ${entry}`), onError: fail })}
                >
                  <Trash2 size={13} />
                </IconButton>
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}
    </Card>
  );
}

// Burp keeps its browser block in User options → Misc, beside Hotkeys; this section sits in the
// same relative slot. Read-only on purpose: the engine is named by -dom at startup, and switching
// it live would race the audit engine's unlocked config reads and strand a cached browser.
function DomEngineSection(): JSX.Element {
  const stats = useStats();
  const checks = stats.data?.dom_checks === true;

  return (
    <Card>
      <SectionHeading
        title="Browser engine"
        detail="Which headless browser runs the DOM-based checks — named by -dom when this server started. Changing it takes a restart."
        actions={<RefreshButton onClick={() => void stats.refetch()} loading={stats.isFetching} />}
      />
      {stats.error ? <ErrorNotice error={stats.error} onRetry={() => void stats.refetch()} /> : null}
      <div className="metric-grid wide">
        <Metric label="Engine" value={stats.data?.dom_engine ?? "—"} />
        <Metric
          label="DOM-based checks"
          value={stats.data == null ? "—" : checks ? "Admitted" : "Excluded"}
          tone={checks ? "good" : "neutral"}
          detail={checks ? undefined : "Start the server with -dom chrome or -dom ws://… to admit them"}
        />
      </div>
    </Card>
  );
}

function ScannerSettingsSection(): JSX.Element {
  const configs = useScannerConfigs();

  return (
    <Card>
      <SectionHeading
        title="Scanner"
        detail="Shipped audit configurations and their concrete settings. Read-only."
        actions={
          <RefreshButton onClick={() => void configs.refetch()} loading={configs.isFetching} />
        }
      />
      {configs.error ? <ErrorNotice error={configs.error} onRetry={() => void configs.refetch()} /> : null}
      {configs.data ? (
        <>
          <div className="metric-grid wide">
            <Metric label="Shipped by Burp" value={configs.data.shipped_by_burp} />
            <Metric label="Implemented here" value={configs.data.implemented_here} />
            <Metric label="Omitted" value={configs.data.omitted_reason} detail={configs.data.how_to_run_under} />
          </div>
          {configs.data.default ? (
            <div className="stack" style={{ marginTop: "var(--gap)" }}>
              <h4>Server default</h4>
              <DetailList rows={[
                { label: "Time budget", value: formatDuration(configs.data.default.time_budget_ms) },
                { label: "Max requests", value: configs.data.default.max_requests ?? "uncapped" },
                { label: "Consecutive check failures (abandon unit)", value: configs.data.default.consecutive_check_failures_to_abandon_unit },
                { label: "Consecutive unit failures (fail item)", value: configs.data.default.consecutive_unit_failures_to_fail_item },
                { label: "Pause session after failed items", value: configs.data.default.pause_session_after_failed_items },
                { label: "Pause at failed item %", value: configs.data.default.pause_session_at_failed_item_percentage + "%" },
              ]} />
            </div>
          ) : null}
          <div className="stack" style={{ marginTop: "var(--gap)" }}>
            <h4>Presets</h4>
            <SimpleTable headers={["Name", "Keys set", ""]}>
              {(configs.data.configs ?? []).map((c) => (
                <tr key={c.name}>
                  <td><strong>{c.name}</strong></td>
                  <td><span className="cell-num">{c.keys.length}</span></td>
                  <td>{c.keys.map((k) => k.name).join(", ") || <span className="cell-dim">no extra keys</span>}</td>
                </tr>
              ))}
            </SimpleTable>
          </div>
        </>
      ) : configs.isLoading ? <LoadingPanel label="Loading scanner configurations" /> : null}
      {configs.data ? <p className="field-hint">{configs.data.applies_to_server}</p> : null}
    </Card>
  );
}

function HotkeysSection(): JSX.Element {
  return (
    <Card>
      <SectionHeading
        title="Hotkeys"
        detail="The full binding set, the same list the ? modal shows. mod is ⌘ on macOS and Ctrl elsewhere; bindings that had to differ from Burp say why."
      />
      <div className="shortcut-table">
        {SHORTCUT_GROUPS.map((group) => (
          <div key={group.title}>
            <div className="shortcut-group">{group.title}</div>
            {group.rows.map((entry) => (
              <div className="shortcut-row" key={entry.label}>
                <div>
                  {entry.keys.map((key, i) => (
                    <span key={key}>
                      {i > 0 ? "+" : null}
                      <Kbd>{key}</Kbd>
                    </span>
                  ))}
                </div>
                <span>
                  {entry.label}
                  {entry.note ? <small className="shortcut-note">{entry.note}</small> : null}
                </span>
              </div>
            ))}
          </div>
        ))}
      </div>
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
        description="Protocol reporting, appearance, the CA certificate, and the console's own diagnostics. Scope lives under Target."
      />
      <ProxySettingsSection />
      <TlsPassthroughSection />
      <ProtocolSection />
      <ScannerSettingsSection />
      <DomEngineSection />
      <AppearanceSection />
      <HotkeysSection />
      <CertificateSection />
      <DiagnosticsSection />
    </div>
  );
}
