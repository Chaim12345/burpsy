import { useEffect, useState } from "react";
import { Download, Plus, Radar, RotateCcw, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { formatBytes, formatCount, formatDuration } from "../lib/api";
import { useScannerConfig, useSaveScannerConfig, useStats } from "../lib/data";
import { useScannerConfigs } from "../lib/data.attack";
import { useNetworkSettings, useSaveNetworkSettings } from "../lib/data.network";
import type { HostOverride, NetworkPatch, NetworkSettings, RedirectMode, ResolutionPolicy } from "../lib/data.network";
import { useCaCert, useEventHubStats, useProtocols, useScopeView, useSendFrameProgram, useUpdateScope, usePassthrough, useAddPassthrough, useRemovePassthrough } from "../lib/data.policy";
import { useApp, type Density, type Theme } from "../lib/store";
import { SHORTCUT_GROUPS } from "../lib/shortcuts";
import type { FrameProgramResponse } from "../lib/types.policy";
import type { ScannerConfig } from "../lib/types";
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

// The audit-family switches Burp keeps under Scanner → Options → Scan issues, made live: every
// toggle PUTs through /api/scanner/config and persists, so a policy set here survives a restart.
// Draft-then-Save rather than save-on-toggle because flipping six families should cost one
// confirmed request, not six racing ones.
const AUDIT_CHECK_GROUPS: { title: string; detail: string; rows: { key: keyof ScannerConfig; label: string; hint?: string }[] }[] = [
  {
    title: "Active injection",
    detail: "Families that send crafted requests at the target.",
    rows: [
      { key: "check_sqli", label: "SQL injection" },
      { key: "check_xss", label: "Cross-site scripting" },
      { key: "check_path_traversal", label: "File path traversal" },
      { key: "check_ssrf", label: "Server-side request forgery" },
      { key: "check_xxe", label: "XML external entity", hint: "Needs the target to accept XML input" },
      { key: "check_jwt_weak", label: "Weak JWT secrets" },
      { key: "check_js_vulns", label: "JavaScript vulnerabilities" },
      { key: "check_cache_poisoning", label: "Web cache poisoning" },
      { key: "check_response_dependence", label: "Response-dependence analysis" },
      { key: "check_active_injection", label: "Generic active insertion probes" },
      { key: "check_extended_active", label: "Extended active coverage", hint: "More insertion points per exchange — slower, deeper" },
    ],
  },
  {
    title: "Passive",
    detail: "Response inspection that never sends a request of its own. On by default.",
    rows: [
      { key: "check_headers", label: "Security headers & cookies" },
      { key: "check_passive_posture", label: "Security posture" },
      { key: "check_passive_analysis", label: "Advanced passive analysis" },
      { key: "check_host_discovery", label: "Host discovery notes" },
    ],
  },
  {
    title: "Engines & coverage",
    detail: "Cross-cutting engines and where the scanner is allowed to spend effort.",
    rows: [
      { key: "check_corpus", label: "BCheck corpus actives", hint: "Only with a corpus loaded via --bchecks" },
      { key: "check_dom", label: "DOM-based checks", hint: "Needs -dom chrome (or ws://) at startup" },
      { key: "check_out_of_band", label: "Out-of-band callbacks", hint: "interactsh confirmation for blind findings" },
      { key: "check_stored", label: "Stored-input rendering" },
      { key: "check_extended_coverage", label: "Extended crawl coverage" },
      { key: "check_reflection_probes", label: "Reflection probing" },
    ],
  },
];

function AuditChecksSection(): JSX.Element {
  const config = useScannerConfig();
  const save = useSaveScannerConfig();
  const [draft, setDraft] = useState<ScannerConfig | null>(null);

  const confirmed = config.data ?? null;
  const current = draft ?? confirmed;
  const dirty =
    current !== null && confirmed !== null &&
    (Object.keys(confirmed) as (keyof ScannerConfig)[]).some((key) => current[key] !== confirmed[key]);

  const toggle = (key: keyof ScannerConfig) =>
    setDraft({ ...current!, [key]: !current![key] } as ScannerConfig);

  const persist = () => {
    if (!current || !confirmed) return;
    const patch: Partial<ScannerConfig> = {};
    const writable = patch as Record<string, number | boolean>;
    for (const key of Object.keys(confirmed) as (keyof ScannerConfig)[]) {
      if (current[key] !== confirmed[key]) writable[key] = current[key];
    }
    save.mutate(patch, {
      onSuccess: () => {
        toast.success("Scan configuration saved — it now governs this run and future starts");
        setDraft(null);
      },
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Saving scan configuration failed"),
    });
  };

  return (
    <Card>
      <SectionHeading
        title="Audit checks"
        detail="Which issue families the scanner runs, editable while it runs. Changes are persisted for future starts too."
        actions={
          <>
            {dirty ? <Badge tone="warn">unsaved</Badge> : null}
            <Button size="small" disabled={!dirty || save.isPending} onClick={persist}>
              Save changes
            </Button>
            <RefreshButton
              onClick={() => {
                setDraft(null);
                void config.refetch();
              }}
              loading={config.isFetching}
            />
          </>
        }
      />
      {config.error ? <ErrorNotice error={config.error} onRetry={() => void config.refetch()} /> : null}
      {config.isLoading ? <LoadingPanel label="Loading audit checks" /> : null}
      {current ? (
        <>
          <div className="metric-grid wide">
            <Field label="Concurrent checks">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={1}
                  value={current.max_concurrency}
                  onChange={(event) => setDraft({ ...current, max_concurrency: Math.max(1, Number(event.target.value) || 1) })}
                  style={{ maxWidth: "6rem" }}
                />
              )}
            </Field>
            <Field label="Check timeout (ms)">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={current.timeout_ms}
                  onChange={(event) => setDraft({ ...current, timeout_ms: Math.max(0, Number(event.target.value) || 0) })}
                  style={{ maxWidth: "8rem" }}
                />
              )}
            </Field>
            <Field label="Probe timeout (ms)">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={current.probe_timeout_ms}
                  onChange={(event) => setDraft({ ...current, probe_timeout_ms: Math.max(0, Number(event.target.value) || 0) })}
                  style={{ maxWidth: "8rem" }}
                />
              )}
            </Field>
          </div>
          <div className="stack">
            {AUDIT_CHECK_GROUPS.map((group) => (
              <div key={group.title} style={{ marginTop: "var(--gap)" }}>
                <h4>{group.title}</h4>
                <p className="cell-dim" style={{ margin: 0 }}>{group.detail}</p>
                <div className="switch-grid">
                  {group.rows.map((row) => (
                    <label key={row.key} className="switch-row" htmlFor={`audit-${row.key}`}>
                      <span>
                        <span>{row.label}</span>
                        {row.hint ? <span className="cell-dim" style={{ display: "block" }}>{row.hint}</span> : null}
                      </span>
                      <Switch id={`audit-${row.key}`} label={row.label} checked={Boolean(current[row.key])} onCheckedChange={() => toggle(row.key)} />
                    </label>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : null}
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

// Burp's Settings → Network, as one section: hostname resolution, the DNS lookup policy, the three
// timeouts, the redirect policy, 100-continue and open-ended responses.
//
// One draft over the whole document with one Save, rather than a control that PUTs on every keystroke.
// The reason is the server's own refusal rules: connect_ms must not exceed total_ms, and a resolution
// override needs a host AND an address before it can validate. Saving per field would make an operator
// raising both timeouts hit a refusal halfway through a legal edit, and would refuse a half-typed
// override row on every character. So the draft is local until Save, and Save sends only the sections
// that actually changed.
function NetworkSection(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useNetworkSettings();
  const save = useSaveNetworkSettings();

  const [draft, setDraft] = useState<NetworkSettings | null>(null);
  /** The server state the draft was adopted from; the dirty check compares against it. */
  const [baseline, setBaseline] = useState("");
  const [newHost, setNewHost] = useState("");
  const [newAddress, setNewAddress] = useState("");

  const dirty = draft !== null && JSON.stringify(draft) !== baseline;

  // Adopt server state only while the operator has nothing unsaved, the same rule matchreplace.tsx
  // follows: a background refetch must never discard edits that are not yet persisted.
  useEffect(() => {
    if (!data) return;
    // The nulls the wire uses for "no rows" become arrays here, so every control below can treat the
    // two lists the same way. Normalising on adoption also keeps the dirty check honest — comparing a
    // draft holding [] against a baseline holding null would report unsaved changes on a fresh load.
    const normalised: NetworkSettings = {
      ...data.settings,
      resolution: { ...data.settings.resolution, overrides: data.settings.resolution.overrides ?? [] },
      streaming: { ...data.settings.streaming, hosts: data.settings.streaming.hosts ?? [] },
    };
    const next = JSON.stringify(normalised);
    if (next === baseline) return;
    if (draft !== null && JSON.stringify(draft) !== baseline) return;
    setDraft(normalised);
    setBaseline(next);
  }, [data, baseline, draft]);

  const overrides = draft?.resolution.overrides ?? [];
  const streamingHosts = draft?.streaming.hosts ?? [];

  const patchSection = <S extends keyof NetworkSettings>(section: S, changes: Partial<NetworkSettings[S]>) =>
    setDraft((current) => (current === null ? current : { ...current, [section]: { ...current[section], ...changes } }));

  const setOverrides = (next: HostOverride[]) => patchSection("resolution", { overrides: next });

  const addOverride = () => {
    const host = newHost.trim();
    const address = newAddress.trim();
    if (!host || !address) return;
    setOverrides([...overrides, { host: host.toLowerCase(), address, enabled: true }]);
    setNewHost("");
    setNewAddress("");
  };

  const onRevert = () => {
    if (!baseline) return;
    setDraft(JSON.parse(baseline) as NetworkSettings);
  };

  // Only the sections that changed are sent. A full-document PUT would work, but it would also
  // overwrite a section another tab had just edited with whatever this page last read — the partial
  // patch is what makes two panels on one server safe.
  const onSave = () => {
    if (draft === null || !baseline) return;
    const base = JSON.parse(baseline) as NetworkSettings;
    const patch: NetworkPatch = {};
    for (const section of Object.keys(draft) as (keyof NetworkSettings)[]) {
      if (JSON.stringify(draft[section]) !== JSON.stringify(base[section])) {
        patch[section] = draft[section] as never;
      }
    }
    if (Object.keys(patch).length === 0) return;
    save.mutate(patch, {
      onSuccess: () => toast.success("Network settings applied"),
      // The server's refusals name the field and the limit. Passed through rather than replaced with
      // a generic message, because the message is the only thing that says what to change.
      onError: (failure: unknown) =>
        toast.error(failure instanceof Error ? failure.message : "Network settings were refused"),
    });
  };

  const following = draft !== null && draft.redirects.mode !== "never";

  return (
    <Card>
      <SectionHeading
        title="Network"
        detail="Hostname resolution, DNS lookup, timeouts, redirections and open-ended responses. These bind every request this process sends — Repeater, Intruder, scanner probes and the crawler alike."
        actions={
          <>
            {dirty ? <Badge tone="warn">unsaved changes</Badge> : <Badge tone="good">saved</Badge>}
            <Button variant="outline" size="small" onClick={onRevert} disabled={!dirty}>
              <RotateCcw size={13} />
              Revert
            </Button>
            <Button size="small" onClick={onSave} disabled={!dirty || save.isPending}>
              <Save size={13} />
              Save
            </Button>
            <RefreshButton onClick={() => void refetch()} loading={isFetching} />
          </>
        }
      />
      {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading network settings" /> : null}

      {draft && data ? (
        <>
          <h4>Hostname resolution</h4>
          <div className="notice">
            <span>
              An override sends requests for a host to an address of your choosing. The TLS SNI and the{" "}
              <code>Host</code> header keep the hostname, so this reaches a named vhost at an address DNS
              does not point at — a pre-cutover deployment, or a service reachable only by IP. The address
              must be an IP: an override replaces the lookup, so it has to end at an address.
            </span>
          </div>

          <Toolbar>
            <Field label="Host" hint="Exact name, no wildcard">
              {(id) => (
                <Input
                  id={id}
                  value={newHost}
                  onChange={(event) => setNewHost(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") addOverride();
                  }}
                  placeholder="staging.example.test"
                  style={{ maxWidth: "var(--w-sm)" }}
                />
              )}
            </Field>
            <Field label="Address" hint="IPv4 or IPv6 literal">
              {(id) => (
                <Input
                  id={id}
                  value={newAddress}
                  onChange={(event) => setNewAddress(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") addOverride();
                  }}
                  placeholder="10.0.0.7"
                  style={{ maxWidth: "var(--w-sm)" }}
                />
              )}
            </Field>
            <Button disabled={!newHost.trim() || !newAddress.trim()} onClick={addOverride}>
              <Plus size={13} />
              Add override
            </Button>
          </Toolbar>

          {overrides.length === 0 ? (
            <Empty
              title="No resolution overrides"
              detail="Every hostname is resolved by the lookup policy below. Add an override to send one host somewhere DNS does not point."
            />
          ) : (
            <SimpleTable headers={["On", "Host", "Address", ""]}>
              {overrides.map((entry, index) => (
                <tr key={`${entry.host}-${index}`}>
                  <td>
                    <Switch
                      checked={entry.enabled}
                      label={`Apply the override for ${entry.host}`}
                      onCheckedChange={(on) =>
                        setOverrides(overrides.map((row, i) => (i === index ? { ...row, enabled: on } : row)))
                      }
                    />
                  </td>
                  <td>
                    <code>{entry.host}</code>
                  </td>
                  <td>
                    <code>{entry.address}</code>
                  </td>
                  <td>
                    <IconButton
                      label={`Remove the override for ${entry.host}`}
                      size="small"
                      onClick={() => setOverrides(overrides.filter((_, i) => i !== index))}
                    >
                      <Trash2 size={13} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </SimpleTable>
          )}

          <h4>DNS lookup</h4>
          <Toolbar>
            <Field label="Lookup policy" hint="Where a hostname's address comes from">
              {(id) => (
                <Select
                  id={id}
                  value={draft.resolution.policy}
                  onChange={(event) => patchSection("resolution", { policy: event.target.value as ResolutionPolicy })}
                  style={{ maxWidth: "var(--w-sm)" }}
                >
                  <option value="system">System resolver</option>
                  <option value="resolver">A resolver I name</option>
                </Select>
              )}
            </Field>
            <Field label="Resolver address" hint="Bare address takes port 53">
              {(id) => (
                <Input
                  id={id}
                  value={draft.resolution.resolver}
                  disabled={draft.resolution.policy !== "resolver"}
                  onChange={(event) => patchSection("resolution", { resolver: event.target.value })}
                  placeholder="10.0.0.53"
                  style={{ maxWidth: "var(--w-sm)" }}
                />
              )}
            </Field>
            <Field label="Lookup timeout (ms)">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={draft.resolution.timeout_ms}
                  onChange={(event) => patchSection("resolution", { timeout_ms: Number(event.target.value) })}
                  style={{ maxWidth: "var(--w-xs)" }}
                />
              )}
            </Field>
          </Toolbar>
          <p className="field-hint">
            A named resolver has to be an IP address: a resolver reachable only by name would need a lookup
            of its own, which is the thing being configured.
          </p>

          <h4>Timeouts</h4>
          <div className="notice">
            <span>
              Three bounds because they fail differently. A connect timeout means the host is not there, a
              read timeout means it is there and silent, and a total timeout means the whole exchange
              overran. Zero means no bound of its own. The connect and read bounds must not exceed the
              total, or the total would expire first and neither would ever apply.
            </span>
          </div>
          <Toolbar>
            <Field label="Connect (ms)" hint="TCP connect and TLS handshake">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={draft.timeouts.connect_ms}
                  onChange={(event) => patchSection("timeouts", { connect_ms: Number(event.target.value) })}
                  style={{ maxWidth: "var(--w-xs)" }}
                />
              )}
            </Field>
            <Field label="Read (ms)" hint="Wait for a response to begin">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={draft.timeouts.read_ms}
                  onChange={(event) => patchSection("timeouts", { read_ms: Number(event.target.value) })}
                  style={{ maxWidth: "var(--w-xs)" }}
                />
              )}
            </Field>
            <Field label="Total (ms)" hint="Dial through last body byte">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={draft.timeouts.total_ms}
                  onChange={(event) => patchSection("timeouts", { total_ms: Number(event.target.value) })}
                  style={{ maxWidth: "var(--w-xs)" }}
                />
              )}
            </Field>
          </Toolbar>

          <h4>Redirections</h4>
          <div className="notice">
            <span>
              Off by default, and that is a design position rather than a gap. A 30x <em>is</em> the
              response: auditing a login flow needs the redirect and its <code>Set-Cookie</code>, not the
              page three hops later. Following also multiplies traffic at the client's expense and hides
              findings, because a redirect to an error page reads as a clean 200. Every hop that is
              followed is re-authorised against scope on the bytes about to be written, so a hop the scope
              refuses is refused rather than sent — including under <strong>Always</strong>, which means
              "apply no extra filter of my own", never "send what scope forbids".
            </span>
          </div>
          <Toolbar>
            <Field label="Follow redirects" hint="Burp's four modes">
              {(id) => (
                <Select
                  id={id}
                  value={draft.redirects.mode}
                  onChange={(event) => patchSection("redirects", { mode: event.target.value as RedirectMode })}
                  style={{ maxWidth: "var(--w-sm)" }}
                >
                  <option value="never">Never</option>
                  <option value="on_site">On-site only</option>
                  <option value="in_scope">In-scope only</option>
                  <option value="always">Always (still scope-checked)</option>
                </Select>
              )}
            </Field>
            <Field label="Max hops" hint={`Bounded to ${data.accepted.max_redirect_hops}`}>
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={1}
                  max={data.accepted.max_redirect_hops}
                  value={draft.redirects.max_hops}
                  disabled={!following}
                  onChange={(event) => patchSection("redirects", { max_hops: Number(event.target.value) })}
                  style={{ maxWidth: "var(--w-xs)" }}
                />
              )}
            </Field>
          </Toolbar>

          <h4>100-continue</h4>
          <div className="stack">
            <Switch
              checked={draft.continue.understand_100_continue}
              label="Read past an interim 1xx to the final response"
              onCheckedChange={(on) => patchSection("continue", { understand_100_continue: on })}
            />
            <Switch
              checked={draft.continue.remove_expect_header}
              label="Strip Expect: 100-continue from outbound requests"
              onCheckedChange={(on) => patchSection("continue", { remove_expect_header: on })}
            />
            <Field label="Expect-continue timeout (ms)" hint="How long to wait for a 100 before sending the body">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={draft.continue.expect_continue_timeout_ms}
                  onChange={(event) =>
                    patchSection("continue", { expect_continue_timeout_ms: Number(event.target.value) })
                  }
                  style={{ maxWidth: "var(--w-xs)" }}
                />
              )}
            </Field>
          </div>
          <p className="field-hint">
            A <code>100 Continue</code> is not the response, it is the peer saying "go on" — so reading past
            it is on by default. A <code>101</code> is never skipped: it is an upgrade, and the bytes after
            it belong to another protocol. Stripping the header only affects the typed send path; raw bytes
            are sent verbatim, so edit the bytes to change them.
          </p>

          <h4>Open-ended responses</h4>
          <div className="notice">
            <span>
              Hosts whose responses do not end — an event stream, a long poll. Declaring one bounds its read
              by the timeout below and returns what arrived; without the declaration it is
              indistinguishable from a hung target, and the whole response comes back as an error. Patterns
              match a hostname exactly or as <code>*.example.com</code>, which also matches the bare domain.
            </span>
          </div>
          <Toolbar>
            <Field label="Streaming host pattern">
              {(id) => (
                <Input
                  id={id}
                  value={draft.streaming.hosts?.join(", ") ?? ""}
                  onChange={(event) =>
                    patchSection("streaming", {
                      hosts: event.target.value
                        .split(",")
                        .map((entry) => entry.trim())
                        .filter((entry) => entry !== ""),
                    })
                  }
                  placeholder="*.events.example.test, live.example.test"
                  style={{ maxWidth: "var(--w-lg)" }}
                />
              )}
            </Field>
            <Field label="Open-ended timeout (ms)">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={0}
                  value={draft.streaming.timeout_ms}
                  onChange={(event) => patchSection("streaming", { timeout_ms: Number(event.target.value) })}
                  style={{ maxWidth: "var(--w-xs)" }}
                />
              )}
            </Field>
          </Toolbar>
          <p className="field-hint">
            {streamingHosts.length === 0
              ? "No host is declared open-ended. Every response is read under the timeouts above."
              : `${streamingHosts.length} pattern${streamingHosts.length === 1 ? "" : "s"} declared open-ended.`}
          </p>
        </>
      ) : null}
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
      <NetworkSection />
      <AuditChecksSection />
      <ScannerSettingsSection />
      <DomEngineSection />
      <AppearanceSection />
      <HotkeysSection />
      <CertificateSection />
      <DiagnosticsSection />
    </div>
  );
}
