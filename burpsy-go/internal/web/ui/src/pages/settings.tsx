import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { scopeBadge } from "../lib/scope-state";
import { Download, KeyRound, Plus, Radar, RotateCcw, Save, Search, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { formatBytes, formatCount, formatDuration } from "../lib/api";
import type { CaExportKind } from "../lib/ca-export";
import { useBrowserSettings, useClearBrowserData, useSaveBrowserSettings, type BrowserSettingsEdit } from "../lib/data.browser";
import { useInterceptStartup, useProxyHistoryLogging, useSaveInterceptStartup, useSaveProxyHistoryLogging, useStats } from "../lib/data";
import { useScanConfigLibrary, useScannerConfigs , useSkills, useTriageSettings } from "../lib/data.attack";
import { DEFAULT_REDIRECT_TYPES, useNetworkSettings, useSaveNetworkSettings } from "../lib/data.network";
import type {
 AddressFamily,
 HostOverride,
 NetworkPatch,
 NetworkSettings,
 RedirectMode,
 ResolutionPolicy,
} from "../lib/data.network";
import {
 useDeletePool,
 useDeleteSchedule,
 usePools,
 useSavePool,
 useSaveSchedule,
 useSchedules,
 useUpdatePool,
 useUpdateSchedule,
 type Pool,
 type Schedule,
} from "../lib/data.pools";
import {
 useClearNetworkProxy,
 useNetworkProxy,
 useRemoveNetworkProxyRule,
 useSaveNetworkProxy,
} from "../lib/data.network";
import { useBackupNow, useBackupConfig, useSaveBackupConfig, useCaCert, useCaStatus, useExportCa, useImportCaCert, useRegenerateCaCert, useEventHubStats, useProtocols, useScopeView, useSendFrameProgram, useUpdateScope, usePassthrough, useAddPassthrough, useRemovePassthrough, useSetPassthroughSwitches } from "../lib/data.policy";
import { useUninterestingHeaders, useSetUninterestingHeaders } from "../lib/data.workbench";
import { cn } from "../lib/cn";
import {
 SETTINGS_SECTIONS,
 filterSettingsSections,
 matchesAllWords,
 onSettingsSectionRequest,
 requestSettingsSection,
 settingsSectionAnchor,
 takePendingSettingsSection,
 type SettingsSection,
 type SettingsSectionId,
} from "../lib/settings-sections";
import { DEFAULT_HIDE_REQUEST_HEADERS, DEFAULT_HIDE_RESPONSE_HEADERS, parseHeaderNames } from "../lib/message";
import { editorFontStack, useApp, type Density, type EditorFont, type EditorFontFamily, type Theme, type UiScale } from "../lib/store";
import { parseThemeFile, THEME_SLOT_FAMILIES } from "../lib/theme-import";
import { ROUTE_RISK } from "../lib/route-risk";
import { ROUTE_GATED } from "../lib/gated-routes";
import type { MessageVariant } from "../ui/variant-picker";
import { actionForChord, chordKeys, shortcutGroups, validateChord, type ShortcutAction } from "../lib/shortcuts";
import { chordFromEvent, resetAllChords, resetChord, setChord, useKeymap } from "../lib/keymap";
import type { FrameProgramResponse } from "../lib/types.policy";
import type { SkillsView, TriageSettingsView } from "../lib/types.attack";
import { DetailList } from "../ui/json";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Kbd, LinkButton, Metric, Modal, NeedsValueButton, Select, Switch, Textarea, Toolbar, type Tone } from "../ui/primitives";
import { SimpleTable } from "../ui/table";
import { BURP_HOTKEYS } from "../lib/burp-hotkeys";
import { ClientCertificatesSection, PlatformAuthSection, ServerCertificatesSection } from "./settings.network";
import { FileLoggingSection } from "./settings.logging";
import { ScanConfigDetail } from "./settings.scanconfig";
import { autoBackupSchema, backupNowSchema, intervalHoursSchema, poolSchema, probeSchema } from "../lib/form-schemas";
import { WholeNumberInput } from "../ui/whole-number-input";
import { useZodForm } from "../lib/use-zod-form";

const THEMES: { value: Theme; label: string }[] = [
 { value: "system", label: "Follow the system" },
 { value: "light", label: "Light" },
 { value: "dark", label: "Dark" },
];

const DENSITIES: { value: Density; label: string }[] = [
 { value: "comfortable", label: "Comfortable" },
 { value: "compact", label: "Compact" },
];

const UI_SCALES: { value: UiScale; label: string }[] = [
 { value: "100%", label: "100% (default)" },
 { value: "110%", label: "110%" },
 { value: "125%", label: "125%" },
 { value: "150%", label: "150%" },
];

/** Burp's three readings, in the order its settings panel lists them (ngcj). Labels are its
 * own: Original / Edited / Auto-modified (map_root.tsv: configPanelProxyMessageDisplay*). */
const MESSAGE_VARIANT_OPTIONS: { value: MessageVariant; label: string }[] = [
 { value: "original", label: "Original (Burp's default)" },
 { value: "edited", label: "Edited" },
 { value: "auto-modified", label: "Auto-modified" },
];

const EDITOR_FONTS: { value: EditorFont; label: string }[] = [
 { value: "12px", label: "12px (default)" },
 { value: "13px", label: "13px" },
 { value: "14px", label: "14px" },
 { value: "16px", label: "16px" },
 { value: "18px", label: "18px" },
];

// The editor font family (burpsy-react-ui-mqrn), Burp's http_message_display.font_name. "Default"
// keeps the stylesheet's own --font-mono stack (not labelled with a face name — IBM Plex Mono leads
// that stack but is not bundled, so what "Default" renders as depends on the operator's machine).
// The rest name common monospace faces. The preview face comes from editorFontStack, the one source
// of truth the actual --editor-font-family is built from, so the menu cannot drift from the result.
const EDITOR_FONT_FAMILIES: { value: EditorFontFamily; label: string }[] = [
 { value: "default", label: "Default" },
 { value: "ibm-plex-mono", label: "IBM Plex Mono" },
 { value: "cascadia-code", label: "Cascadia Code" },
 { value: "jetbrains-mono", label: "JetBrains Mono" },
 { value: "sf-mono", label: "SF Mono" },
 { value: "consolas", label: "Consolas" },
 { value: "menlo", label: "Menlo" },
 { value: "courier-new", label: "Courier New" },
];

/** The CSS family a menu option previews in — the stored family's stack, or --font-mono for "default". */
function editorFontPreview(value: EditorFontFamily): string {
 return editorFontStack(value) || "var(--font-mono)";
}

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
      {data ? <Badge tone={scopeBadge(data).tone}>{scopeBadge(data).label}</Badge> : null}
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

export function ProtocolSection(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useProtocols();
 const probe = useSendFrameProgram();
 // The probe form (vlrh): text fields, validated and converted by probeSchema.
 const form = useZodForm(probeSchema, { host: "", port: "443", tls: true });
 const [result, setResult] = useState<FrameProgramResponse | null>(null);

 const downgrades = Object.entries(data?.downgrades ?? {});

 // Shown beside the disabled Probe button (z2l5): the host placeholder is an example, not a value.
 const probeCheck = probeSchema.safeParse(form.watch());
 const probeMissing = probeCheck.success ? null : probeCheck.error.issues[0]?.path[0] === "host" ? "needs a host" : "needs a port";

 const runProbe = form.handleSubmit(
  ({ host, port, tls }) => {
   probe.mutate(
    // No frames: the preface goes out and the reply is read, which is what
    // reports the negotiated protocol. Still authorised against scope server-side.
    { host, port, tls, preface: true, read_for_ms: 750, frames: [] },
    {
     onSuccess: (response) => {
      setResult(response);
      if (response.error) toast.error(response.error);
      else toast.success(`Negotiated ${response.negotiated || "nothing"} with ${host}`);
     },
     onError: (failure: unknown) => {
      setResult(null);
      toast.error(failure instanceof Error ? failure.message : "Probe failed");
     },
    },
   );
  },
  () => toast.error("A probe needs a host and a port"),
 );

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
     {(id) => <Input id={id} placeholder="api.example.com" {...form.register("host")} />}
    </Field>
    <Field label="Port">
     {(id) => (
      <Input id={id} inputMode="numeric" style={{ maxWidth: "var(--w-xs)" }} {...form.register("port")} />
     )}
    </Field>
    <Field label="TLS" htmlFor="protocol-probe-tls">
     <Switch id="protocol-probe-tls" label="Use TLS for the probe" checked={form.watch("tls")} onCheckedChange={(on) => form.setValue("tls", on)} />
    </Field>
    <NeedsValueButton onClick={() => void runProbe()} disabled={probe.isPending} missing={probeMissing}>
     <Radar size={13} />
     {probe.isPending ? "Probing…" : "Probe negotiation"}
    </NeedsValueButton>
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
   <InterceptStartupPreference />
   <ProxyHistoryLoggingPreference />
  </Card>
 );
}

/**
 * Burp's "Proxy history logging" (configPanelProxyHistoryLogging, burpsy-react-ui-z80e): when hosts
 * are added to the target scope, whether to stop sending out-of-scope items to Proxy history, ask
 * each time, or do nothing. Saved immediately, like the interception preference beside it.
 */
function ProxyHistoryLoggingPreference(): JSX.Element {
 const { data } = useProxyHistoryLogging();
 const save = useSaveProxyHistoryLogging();
 const mode = data?.mode ?? "ask";
 const options: { value: string; label: string; hint: string }[] = [
  { value: "stop", label: "Stop logging out-of-scope items", hint: "adding to scope turns on Don't send out-of-scope items to Proxy history" },
  { value: "ask", label: "Ask me what to do each time", hint: "adding to scope offers to stop logging (the default)" },
  { value: "nothing", label: "Do nothing", hint: "adding to scope leaves Proxy history logging alone" },
 ];
 return (
  <div style={{ marginTop: "var(--s2)" }}>
   <div className="field-hint">Proxy history logging — what adding hosts to the target scope does about out-of-scope items.</div>
   <div role="radiogroup" aria-label="Proxy history logging">
    {options.map((option) => (
     <label key={option.value} style={{ display: "flex", alignItems: "center", gap: "var(--s1)", margin: "var(--s1) 0" }}>
      <input
       type="radio"
       name="proxy-history-logging"
       checked={mode === option.value}
       onChange={() =>
        save.mutate(option.value, {
         onSuccess: () => toast.success(`Proxy history logging: ${option.label}`),
         onError: (cause) => toast.error(cause instanceof Error ? cause.message : "Could not save the Proxy history logging choice"),
        })
       }
      />
      <span>
       {option.label} <span className="field-hint">— {option.hint}</span>
      </span>
     </label>
    ))}
   </div>
  </div>
 );
}

/**
 * Burp's "Default Proxy interception state" (configPanelProxyInterception,
 * burpsy-react-ui-7vy): whether the intercept switch is on, off, or restored
 * from last session when a server starts. The three choices are Burp's own
 * radio set; "restore" is available because burpsy persists project state, and
 * it means a session that ended mid-interception resumes holding.
 *
 * A preference about the NEXT start, not the live switch — the Intercept tab's
 * toggle stays the live control. Persistence is immediate: a mode that needed a
 * save step would silently apply only when the operator remembered it.
 */
function InterceptStartupPreference(): JSX.Element {
 const { data } = useInterceptStartup();
 const save = useSaveInterceptStartup();
 const mode = data?.mode ?? "off";
 const options: { value: string; label: string; hint: string }[] = [
  { value: "off", label: "Disable interception", hint: "the intercept switch starts off (burpsy's default)" },
  { value: "on", label: "Enable interception", hint: "the intercept switch starts on" },
  { value: "restore", label: "Restore last state", hint: "the switch starts where the last session left it" },
 ];
 return (
  <div style={{ marginTop: "var(--s2)" }}>
   <div className="field-hint">Default Proxy interception state — whether interception is enabled when the server starts.</div>
   <div role="radiogroup" aria-label="Default Proxy interception state">
    {options.map((option) => (
     <label key={option.value} style={{ display: "flex", alignItems: "center", gap: "var(--s1)", margin: "var(--s1) 0" }}>
      <input
       type="radio"
       name="intercept-startup-mode"
       checked={mode === option.value}
       onChange={() =>
        save.mutate(option.value, {
         onSuccess: () => toast.success(`Interception will ${option.value === "on" ? "start on" : option.value === "off" ? "start off" : "restore its last state"} at startup`),
         onError: (cause) => toast.error(cause instanceof Error ? cause.message : "Could not save the startup preference"),
        })
       }
      />
      <span>
       {option.label}{" "}
       <span className="field-hint">— {option.hint}</span>
      </span>
     </label>
    ))}
   </div>
  </div>
 );
}

export function TlsPassthroughSection(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = usePassthrough();
 const add = useAddPassthrough();
 const remove = useRemovePassthrough();
 const switches = useSetPassthroughSwitches();
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

   {data ? (
    <Toolbar>
     <Field
      label="Apply to out-of-scope items"
      hint="relay every host the target scope cannot contain, so it is never decrypted"
      htmlFor="passthrough-out-of-scope"
     >
      <Switch
       id="passthrough-out-of-scope"
       label="Apply TLS passthrough to out-of-scope items"
       checked={data.apply_out_of_scope}
       onCheckedChange={(on) => switches.mutate({ apply_out_of_scope: on }, { onError: fail })}
      />
     </Field>
     <Field
      label="Add a host when a client refuses the certificate"
      hint={
       data.auto_added > 0
        ? `a pinned client's next connection is relayed instead of failing again — added this run: ${formatCount(data.auto_added)}`
        : "a pinned client's next connection is relayed instead of failing again"
      }
      htmlFor="passthrough-auto-add"
     >
      <Switch
       id="passthrough-auto-add"
       label="Add a host to TLS passthrough when a client refuses burpsy's certificate"
       checked={data.auto_add_on_failure}
       onCheckedChange={(on) => switches.mutate({ auto_add_on_failure: on }, { onError: fail })}
      />
     </Field>
    </Toolbar>
   ) : null}

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
/**
 * Burp's browser settings (burpsy-react-ui-bufa) — the browser "Open browser" launches, which is not
 * the DOM-check engine above: this one is the operator's, on its own profile, routed through a Proxy
 * listener. Every switch is saved with the project and applies to the next launch.
 */
function BrowserSection(): JSX.Element {
 const settings = useBrowserSettings();
 const save = useSaveBrowserSettings();
 const clear = useClearBrowserData();
 const [confirmClear, setConfirmClear] = useState(false);
 // The folder is typed, so it is a draft until the operator applies it — a PUT per keystroke would
 // save half-typed paths, and the server refuses a relative one with a 400 that should be read once.
 const [folder, setFolder] = useState<string | null>(null);
 const s = settings.data;
 const folderDraft = folder ?? s?.browser_data_directory ?? "";

 const put = (edit: BrowserSettingsEdit, what: string, after?: () => void) =>
  save.mutate(edit, {
   onSuccess: () => after?.(),
   onError: (failure) => toast.error(`${what} was not saved: ${failure.message}`),
  });

 return (
  <Card>
   <SectionHeading
    title="Browser"
    detail="The browser Open browser launches: Chromium on its own profile, routed through a burpsy Proxy listener and trusting burpsy's CA. Saved with the project; changes apply to the next launch."
    actions={<RefreshButton onClick={() => void settings.refetch()} loading={settings.isFetching} />}
   />
   {settings.isPending ? (
    <LoadingPanel label="Reading the browser settings" />
   ) : settings.isError ? (
    <ErrorNotice title="Could not read the browser settings" error={settings.error} onRetry={() => void settings.refetch()} />
   ) : s ? (
    <div className="stack">
     <div className="metric-grid wide">
      <Metric
       label="Proxy a launch will use"
       value={s.proxy || "none usable"}
       tone={s.proxy ? "good" : "warn"}
       detail={s.proxy ? undefined : "Open browser is refused until a Proxy listener is running"}
      />
      <Metric label="Browser" value={s.running ? "Running" : "Not running"} tone={s.running ? "info" : "neutral"} />
     </div>
     <Field
      label="Browser data folder"
      hint={`Empty uses the per-project default. A launch uses ${s.profile_dir}. Must be an absolute path.`}
     >
      {(id) => (
       <div className="inline-add">
        <Input
         id={id}
         value={folderDraft}
         placeholder="per-project default"
         spellCheck={false}
         onChange={(event) => setFolder(event.target.value)}
        />
        <Button
         variant="outline"
         size="small"
         disabled={save.isPending || folder === null || folder === s.browser_data_directory}
         onClick={() => put({ browser_data_directory: folderDraft.trim() }, "The data folder", () => setFolder(null))}
        >
         Apply
        </Button>
       </div>
      )}
     </Field>
     <Checkbox
      checked={s.allow_saving_browser_settings}
      disabled={save.isPending}
      onCheckedChange={(on) => put({ allow_saving_browser_settings: on }, "Store browser data")}
      label="Store browser data between launches (cookies, logins, history)"
     />
     <Checkbox
      checked={s.allow_running_without_sandbox}
      disabled={save.isPending}
      onCheckedChange={(on) => put({ allow_running_without_sandbox: on }, "Allow running without the sandbox")}
      label="Allow running without the sandbox"
     />
     <div className="notice notice-warn">
      Chromium refuses to start sandboxed when burpsy runs as root, so this is required there — and it
      removes the browser&apos;s main defence against a malicious page. Test only targets you are authorised
      to test, and prefer running burpsy as an ordinary user.
     </div>
     <Checkbox
      checked={s.disable_gpu}
      disabled={save.isPending}
      onCheckedChange={(on) => put({ disable_gpu: on }, "Disable GPU")}
      label="Disable GPU (for remote displays and VMs where hardware acceleration fails)"
     />
     <Toolbar>
      <Button variant="danger" size="small" disabled={s.running || clear.isPending} onClick={() => setConfirmClear(true)}>
       <Trash2 size={13} aria-hidden="true" />
       Clear all browser data
      </Button>
      {s.running ? <span className="field-hint">Close the burpsy browser first — its data is in use.</span> : null}
     </Toolbar>
     <Modal
      open={confirmClear}
      onOpenChange={setConfirmClear}
      title="Clear all browser data?"
      description={`Deletes the burpsy browser's profile at ${s.profile_dir} — its cookies, saved logins and history. Nothing brings them back.`}
     >
      <div className="page-actions">
       <Button variant="outline" autoFocus onClick={() => setConfirmClear(false)}>
        Cancel
       </Button>
       <Button
        variant="danger"
        disabled={clear.isPending}
        onClick={() =>
         clear.mutate(undefined, {
          onSuccess: (result) => {
           setConfirmClear(false);
           toast.success(`Cleared ${result.cleared}`);
          },
          onError: (failure) => {
           setConfirmClear(false);
           toast.error(`Browser data was not cleared: ${failure.message}`);
          },
         })
        }
       >
        <Trash2 size={13} aria-hidden="true" />
        {clear.isPending ? "Clearing…" : "Clear all browser data"}
       </Button>
      </div>
     </Modal>
    </div>
   ) : null}
  </Card>
 );
}

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

// The audit-family switches Burp keeps under Scanner -> Options -> Scan issues moved to the
// Scanner page (burpsy-react-ui-1yd): Burp puts scan configuration in the scan-launch dialogue,
// and a switch's effect - what the next audit sends - is only readable next to the thing that
// launches one. Settings keeps the configuration library: the shipped presets read-only, and the
// operator's own saved configurations, whose issue selection and parameter exemptions are edited in
// the panel a row opens (burpsy-react-ui-saq3.3.1).
function ScannerSettingsSection(): JSX.Element {
 const configs = useScannerConfigs();
 // Burp's Configuration library (burpsy-react-ui-uxcs). One name box serves both "save as" and
 // "rename to", because both answer the same question and two boxes would let them disagree.
 const configLibrary = useScanConfigLibrary();
 const [configName, setConfigName] = useState("");
 const [configFrom, setConfigFrom] = useState("");
 // Which configuration the detail panel shows, by name, so a refetch that brings a newer saved
 // version re-renders the panel with it rather than with a stale copy held here.
 const [opened, setOpened] = useState<string | null>(null);
 const openedConfig = (configs.data?.configs ?? []).find((c) => c.name === opened && !c.damaged) ?? null;
 return (
  <Card>
   <SectionHeading
    title="Scanner"
    detail="Audit configurations: the shipped presets, read-only, and your own saved ones, whose issue selection and parameter exemptions you can edit."
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
       <h3 className="subheading">Server default</h3>
       <DetailList rows={[
        { label: "Time budget", value: formatDuration(configs.data.default.time_budget_ms) },
        { label: "Max requests", value: configs.data.default.max_requests ?? "uncapped" },
        { label: "Consecutive check failures (abandon unit)", value: configs.data.default.consecutive_check_failures_to_abandon_unit },
        { label: "Consecutive unit failures (fail item)", value: configs.data.default.consecutive_unit_failures_to_fail_item },
        { label: "Pause session after failed items", value: configs.data.default.pause_session_after_failed_items },
        { label: "Pause at failed item %", value: configs.data.default.pause_session_at_failed_item_percentage + "%" },
        {
         label: "Issue selection",
         value: (configs.data.default.issue_types ?? []).length > 0
          ? `only ${formatCount((configs.data.default.issue_types ?? []).length)} selected issue types`
          : "every issue type",
        },
        { label: "Issue types disabled", value: formatCount((configs.data.default.disabled_issue_types ?? []).length) },
        { label: "Detection methods disabled", value: formatCount((configs.data.default.disabled_detection_methods ?? []).length) },
        { label: "Skip all tests for", value: (configs.data.default.skip_all_tests_for_parameters ?? []).join(", ") || "no parameters" },
        {
         label: "Skip server-side injection for",
         value: (configs.data.default.skip_server_side_injection_for_parameters ?? []).join(", ") || "no parameters",
        },
       ]} />
      </div>
     ) : null}
     {/* Burp's Configuration library (burpsy-react-ui-uxcs). The shipped presets and the operator's
         own saved configurations are ONE table, because an audit resolves one namespace and a reader
         asking "what can this run under?" should not have to merge two lists. Shipped rows are
         read-only and say so; only saved rows offer Rename and Delete, so no button is ever shown
         that could only answer 409. */}
     <div className="stack" style={{ marginTop: "var(--gap)" }}>
      <h3 className="subheading">Configuration library</h3>
      <div className="toolbar">
       <Input
        aria-label="New configuration name"
        value={configName}
        onChange={(event) => setConfigName(event.target.value)}
        placeholder="name this configuration"
        style={{ maxWidth: "var(--w-md)" }}
       />
       <Button
        size="small"
        disabled={!configName.trim() || configLibrary.isPending}
        onClick={() =>
         configLibrary.mutate(
          { action: "clone", name: configName.trim(), from: configFrom || undefined },
          {
           onSuccess: () => { toast.success(`Saved ${configName.trim()}`); setConfigName(""); },
           onError: (cause: Error) => toast.error(cause.message),
          },
         )
        }
       >
        {configFrom ? "Save a copy of the selected" : "Save current settings as…"}
       </Button>
       <Select
        aria-label="Copy from"
        value={configFrom}
        onChange={(event) => setConfigFrom(event.target.value)}
        style={{ maxWidth: "var(--w-md)" }}
       >
        <option value="">from the settings this server audits under</option>
        {(configs.data.configs ?? []).filter((c) => !c.damaged).map((c) => (
         <option key={c.name} value={c.name}>from {c.name}</option>
        ))}
       </Select>
      </div>
      <SimpleTable headers={["Name", "Source", "Keys set", "", ""]}>
       {(configs.data.configs ?? []).map((c) => (
        <tr key={c.name}>
         <td><strong>{c.name}</strong></td>
         <td>
          {c.damaged ? (
           <Badge tone="warn">unreadable</Badge>
          ) : c.shipped ? (
           <span className="cell-dim">shipped (read-only)</span>
          ) : (
           <Badge>saved</Badge>
          )}
         </td>
         {/* `?? []` because a saved or damaged row carried "keys": null until saq3.3.1, and reading
             .length off it took the whole Settings page down the moment one configuration was saved. */}
         <td><span className="cell-num">{(c.keys ?? []).length}</span></td>
         <td>{(c.keys ?? []).map((k) => k.name).join(", ") || <span className="cell-dim">no extra keys</span>}</td>
         <td>
          {c.shipped ? (
           <Button
            variant="outline"
            size="small"
            aria-pressed={opened === c.name}
            onClick={() => setOpened(opened === c.name ? null : c.name)}
           >
            View
           </Button>
          ) : (
           <div className="toolbar">
            {c.damaged ? null : (
             <Button
              variant="outline"
              size="small"
              aria-pressed={opened === c.name}
              onClick={() => setOpened(opened === c.name ? null : c.name)}
             >
              Edit
             </Button>
            )}
            <Button
             variant="outline"
             size="small"
             disabled={!configName.trim() || configLibrary.isPending}
             title={configName.trim() ? `Rename to ${configName.trim()}` : "Type the new name above first"}
             onClick={() =>
              configLibrary.mutate(
               { action: "rename", name: configName.trim(), from: c.name },
               {
                onSuccess: () => { toast.success(`Renamed to ${configName.trim()}`); setConfigName(""); },
                onError: (cause: Error) => toast.error(cause.message),
               },
              )
             }
            >
             Rename
            </Button>
            <Button
             variant="outline"
             size="small"
             disabled={configLibrary.isPending}
             onClick={() =>
              configLibrary.mutate({ action: "delete", name: c.name }, {
               onSuccess: () => toast.success(`Deleted ${c.name}`),
               onError: (cause: Error) => toast.error(cause.message),
              })
             }
            >
             Delete
            </Button>
           </div>
          )}
         </td>
        </tr>
       ))}
      </SimpleTable>
     </div>
     {openedConfig ? (
      <ScanConfigDetail key={openedConfig.name} config={openedConfig} onClose={() => setOpened(null)} />
     ) : null}
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
 const redirectTypes = draft?.redirects.types ?? DEFAULT_REDIRECT_TYPES;

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
     <h3 className="subheading">Hostname resolution</h3>
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

     <h3 className="subheading">DNS lookup</h3>
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
      <Field
       label="Address family"
       hint="Filter the answer to one family"
      >
       {(id) => (
        <Select
         id={id}
         // A document written before the field existed reads null, and that means "system" — the
         // value the engine normalises it to. Anything else would show a preference nobody set.
         value={draft.resolution.family ?? "system"}
         onChange={(event) =>
          patchSection("resolution", { family: event.target.value as AddressFamily })
         }
         style={{ maxWidth: "var(--w-sm)" }}
        >
         {(data.accepted.resolution_families ?? ["system", "ipv4", "ipv6"]).map((family) => (
          <option key={family} value={family}>
           {family === "system" ? "System order (both families)" : family.toUpperCase()}
          </option>
         ))}
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
        <WholeNumberInput
         id={id}
         min={0}
         value={draft.resolution.timeout_ms}
         onCommit={(next) => patchSection("resolution", { timeout_ms: next })}
         style={{ maxWidth: "var(--w-xs)" }}
        />
       )}
      </Field>
     </Toolbar>
     <p className="field-hint">
      A named resolver has to be an IP address: a resolver reachable only by name would need a lookup
      of its own, which is the thing being configured.
     </p>

     <h3 className="subheading">Timeouts</h3>
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
        <WholeNumberInput
         id={id}
         min={0}
         value={draft.timeouts.connect_ms}
         onCommit={(next) => patchSection("timeouts", { connect_ms: next })}
         style={{ maxWidth: "var(--w-xs)" }}
        />
       )}
      </Field>
      <Field label="Read (ms)" hint="Wait for a response to begin">
       {(id) => (
        <WholeNumberInput
         id={id}
         min={0}
         value={draft.timeouts.read_ms}
         onCommit={(next) => patchSection("timeouts", { read_ms: next })}
         style={{ maxWidth: "var(--w-xs)" }}
        />
       )}
      </Field>
      <Field label="Total (ms)" hint="Dial through last body byte">
       {(id) => (
        <WholeNumberInput
         id={id}
         min={0}
         value={draft.timeouts.total_ms}
         onCommit={(next) => patchSection("timeouts", { total_ms: next })}
         style={{ maxWidth: "var(--w-xs)" }}
        />
       )}
      </Field>
     </Toolbar>

     <h3 className="subheading">Redirections</h3>
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
        <WholeNumberInput
         id={id}
         min={1}
         max={data.accepted.max_redirect_hops}
         value={draft.redirects.max_hops}
         disabled={!following}
         onCommit={(next) => patchSection("redirects", { max_hops: next })}
         style={{ maxWidth: "var(--w-xs)" }}
        />
       )}
      </Field>
     </Toolbar>

     <Toolbar>
      <Field
       label="Resubmit cookies"
       htmlFor="network-replay-cookies"
       hint="Burp's rule for following a login redirect"
      >
       <Switch
        id="network-replay-cookies"
        label="Resubmit the cookies each hop's response set"
        checked={draft.redirects.replay_cookies === true}
        onCheckedChange={(checked) => patchSection("redirects", { replay_cookies: checked })}
       />
      </Field>
     </Toolbar>
     <p className="field-hint">
      {draft.redirects.replay_cookies === true
       ? "A hop's Set-Cookie is carried to the next hop on the same host. Off by default: a credential the target set mid-chain is not one you asked to send, and a target that sets throwaway cookies would keep resending them."
       : "Off. A login or SSO flow that sets a cookie on its 302 will arrive at the destination unauthenticated, which reads as a broken application rather than a missing cookie."}
     </p>

     <h3 className="subheading">Allowed redirect types</h3>
     <p className="field-hint">
      Which responses count as a redirect when one is followed. A Refresh or meta-refresh hop is
      sent as a GET with no body, the way a browser navigates it.
     </p>
     <div className="switch-grid">
      {(
       [
        ["understand_3xx_status_code", "3xx status code with Location header", "On by default"],
        ["understand_any_status_code_with_location_header", "Any status code with Location header", "Off by default: a 201 names what it created, not where to go"],
        ["understand_refresh_header", "Refresh header", "On by default"],
        ["understand_meta_refresh_tag", "Meta refresh tag", "On by default; HTML responses only"],
       ] as const
      ).map(([key, label, detail]) => (
       <label key={key} className="switch-row" htmlFor={`redirect-type-${key}`}>
        <span>
         <span>{label}</span>
         <span className="cell-dim" style={{ display: "block" }}>{detail}</span>
        </span>
        <Switch
         id={`redirect-type-${key}`}
         label={label}
         checked={redirectTypes[key]}
         onCheckedChange={(on) => patchSection("redirects", { types: { ...redirectTypes, [key]: on } })}
        />
       </label>
      ))}
     </div>
     <p className="field-hint">
      JavaScript-driven redirects are not followed: that would mean running the page's script, which
      this sender does not do.
     </p>

     <h3 className="subheading">HTTP/1 and HTTP/2</h3>
     <div className="switch-grid">
      <label className="switch-row" htmlFor="network-http1-keep-alive">
       <span>
        <span>Use keep-alive for HTTP/1 if the server supports it</span>
        <span className="cell-dim" style={{ display: "block" }}>
         Off by default: each request gets its own connection. On, a connection the response left reusable carries the next request to that host, and is closed after five seconds idle.
        </span>
       </span>
       <Switch
        id="network-http1-keep-alive"
        label="Use keep-alive for HTTP/1 if the server supports it"
        checked={draft.http1?.enable_keep_alive === true}
        onCheckedChange={(on) => patchSection("http1", { enable_keep_alive: on })}
       />
      </label>
      <label className="switch-row" htmlFor="network-http2-default">
       <span>
        <span>Default to HTTP/2 if the server supports it</span>
        <span className="cell-dim" style={{ display: "block" }}>
         On by default. Off, a request that names no protocol goes out as HTTP/1.1; one written as HTTP/2, or pinned to HTTP/2 in Repeater, still uses it.
        </span>
       </span>
       <Switch
        id="network-http2-default"
        label="Default to HTTP/2 if the server supports it"
        checked={draft.http2?.enable_http2 !== false}
        onCheckedChange={(on) => patchSection("http2", { enable_http2: on })}
       />
      </label>
     </div>

     <h3 className="subheading">100-continue</h3>
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
        <WholeNumberInput
         id={id}
         min={0}
         value={draft.continue.expect_continue_timeout_ms}
         onCommit={(next) => patchSection("continue", { expect_continue_timeout_ms: next })}
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

     <h3 className="subheading">Open-ended responses</h3>
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
        <WholeNumberInput
         id={id}
         min={0}
         value={draft.streaming.timeout_ms}
         onCommit={(next) => patchSection("streaming", { timeout_ms: next })}
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
     {/* Burp's three streaming_responses switches (burpsy-react-ui-609d / -v52t). They apply to the
         proxy leg and, for text/event-stream, to every request the console sends. */}
     <div className="stack">
      <Switch
       checked={draft.streaming.use_text_event_stream_header === true}
       label="Treat text/event-stream responses as streaming"
       onCheckedChange={(on) => patchSection("streaming", { use_text_event_stream_header: on })}
      />
      <p className="field-hint">
       Recognise an event stream by its content type rather than by host, so it is forwarded as it
       arrives and returned when the open-ended timeout ends — on hosts nobody declared above.
      </p>
      <Switch
       checked={draft.streaming.store !== false}
       label="Store streaming responses (may result in large captures)"
       onCheckedChange={(on) => patchSection("streaming", { store: on })}
      />
      <p className="field-hint">
       {draft.streaming.store === false
        ? "Off: a streamed body still reaches the browser live; history keeps the response head and a note instead of the bytes."
        : "On: a streamed body is recorded in history like any other response."}
      </p>
      <Switch
       checked={draft.streaming.strip_chunked_encoding_metadata === true}
       label="Strip chunked encoding metadata from streamed responses"
       onCheckedChange={(on) => patchSection("streaming", { strip_chunked_encoding_metadata: on })}
      />
      <p className="field-hint">
       {draft.streaming.strip_chunked_encoding_metadata === true
        ? "On: a chunked stream is forwarded without its Transfer-Encoding header, its body sent until the connection closes."
        : "Off: a chunked stream is forwarded as chunks, keeping its Transfer-Encoding header true."}
      </p>
     </div>

   {/* Upstream TLS: every intercepted connection was opened with verification off and nothing could
       turn it on (burpsy-react-ui-f365). On by default; the two escape hatches are named rather than
       assumed, because "add their CA" and "turn verification off" are different decisions. */}
   <Card>
    <SectionHeading
     title="Upstream TLS"
     detail="How the certificate the target presents is treated, on Repeater sends, scanner probes and browser traffic through the proxy."
    />
    {draft !== null ? (
     <>
      <Toolbar>
       <Field label="Verify target certificates" htmlFor="network-tls-verify">
        <Switch
         id="network-tls-verify"
         label="Verify the certificate the target presents"
         checked={draft.tls.verify}
         onCheckedChange={(checked) => patchSection("tls", { verify: checked })}
        />
       </Field>
       <Field label="Custom CA bundle (PEM path)">
        {(id) => (
         <Input
          id={id}
          value={draft.tls.root_ca_path}
          onChange={(event) => patchSection("tls", { root_ca_path: event.target.value })}
          placeholder="/etc/ssl/corporate-ca.pem"
          style={{ maxWidth: "var(--w-lg)" }}
         />
        )}
       </Field>
       <Field label="Minimum TLS version">
        {(id) => (
         <Select
          id={id}
          value={String(draft.tls.min_version)}
          onChange={(event) => patchSection("tls", { min_version: Number(event.target.value) })}
        >
          <option value="0">Go default</option>
          <option value="769">TLS 1.0</option>
          <option value="770">TLS 1.1</option>
          <option value="771">TLS 1.2</option>
          <option value="772">TLS 1.3</option>
        </Select>
        )}
       </Field>
      </Toolbar>
      <p className="field-hint">
       {draft.tls.verify
        ? draft.tls.root_ca_path
          ? `Verified against the system roots plus ${draft.tls.root_ca_path}. A target whose issuer is in neither is refused.`
          : "Verified against the system roots. A self-signed target is refused — add its CA above, or turn verification off for it deliberately."
        : "Verification is OFF: any certificate is accepted from any target. Use it for a self-signed lab target, not for a comparison between two builds — the certificate changing is the thing you are looking for."}
      </p>
     </>
    ) : null}
   </Card>
    </>
   ) : null}
  </Card>
 );
}

/**
 * One editable row. Capture is a keydown on a focused input rather than a text field the
 * operator types "mod+k" into: Burp captures the keystroke, and asking someone to spell a
 * chord is asking them to learn this file's vocabulary.
 */
function HotkeyRow({ action, keymap }: { action: ShortcutAction; keymap: Record<string, string | null> }): JSX.Element {
 const [editing, setEditing] = useState(false);
 const [captured, setCaptured] = useState<string>("");
 const [problem, setProblem] = useState<string | null>(null);
 const overridden = Object.prototype.hasOwnProperty.call(keymap, action.id);
 const keys = chordKeys(action, keymap);

 const commit = (raw: string) => {
  const checked = validateChord(raw);
  if ("error" in checked) {
   setProblem(checked.error);
   return;
  }
  // Duplicate detection, naming the holder — Burp's own wording is "This hotkey is already
  // assigned to ...". Silently stealing the chord would leave two rows claiming one key and
  // whichever registered last winning, which is not a thing the table could then explain.
  const clash = actionForChord(keymap, checked.chord, action.id);
  if (clash) {
   setProblem(`Already assigned to "${clash.label}"`);
   return;
  }
  setChord(action.id, checked.chord);
  setEditing(false);
  setCaptured("");
  setProblem(null);
 };

 return (
  <div className="shortcut-row">
   <div>
    {keys.map((key, i) => (
     <span key={`${key}-${i}`}>
      {i > 0 ? "+" : null}
      <Kbd>{key}</Kbd>
     </span>
    ))}
   </div>
   <span>
    {action.label}
    {action.note ? <small className="shortcut-note">{action.note}</small> : null}
    {!action.rebindable ? <small className="shortcut-note">Fixed — not reassignable</small> : null}
    {problem ? <small className="shortcut-note">{problem}</small> : null}
   </span>
   <span className="shortcut-actions">
    {action.rebindable ? (
     editing ? (
      <>
       <Input
        aria-label={`New keystroke for ${action.label}`}
        autoFocus
        readOnly
        value={captured}
        placeholder="Press a combination"
        onKeyDown={(event) => {
         event.preventDefault();
         if (event.key === "Escape") {
          setEditing(false);
          setCaptured("");
          setProblem(null);
          return;
         }
         const chord = chordFromEvent(event);
         setCaptured(chord);
         setProblem(null);
         if (event.key === "Enter" && captured !== "") commit(captured);
        }}
       />
       <Button size="small" variant="primary" disabled={captured === ""} onClick={() => commit(captured)}>
        Apply
       </Button>
       <Button size="small" variant="quiet" onClick={() => { setEditing(false); setCaptured(""); setProblem(null); }}>
        Cancel
       </Button>
      </>
     ) : (
      <>
       <Button size="small" variant="quiet" onClick={() => { setEditing(true); setProblem(null); }}>
        Edit
       </Button>
       {overridden ? (
        <Button size="small" variant="quiet" onClick={() => resetChord(action.id)}>
         Reset
        </Button>
       ) : null}
      </>
     )
    ) : null}
   </span>
  </div>
 );
}

function HotkeysSection(): JSX.Element {
 const keymap = useKeymap();
 const [term, setTerm] = useState("");
 const groups = useMemo(() => {
  const needle = term.trim().toLowerCase();
  return shortcutGroups()
   .map((group) => ({
    title: group.title,
    rows: group.rows.filter(
     (row) =>
      needle === "" ||
      row.label.toLowerCase().includes(needle) ||
      row.group.toLowerCase().includes(needle) ||
      chordKeys(row, keymap).join("+").toLowerCase().includes(needle),
    ),
   }))
   .filter((group) => group.rows.length > 0);
 }, [term, keymap]);

 const rebindable = shortcutGroups().flatMap((g) => g.rows).filter((r) => r.rebindable).length;
 const fixed = shortcutGroups().flatMap((g) => g.rows).length - rebindable;
 const overrides = Object.keys(keymap).length;
 const shown = groups.reduce((n, g) => n + g.rows.length, 0);

 return (
  <Card>
   <SectionHeading
    title="Hotkeys"
    detail="mod is ⌘ on macOS and Ctrl elsewhere. Stored in this browser; it does not travel with the capture."
    actions={overrides > 0 ? <Button size="small" variant="quiet" onClick={resetAllChords}>Reset all</Button> : undefined}
   />
   <Field label="Search hotkeys" hint="Matches the action, its group, or the keys themselves.">
    {(id) => <Input id={id} value={term} onChange={(event) => setTerm(event.target.value)} placeholder="repeater, palette, mod+k" />}
   </Field>
   {/* Three counts, because they answer three different questions: how many can be changed,
          how many cannot, and how many the operator has changed. A single "22 shortcuts" would
          hide the fact that most of these rows have no Edit button and say why. */}
   <p className="field-hint">
    {formatCount(rebindable)} reassignable, {formatCount(fixed)} fixed
    {overrides > 0 ? `, ${formatCount(overrides)} changed from the default` : ""}
    {term.trim() !== "" ? ` — showing ${formatCount(shown)}` : ""}
   </p>
   <div className="shortcut-table">
    {groups.length === 0 ? (
     <Empty title="No matching hotkey" detail="Nothing matches that search." />
    ) : (
     groups.map((group) => (
      <div key={group.title}>
       <div className="shortcut-group">{group.title}</div>
       {group.rows.map((row) => (
        <HotkeyRow key={row.id} action={row} keymap={keymap} />
       ))}
      </div>
     ))
    )}
   </div>
   <BurpHotkeyTable term={term} />
  </Card>
 );
}

const DISPOSITION_LABEL = { same: "Same chord", alternative: "Browser alternative", declined: "Declined" } as const;
const DISPOSITION_TONE = { same: "good", alternative: "warn", declined: "neutral" } as const;

/**
 * Burp's 50 shipped hotkeys and what burpsy does with each (2czi, lib/burp-hotkeys.ts): the same
 * chord, a browser-forced alternative with the reason, or declined with the reason. The answer to
 * "where did my Ctrl+T go" lives here rather than in a wiki.
 */
function BurpHotkeyTable({ term }: { term: string }): JSX.Element {
 const needle = term.trim().toLowerCase();
 const rows = BURP_HOTKEYS.filter(
  (row) =>
   needle === "" ||
   row.action.replace(/_/g, " ").includes(needle) ||
   row.burpChord.toLowerCase().includes(needle) ||
   (row.chord ?? "").includes(needle) ||
   row.reason.toLowerCase().includes(needle),
 );
 const counts = { same: 0, alternative: 0, declined: 0 };
 for (const row of BURP_HOTKEYS) counts[row.disposition] += 1;
 return (
  <div className="burp-hotkeys">
   <div className="shortcut-group">Burp's default hotkeys</div>
   <p className="field-hint">
    Burp ships {BURP_HOTKEYS.length}: {counts.same} bound to the same chord, {counts.alternative} to a browser-forced
    alternative, {counts.declined} declined. Every other Burp action has no default chord and is in the command palette.
   </p>
   {rows.length === 0 ? (
    <Empty title="No matching Burp hotkey" detail="Nothing in Burp's default table matches that search." />
   ) : (
    <SimpleTable headers={["Burp action", "Burp", "burpsy", "Disposition", "Why"]}>
     {rows.map((row) => (
      <tr key={row.action}>
       <td>
        <code>{row.action}</code>
       </td>
       <td>
        <Kbd>{row.burpChord}</Kbd>
       </td>
       <td>{row.chord ? <Kbd>{row.chord}</Kbd> : <span className="cell-dim">none</span>}</td>
       <td>
        <Badge tone={DISPOSITION_TONE[row.disposition]}>{DISPOSITION_LABEL[row.disposition]}</Badge>
       </td>
       <td className="burp-hotkeys-reason">{row.reason}</td>
      </tr>
     ))}
    </SimpleTable>
   )}
  </div>
 );
}

function AppearanceSection(): JSX.Element {
 const theme = useApp((state) => state.theme);
 const setTheme = useApp((state) => state.setTheme);
 const density = useApp((state) => state.density);
 const setDensity = useApp((state) => state.setDensity);
 const tableStripes = useApp((state) => state.tableStripes);
 const setTableStripes = useApp((state) => state.setTableStripes);
 const editorFont = useApp((state) => state.editorFont);
 const setEditorFont = useApp((state) => state.setEditorFont);
 const editorFontFamily = useApp((state) => state.editorFontFamily);
 const setEditorFontFamily = useApp((state) => state.setEditorFontFamily);
 const uiScale = useApp((state) => state.uiScale);
 const setUiScale = useApp((state) => state.setUiScale);

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
    {/* Burp's Settings › Display › Table appearance (desktop/settings/ui/display.html): "Zebra
        stripe" / "No zebra stripe", zebra by default. */}
    <Field label="Table appearance" hint="Zebra stripes shade every other row, so a long table reads across.">
     {(id) => (
      <Select id={id} value={tableStripes ? "zebra" : "plain"} onChange={(event) => setTableStripes(event.target.value === "zebra")}>
       <option value="zebra">Zebra stripe</option>
       <option value="plain">No zebra stripe</option>
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
    {/* The two text scales (burpsy-react-ui-7bd), Burp's separate knobs: the UI scale
        multiplies every chrome text token; the editor font sizes the message editor
        alone. Separate, because browser zoom scales everything together and the
        editor's HTTP bytes are what an operator stares at for hours. */}
    <Field label="UI text size" hint="Scales the interface text; the message editor is separate.">
     {(id) => (
      <Select id={id} value={uiScale} onChange={(event) => setUiScale(event.target.value as UiScale)}>
       {UI_SCALES.map((option) => (
        <option key={option.value} value={option.value}>
         {option.label}
        </option>
       ))}
      </Select>
     )}
    </Field>
    <Field label="Editor font size" hint="Sizes the HTTP message editors only.">
     {(id) => (
      <Select id={id} value={editorFont} onChange={(event) => setEditorFont(event.target.value as EditorFont)}>
       {EDITOR_FONTS.map((option) => (
        <option key={option.value} value={option.value}>
         {option.label}
        </option>
       ))}
      </Select>
     )}
    </Field>
    {/* The editor font family (burpsy-react-ui-mqrn), Burp's http_message_display.font_name. Each
        option is rendered in its own face so the menu previews the font; a family the machine lacks
        falls back to generic monospace, so the HTTP bytes never land in the body sans. */}
    <Field label="Editor font" hint="The monospace family the HTTP message editors read in.">
     {(id) => (
      <Select
       id={id}
       value={editorFontFamily}
       onChange={(event) => setEditorFontFamily(event.target.value as EditorFontFamily)}
       style={{ fontFamily: editorFontPreview(editorFontFamily) }}
      >
       {EDITOR_FONT_FAMILIES.map((option) => (
        <option key={option.value} value={option.value} style={{ fontFamily: editorFontPreview(option.value) }}>
         {option.label}
        </option>
       ))}
      </Select>
     )}
    </Field>
   </div>
   <ThemeImport />
  </Card>
 );
}

/**
 * The JSON theme import (burpsy-react-ui-fpew), Burp's ThemeFactory.loadCustom scoped to burpsy's own
 * tokens. A palette is pasted or loaded from a file, applied live (the preview — every slot it names
 * overrides the Penpot default), and reverted with one button. A file that names a slot burpsy has no
 * token for is refused, naming the slot, rather than partly applied.
 *
 * Paste and file both, mirroring the CA-certificate import below: an operator on an SSH-forwarded
 * console has the JSON as text already, and a file picker there reaches into the wrong machine.
 */
function ThemeImport(): JSX.Element {
 const customTheme = useApp((state) => state.customTheme);
 const setCustomTheme = useApp((state) => state.setCustomTheme);
 const themePreview = useApp((state) => state.themePreview);
 const setThemePreview = useApp((state) => state.setThemePreview);
 const [text, setText] = useState("");
 const [fileName, setFileName] = useState("");
 const [error, setError] = useState<string | null>(null);
 const fileRef = useRef<HTMLInputElement>(null);

 // Preview, not keep: a bad palette (dark text on dark paper) would make this very page unreadable —
 // the Revert button included — so applying parses into themePreview, which is not persisted and so is
 // escaped by a reload. "Keep this theme" is the deliberate second step that survives one.
 const preview = () => {
  const result = parseThemeFile(text);
  if ("error" in result) {
   setError(result.error);
   return;
  }
  setError(null);
  setThemePreview(result.theme);
 };

 const tokenCount = (t: { tokens: Record<string, string> }) => Object.keys(t.tokens).length;

 return (
  <div className="stack" style={{ marginTop: "var(--gap)" }}>
   <SectionHeading
    title="Theme import"
    detail={`A JSON palette filling only the slots it names — ${THEME_SLOT_FAMILIES.map((f) => f.family).join(", ")}. The rest stay at the defaults; the editor's syntax colours (header, body highlighting) are not themeable yet.`}
   />
   {themePreview ? (
    <p className="field-hint">
     Previewing <strong>{themePreview.name || "an imported theme"}</strong> ({tokenCount(themePreview)} token
     {tokenCount(themePreview) === 1 ? "" : "s"}) — not kept yet; a reload discards it.
    </p>
   ) : customTheme ? (
    <p className="field-hint">
     Applied: <strong>{customTheme.name || "an imported theme"}</strong> — {tokenCount(customTheme)} token
     {tokenCount(customTheme) === 1 ? "" : "s"} overridden.
    </p>
   ) : null}
   <Field label="Theme JSON" hint='An object with a `tokens` map, e.g. {"name":"House","tokens":{"paper":"#0b0b0b","text":"#e6e6e6"}}.'>
    {(id) => (
     <Textarea
      id={id}
      value={text}
      onChange={(event) => {
       setText(event.target.value);
       setFileName("");
       setError(null);
      }}
      rows={6}
      placeholder={'{\n  "name": "House palette",\n  "tokens": {\n    "paper": "#0b0b0b",\n    "text": "#e6e6e6",\n    "editor-bg": "#111111"\n  }\n}'}
      aria-label="Theme JSON"
     />
    )}
   </Field>
   <Toolbar>
    <Button size="small" onClick={preview} disabled={!text.trim()}>
     Preview theme
    </Button>
    <Button variant="outline" size="small" onClick={() => fileRef.current?.click()}>
     Load from file
    </Button>
    {fileName ? <span className="cell-dim">{fileName}</span> : null}
    {themePreview ? (
     <>
      <Button
       size="small"
       onClick={() => {
        setCustomTheme(themePreview);
        setThemePreview(null);
       }}
      >
       Keep this theme
      </Button>
      <Button variant="outline" size="small" onClick={() => setThemePreview(null)}>
       Discard preview
      </Button>
     </>
    ) : null}
    {customTheme && !themePreview ? (
     <Button
      variant="outline"
      size="small"
      onClick={() => {
       setCustomTheme(null);
       setError(null);
      }}
     >
      Revert to default
     </Button>
    ) : null}
    <input
     ref={fileRef}
     type="file"
     accept="application/json,.json"
     className="sr-only"
     aria-hidden="true"
     tabIndex={-1}
     onChange={(event) => {
      const file = event.target.files?.[0];
      // Cleared so re-picking the same file fires change again — an edited palette saved over the
      // same path is the ordinary way to iterate on a colour that read wrong.
      event.target.value = "";
      if (!file) return;
      void file.text().then((contents) => {
       setText(contents);
       setFileName(file.name);
       setError(null);
      });
     }}
    />
   </Toolbar>
   {error ? <ErrorNotice error={error} title="This theme was refused" /> : null}
  </div>
 );
}

/**
 * Burp's `configPanelCustomCACertificates`. Until this existed the capability was real and
 * filesystem-only — `-ca-dir` at startup — so bringing your own CA cost a restart and every
 * exchange captured so far.
 *
 * Two textareas rather than a file picker: the operator almost always has these as PEM text
 * already, and a paste target works identically over an SSH-forwarded console where a file picker
 * would be reaching into the wrong machine's filesystem.
 */
/**
 * Burp's Settings > User interface > Message editor, the half that drives the eye button above a
 * message (burpsy-react-ui-whr). Burp keeps the two lists as user options —
 * `user_options.misc.uninteresting_headers` (request), `user_options.misc.uninteresting_response_headers`
 * (response), gated by `user_options.misc.uninteresting_headers.hide_uninteresting_headers_by_default`
 * (recovered from the obfuscated jar: burp.Zf4w, burp.Zhs4, burp.Zblz in map_root.tsv). They are
 * per-browser here because only this browser's render consults them; the server never reads them.
 *
 * The section below is a *different* feature with a deliberately similar name: the Comparer's list
 * dims a difference inside a header and hides nothing. This one removes the line from the Pretty
 * view outright. The defect this closes was an operator reading one of those for the other, so both
 * sections name the other and say which is which.
 */
function MessageEditorSection(): JSX.Element {
 const defaultVariant = useApp((state) => state.defaultMessageVariant);
 const setDefaultVariant = useApp((state) => state.setDefaultMessageVariant);
 // A store persisted before these keys existed has them as undefined, and `request.join("\n")`
 // below then threw out of this section and took the whole Settings page down. The fallback is the
 // shipped default list — what the store seeds for a fresh install — so an operator upgrading from
 // before the message-editor lists sees what a new install sees (burpsy-react-ui-2qbi).
 const request = useApp((state) => state.hideRequestHeaders) ?? DEFAULT_HIDE_REQUEST_HEADERS;
 const response = useApp((state) => state.hideResponseHeaders) ?? DEFAULT_HIDE_RESPONSE_HEADERS;
 const byDefault = useApp((state) => state.hideHeadersByDefault);
 const setHideHeaders = useApp((state) => state.setHideHeaders);
 const setHideHeadersByDefault = useApp((state) => state.setHideHeadersByDefault);
 const [requestDraft, setRequestDraft] = useState<string | null>(null);
 const [responseDraft, setResponseDraft] = useState<string | null>(null);

 // Drafts, like the Comparer panel below: the textarea must not be rewritten under the
 // operator's cursor by an unrelated re-render.
 const requestText = requestDraft ?? request.join("\n");
 const responseText = responseDraft ?? response.join("\n");
 const dirty = requestDraft !== null || responseDraft !== null;

 const commit = () => {
  // Through parseHeaderNames, the same function the stored list is built with, so what is
  // saved cannot disagree with what was typed about case or duplicates.
  setHideHeaders("request", parseHeaderNames(requestText));
  setHideHeaders("response", parseHeaderNames(responseText));
  setRequestDraft(null);
  setResponseDraft(null);
  toast.success("Hide-headers lists saved");
 };

 return (
  <Card>
   <SectionHeading
    title="Message editor"
    detail="Which headers the message editor's eye button hides in a Pretty view. Stored in this browser."
   />
   <div className="two-col">
    <Field label="Hide request headers" hint="One name per line. Hidden in a request's Pretty view when the eye is on.">
     <Textarea
      aria-label="Header names the request eye hides, one per line"
      rows={8}
      spellCheck={false}
      value={requestText}
      onChange={(event) => setRequestDraft(event.target.value)}
     />
    </Field>
    <Field label="Hide response headers" hint="One name per line. Hidden in a response's Pretty view when the eye is on.">
     <Textarea
      aria-label="Header names the response eye hides, one per line"
      rows={8}
      spellCheck={false}
      value={responseText}
      onChange={(event) => setResponseDraft(event.target.value)}
     />
    </Field>
   </div>
   <Toolbar>
    <Button size="small" disabled={!dirty} onClick={commit}>
     Save
    </Button>
    <Button
     size="small"
     variant="ghost"
     onClick={() => {
      setRequestDraft(DEFAULT_HIDE_REQUEST_HEADERS.join("\n"));
      setResponseDraft(DEFAULT_HIDE_RESPONSE_HEADERS.join("\n"));
      toast.message("Defaults restored in this form — Save to apply.");
     }}
    >
     Restore defaults
    </Button>
    {dirty ? <Badge tone="warn">unsaved</Badge> : null}
   </Toolbar>
   <Field label="Hide these headers by default" hint="A newly opened Pretty view starts with the eye already on.">
    {(id) => (
     <Switch
      id={id}
      label="Hide these headers by default"
      checked={byDefault}
      onCheckedChange={setHideHeadersByDefault}
     />
    )}
   </Field>
   <Field
    label="Default message reading"
    hint="Which reading a newly selected Proxy history row opens on: the message as modified (Edited), as the peer sent it (Original), or as Match & Replace rewrote it (Auto-modified). Burp's own default is Original."
   >
    {(id) => (
     <Select id={id} value={defaultVariant} onChange={(event) => setDefaultVariant(event.target.value as MessageVariant)}>
      {MESSAGE_VARIANT_OPTIONS.map((option) => (
       <option key={option.value} value={option.value}>
        {option.label}
       </option>
      ))}
     </Select>
    )}
   </Field>
   <p className="field-hint">
    The eye button above a message hides these names in the <strong>Pretty</strong> view only, and the
    bytes are never touched: Raw still shows every header, and so does anything sent. This is not{" "}
    <strong>Comparer: uninteresting headers</strong> below — those names are still shown in a message
    and only their <em>differences</em> are dimmed.
   </p>
  </Card>
 );
}

/**
 * Burp's `configPanelUninterestingRequestHeaders` / `configPanelUninterestingResponseHeaders`
 * (W6 #81/#82), which had no counterpart here at all.
 *
 * One panel for both directions because they are one decision with two lists, and because splitting
 * them would put the request list — empty by default, and rarely wanted — on equal footing with the
 * response list, which is the one that does the work.
 *
 * The wording is careful about what this does: differences inside these headers are *dimmed and
 * counted*, never removed. A setting that quietly dropped differences from a security tool's
 * comparison would be a bad idea however convenient.
 */
/**
 * Burp's `configPanelAutomaticProjectBackup` (W6 #2). Nothing in this build ever copied the project
 * file: persistence existed, so losing the machine lost the engagement.
 *
 * Two halves, and the scheduled one is the point. This card takes a snapshot now; the recurring
 * backup is a schedule of kind "backup" in the Scheduled tasks section below, which reaches the same
 * code — a scheduled backup and a clicked one are one path, so the scheduled one cannot be the
 * version nobody watches.
 */
export function ProjectBackupSection(): JSX.Element {
 const backup = useBackupNow();
 const form = useZodForm(backupNowSchema, { dir: "", retention: "7" });
 const runBackup = form.handleSubmit((options) =>
  backup.mutate(options, {
   onSuccess: (result) =>
    // The warning is surfaced rather than swallowed: "backed up, but beside the live
    // database" and "backed up" are different outcomes.
    result.warning
     ? toast.warning(`Snapshot written to ${result.path} — ${result.warning}`)
     : toast.success(`Snapshot written to ${result.path}; kept ${result.kept}, pruned ${result.pruned}`),
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Backup failed"),
  }),
 );

 return (
  <Card>
   <SectionHeading
    title="Project backup"
    detail="A consistent snapshot of the project database, taken with SQLite's own VACUUM INTO rather than a file copy."
   />
   <AutomaticBackup />
   <div className="form-grid">
    <label htmlFor="backup-dir">Directory</label>
    <Input
     id="backup-dir"
     aria-label="Backup directory"
     placeholder="blank writes beside the live database — worst place if the disk is what fails"
     {...form.register("dir")}
    />
    <label htmlFor="backup-retention">Keep</label>
    <Input
     id="backup-retention"
     aria-label="How many snapshots to keep"
     type="number"
     min={-1}
     aria-invalid={form.formState.errors.retention ? true : undefined}
     {...form.register("retention")}
    />
   </div>
   {form.formState.errors.retention ? (
    <p className="field-hint" role="alert">
     {form.formState.errors.retention.message}
    </p>
   ) : null}
   <Toolbar>
    <Button size="small" disabled={backup.isPending} onClick={() => void runBackup()}>
     {backup.isPending ? "Backing up…" : "Back up now"}
    </Button>
    <span style={{ fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>
     Keep <code>-1</code> to never prune. Snapshots beyond the count are deleted oldest-first,
     and only files this feature wrote are ever touched.
    </span>
   </Toolbar>
   <p className="field-hint">
    A snapshot is a whole copy of the project database, so it costs time and disk proportional to the
    project — which is why the automatic backup above runs on an interval rather than on every write.
    It appears as a schedule named <code>Automatic backup</code> in the Scheduled tasks section, the
    same path a clicked backup takes.
   </p>
  </Card>
 );
}

/**
 * The automatic-backup setting (burpsy-react-ui-jkvb): Burp's configPanelAutomaticProjectBackup
 * interval and its "delete backup file on clean shutdown of Burp" switch. The interval is a real
 * schedule under the covers — the one a clicked and a scheduled backup already share — so setting it
 * here and seeing it in Scheduled tasks are the same fact. 0 minutes turns it off.
 *
 * The in-scope-only narrowing Burp also offers is declined with its reason: burpsy's snapshot is a
 * VACUUM INTO of one SQLite file, and filtering it to in-scope rows would be a second, differently
 * shaped export — a different feature, not a switch on this one.
 */
function AutomaticBackup(): JSX.Element {
 const config = useBackupConfig();
 const save = useSaveBackupConfig();
 const saved = config.data;
 // Saved values fill the fields until the operator types; a background refetch never clobbers an
 // edit in progress (keepDirtyValues in useZodForm).
 const form = useZodForm(
  autoBackupSchema,
  { interval: "0", dir: "", retention: "7" },
  saved ? { interval: String(saved.interval_minutes), dir: saved.dir ?? "", retention: String(saved.retention) } : undefined,
 );
 const deleteOnShutdown = saved?.delete_on_shutdown ?? false;
 const dirty = form.formState.isDirty;

 const commit = (patch: { delete_on_shutdown?: boolean }) =>
  void form.handleSubmit(
   ({ interval_minutes, dir, retention }) =>
    save.mutate(
     { interval_minutes, dir, retention, delete_on_shutdown: patch.delete_on_shutdown ?? deleteOnShutdown },
     {
      onSuccess: () => {
       form.reset(form.getValues());
       toast.success(interval_minutes === 0 ? "Automatic backup turned off." : `Automatic backup every ${interval_minutes} minute${interval_minutes === 1 ? "" : "s"}.`);
      },
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not save the backup setting"),
     },
    ),
   (errors) => toast.error(errors.interval?.message ?? errors.retention?.message ?? "Check the backup settings."),
  )();

 return (
  <div className="stack" style={{ marginBottom: "var(--gap)" }}>
   <div className="form-grid">
    <label htmlFor="backup-interval">Every</label>
    <div style={{ display: "flex", alignItems: "center", gap: "var(--gap-sm)" }}>
     <Input
      id="backup-interval"
      aria-label="Automatic backup interval in minutes"
      type="number"
      min={0}
      style={{ maxWidth: 120 }}
      {...form.register("interval")}
     />
     <span className="cell-dim">minutes — 0 is off</span>
    </div>
    <label htmlFor="auto-backup-dir">Directory</label>
    <Input
     id="auto-backup-dir"
     aria-label="Automatic backup directory"
     placeholder="blank writes beside the live database"
     {...form.register("dir")}
    />
    <label htmlFor="auto-backup-retention">Keep</label>
    <Input
     id="auto-backup-retention"
     aria-label="How many automatic snapshots to keep"
     type="number"
     min={-1}
     style={{ maxWidth: 120 }}
     {...form.register("retention")}
    />
   </div>
   <Switch
    checked={deleteOnShutdown}
    label="Delete the backup on a clean shutdown"
    onCheckedChange={(checked) => commit({ delete_on_shutdown: checked })}
   />
   <Toolbar>
    <Button size="small" disabled={!dirty || save.isPending} onClick={() => commit({})}>
     {save.isPending ? "Saving…" : "Save automatic backup"}
    </Button>
    {config.isError ? <span className="cell-dim">Backup settings need a project database (-db).</span> : null}
   </Toolbar>
   <p className="field-hint">
    In-scope-only backups are not offered: the snapshot is a single-file VACUUM INTO of the whole
    database, and narrowing it to in-scope rows would be a second, differently shaped export — a
    different feature, not a switch on this one.
   </p>
  </div>
 );
}

function UninterestingHeadersSection(): JSX.Element {
 const lists = useUninterestingHeaders();
 const save = useSetUninterestingHeaders();
 const [requestDraft, setRequestDraft] = useState<string | null>(null);
 const [responseDraft, setResponseDraft] = useState<string | null>(null);

 const data = lists.data;
 // The drafts start as null so a background refetch cannot overwrite an in-progress edit, and the
 // textarea falls back to the server's list until the operator types.
 const requestText = requestDraft ?? (data?.request ?? []).join("\n");
 const responseText = responseDraft ?? (data?.response ?? []).join("\n");
 const dirty = requestDraft !== null || responseDraft !== null;

 const commit = (next: { request?: string[]; response?: string[] }) =>
  save.mutate(next, {
   onSuccess: () => {
    setRequestDraft(null);
    setResponseDraft(null);
    toast.success("Uninteresting headers saved");
   },
   onError: (failure: unknown) =>
    toast.error(failure instanceof Error ? failure.message : "Saving the header lists failed"),
  });

 const toList = (text: string) =>
  text
   .split("\n")
   .map((line) => line.trim())
   .filter((line) => line !== "");

 return (
  <Card>
   <SectionHeading
    title="Comparer: uninteresting headers"
    detail={
     data?.applies_to?.length
      ? `Differences in these headers are dimmed in: ${data.applies_to.join(", ")}.`
      : "Headers whose differences are dimmed when comparing messages."
    }
    actions={
     <RefreshButton onClick={() => void lists.refetch()} loading={lists.isFetching} label="Reload" />
    }
   />
   {lists.error ? <ErrorNotice error={lists.error} onRetry={() => void lists.refetch()} /> : null}
   <div className="two-col">
    <Field label="Response headers" hint="One name per line. Applied when comparing responses.">
     <Textarea
      aria-label="Uninteresting response headers, one per line"
      rows={8}
      spellCheck={false}
      value={responseText}
      onChange={(event) => setResponseDraft(event.target.value)}
     />
    </Field>
    <Field label="Request headers" hint="Empty by default: nothing you sent is noise unless you say so.">
     <Textarea
      aria-label="Uninteresting request headers, one per line"
      rows={8}
      spellCheck={false}
      value={requestText}
      onChange={(event) => setRequestDraft(event.target.value)}
     />
    </Field>
   </div>
   <Toolbar>
    <Button
     size="small"
     disabled={!dirty || save.isPending}
     onClick={() => commit({ request: toList(requestText), response: toList(responseText) })}
    >
     {save.isPending ? "Saving…" : "Save"}
    </Button>
    <Button
     size="small"
     variant="ghost"
     disabled={save.isPending || !data}
     onClick={() => {
      // Restore the server's own defaults rather than a copy of them held here — two
      // declarations of a default list drift, and the API already reports one.
      setResponseDraft((data?.default_response ?? []).join("\n"));
      toast.message("Response defaults restored in the editor — Save to apply.");
     }}
    >
     Restore response defaults
    </Button>
    {dirty ? <Badge tone="warn">unsaved</Badge> : null}
   </Toolbar>
   <p className="field-hint">
    Nothing is hidden. A difference inside one of these headers is still reported and still
    rendered — dimmed, and counted separately — so &ldquo;the only differences were in headers you
    discounted&rdquo; stays distinguishable from &ldquo;these messages are identical&rdquo;.
    <strong> Set-Cookie is deliberately not a default</strong>: a rotated or fixated session token
    can be the finding.
   </p>
   <p className="field-hint">
    Not the message editor&rsquo;s hide-headers lists: these names are still shown in a message, so the
    only thing this list changes is what a comparison discounts. The lists that <em>remove</em> lines
    from a Pretty view live in <strong>Message editor</strong> above.
   </p>
  </Card>
 );
}

function CaImportSection(): JSX.Element {
 const status = useCaStatus();
 const importCa = useImportCaCert();
 const regenerateCa = useRegenerateCaCert();
 const [certPem, setCertPem] = useState("");
 const [keyPem, setKeyPem] = useState("");
 const [confirmRegen, setConfirmRegen] = useState(false);

 const s = status.data;
 const ready = certPem.trim() !== "" && keyPem.trim() !== "" && !importCa.isPending;

 return (
  <Card>
   <SectionHeading
    title="Use your own CA"
    detail={
     s?.configured
      ? `Signing as ${s.subject}${s.not_after ? ` · expires ${new Date(s.not_after).toLocaleDateString()}` : ""}`
      : (s?.hint ?? "No signing CA.")
    }
    actions={
     <RefreshButton onClick={() => void status.refetch()} loading={status.isFetching} label="Re-check" />
    }
   />
   <div className="form-grid" style={{ marginTop: 8 }}>
    <label htmlFor="ca-cert-pem">Certificate (PEM)</label>
    <Textarea
     id="ca-cert-pem"
     aria-label="CA certificate in PEM format"
     rows={5}
     spellCheck={false}
     placeholder="-----BEGIN CERTIFICATE-----"
     value={certPem}
     onChange={(e) => setCertPem(e.target.value)}
    />
    <label htmlFor="ca-key-pem">Private key (PEM)</label>
    <Textarea
     id="ca-key-pem"
     aria-label="CA private key in PEM format"
     rows={5}
     spellCheck={false}
     placeholder="-----BEGIN PRIVATE KEY----- (PKCS#1 or PKCS#8)"
     value={keyPem}
     onChange={(e) => setKeyPem(e.target.value)}
    />
   </div>
   <Toolbar>
    <Button
     size="small"
     disabled={!ready}
     onClick={() =>
      importCa.mutate(
       { cert_pem: certPem.trim() + "\n", key_pem: keyPem.trim() + "\n" },
       {
        onSuccess: (next) => {
         // Clear the key from the form as soon as the server has it. It is still in the
         // browser's memory until this component unmounts, which is not something a text
         // field can fix, but leaving it on screen after it has served its purpose is
         // avoidable and so it is avoided.
         setKeyPem("");
         setCertPem("");
         toast.success(
          next.persisted
           ? `Now signing as ${next.subject}. Re-download the certificate and trust it.`
           : `Now signing as ${next.subject}, for this run only — it was not saved: ${next.persist_error}`,
         );
        },
        onError: (failure: unknown) =>
         toast.error(failure instanceof Error ? failure.message : "CA import refused"),
       },
      )
     }
    >
     {importCa.isPending ? "Importing…" : "Import CA"}
    </Button>
    <Button
     size="small"
     variant="outline"
     disabled={!s?.configured || regenerateCa.isPending}
     onClick={() => setConfirmRegen(true)}
    >
     <RotateCcw size={13} />
     {regenerateCa.isPending ? "Regenerating…" : "Regenerate CA"}
    </Button>
    {s?.configured && !s.persisted && s.persist_error ? (
     <Badge tone="warn">not saved to disk</Badge>
    ) : null}
   </Toolbar>
   <p className="field-hint">
    The pair is validated before anything is replaced, so a certificate that is not a CA, a key
    that does not match it, or an expired pair is refused and the current CA keeps signing.
    On success every previously issued per-host certificate is discarded and{" "}
    <strong>every client trusting the old CA must be given the new one</strong> — the previous
    certificate signs nothing from that moment.
   </p>
   <p className="field-hint">
    <strong>Regenerate CA</strong> mints a fresh CA here instead of pasting one — Burp&apos;s
    &ldquo;Regenerate CA certificate&rdquo;. It replaces the current CA immediately and cannot be
    undone; the previous CA and its key are discarded, so every client that trusted it must be given
    the new certificate.
   </p>
   <Modal
    open={confirmRegen}
    onOpenChange={setConfirmRegen}
    title="Regenerate the CA certificate?"
    description="A brand-new CA replaces the current one immediately. The previous certificate stops signing, every per-host certificate is discarded, and the old key is thrown away. Every client that trusted the old CA must be given the new certificate before it can be intercepted again. This cannot be undone."
   >
    <div className="page-actions">
     <Button variant="outline" onClick={() => setConfirmRegen(false)}>
      Cancel
     </Button>
     <Button
      variant="danger"
      disabled={regenerateCa.isPending}
      onClick={() =>
       regenerateCa.mutate(undefined, {
        onSuccess: (next) => {
         setConfirmRegen(false);
         toast.success(
          next.persisted
           ? `A new CA is signing as ${next.subject}. Re-download the certificate and re-trust it in every client — the old one signs nothing now.`
           : `A new CA is signing as ${next.subject}, for this run only — it was not saved: ${next.persist_error}. Re-download and re-trust it.`,
         );
        },
        onError: (failure: unknown) =>
         toast.error(failure instanceof Error ? failure.message : "CA regeneration failed"),
       })
      }
     >
      <RotateCcw size={13} />
      Regenerate CA
     </Button>
    </div>
   </Modal>
  </Card>
 );
}

/**
 * Burp's CA dialog exports (burpsy-react-ui-j92x): the certificate, the private key, or both as a
 * password-protected PKCS#12 keystore — the way to point another tool (ZAP, a scanner, a mobile
 * proxy) at the CA burpsy is already intercepting with.
 *
 * Every export goes through the confirmation gate (lib/ca-export.ts). The certificate is public, so
 * its button is the confirmation; the key and the keystore each open a dialog that says what the key
 * lets its holder do before anything is minted. The password lives in this component only while the
 * dialog is open and is dropped on close, success or failure; the mutation that carried it is reset
 * when the call settles and is not kept by the cache (useExportCa's gcTime 0); the exported bytes are
 * never in state.
 */
function CaExportPanel({ available }: { available: boolean }): JSX.Element {
 const exportCa = useExportCa();
 const [asking, setAsking] = useState<"key" | "pkcs12" | null>(null);
 const [password, setPassword] = useState("");
 const [again, setAgain] = useState("");
 const [refusal, setRefusal] = useState("");

 const dismiss = () => {
  setAsking(null);
  setPassword("");
  setAgain("");
 };

 const run = (kind: CaExportKind) => {
  setRefusal("");
  exportCa.mutate(kind === "pkcs12" ? { kind, password } : { kind }, {
   onSuccess: ({ filename, bytes }) => {
    toast.success(`Exported ${filename} (${formatBytes(bytes)})`);
    dismiss();
   },
   onError: (failure) => {
    setRefusal(failure.message);
    if (kind !== "pkcs12") setAsking(null);
   },
   // Drop the mutation's copy of the variables (the PKCS#12 password) once the call is over.
   onSettled: () => exportCa.reset(),
  });
 };

 const mismatch = asking === "pkcs12" && again !== "" && password !== again;
 const pkcs12Ready = password !== "" && password === again;

 return (
  <div className="stack">
   <strong>Export</strong>
   <Toolbar>
    <Button size="small" variant="outline" disabled={!available || exportCa.isPending} onClick={() => run("cert")}>
     <Download size={14} aria-hidden="true" />
     Export certificate (PEM)
    </Button>
    <Button
     size="small"
     variant="outline"
     disabled={!available || exportCa.isPending}
     onClick={() => {
      setRefusal("");
      setAsking("key");
     }}
    >
     <KeyRound size={14} aria-hidden="true" />
     Export private key…
    </Button>
    <Button
     size="small"
     variant="outline"
     disabled={!available || exportCa.isPending}
     onClick={() => {
      setRefusal("");
      setAsking("pkcs12");
     }}
    >
     <KeyRound size={14} aria-hidden="true" />
     Export PKCS#12…
    </Button>
   </Toolbar>
   {refusal && asking === null ? <ErrorNotice title="The CA was not exported" error={refusal} /> : null}
   <p className="field-hint">
    {available
     ? "For another tool that has to agree with burpsy about what is intercepted. The certificate is public; the private key and the PKCS#12 keystore are not — each asks first. burpsy logs that an export happened (its kind and the CA's subject), never what was exported."
     : "Nothing to export: TLS interception is off, so there is no signing CA. Start burpsy with -intercept-tls."}
   </p>

   <Modal
    open={asking !== null}
    onOpenChange={(next) => {
     if (!next) dismiss();
    }}
    title={asking === "pkcs12" ? "Export the CA as PKCS#12?" : "Export the CA private key?"}
    description="Whoever holds this key can mint a certificate, for any site, that every browser and device trusting burpsy's CA will accept without a warning — and so read and change their TLS traffic. A copy cannot be taken back: if one is lost, regenerate the CA and re-trust the new one everywhere."
   >
    <form
     className="stack"
     onSubmit={(event) => {
      event.preventDefault();
      if (asking === "key") run("key");
      else if (asking === "pkcs12" && pkcs12Ready) run("pkcs12");
     }}
    >
     {asking === "pkcs12" ? (
      <>
       <Field label="Keystore password" hint="Required: a keystore without one opens for anyone who has the file.">
        {(id) => (
         <Input
          id={id}
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
         />
        )}
       </Field>
       <Field label="Repeat the password">
        {(id) => (
         <Input
          id={id}
          type="password"
          autoComplete="new-password"
          aria-invalid={mismatch || undefined}
          value={again}
          onChange={(event) => setAgain(event.target.value)}
         />
        )}
       </Field>
       {mismatch ? (
        <p className="field-hint" role="alert">
         The two passwords differ.
        </p>
       ) : null}
      </>
     ) : (
      <p className="field-hint">The key is downloaded as burpsy-ca.key — a PKCS#8 PEM file with no password on it.</p>
     )}
     {refusal ? <ErrorNotice title="The CA was not exported" error={refusal} /> : null}
     <div className="page-actions">
      <Button variant="outline" autoFocus disabled={exportCa.isPending} onClick={dismiss}>
       Cancel
      </Button>
      <Button
       type="submit"
       variant="danger"
       disabled={exportCa.isPending || (asking === "pkcs12" && !pkcs12Ready)}
      >
       <KeyRound size={14} aria-hidden="true" />
       {exportCa.isPending ? "Exporting…" : asking === "pkcs12" ? "Export PKCS#12" : "Export private key"}
      </Button>
     </div>
    </form>
   </Modal>
  </div>
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
   <CaExportPanel available={data?.available ?? false} />
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

/**
 * Upstream proxy servers and SOCKS (Unit 9) — Burp's two Network panels as one list.
 *
 * The two notices at the top are the point of the section, not decoration. `attached`
 * names the egress surfaces actually holding the policy, because "will this rule
 * apply?" is not answerable from the rule itself: a build wired for senders but not
 * for the proxy listener would otherwise look global and cover half the traffic.
 * `persisted` says whether an edit outlives the process, which matters for a panel
 * whose changes would otherwise silently be for this run only.
 */
function UpstreamProxySection(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useNetworkProxy();
 const save = useSaveNetworkProxy();
 const remove = useRemoveNetworkProxyRule();
 const clear = useClearNetworkProxy();
 const [pattern, setPattern] = useState("");
 const [proxy, setProxy] = useState("");
 const [defaultProxy, setDefaultProxy] = useState("");
 const [confirmClear, setConfirmClear] = useState(false);

 const fail = (failure: unknown, fallback: string) =>
  toast.error(failure instanceof Error ? failure.message : fallback);

 const addRule = () => {
  const host = pattern.trim();
  if (!host || !proxy.trim()) {
   toast.error("A rule needs a host pattern and a proxy URL");
   return;
  }
  save.mutate(
   { pattern: host, proxy: proxy.trim() },
   {
    onSuccess: () => {
     toast.success(`${host} routed through ${proxy.trim()}`);
     setPattern("");
     setProxy("");
    },
    // The server refuses an unparseable URL rather than storing a rule that would fail at dial
    // time, so its message is the useful one and is shown verbatim.
    onError: (failure: unknown) => fail(failure, "The proxy URL was refused"),
   },
  );
 };

 const saveDefault = () => {
  const value = defaultProxy.trim();
  save.mutate(
   { default: value },
   {
    onSuccess: () => {
     toast.success(value ? `Default upstream proxy set to ${value}` : "Default upstream proxy cleared");
     setDefaultProxy("");
    },
    onError: (failure: unknown) => fail(failure, "The default proxy URL was refused"),
   },
  );
 };

 const busy = save.isPending || remove.isPending || clear.isPending;

 // The carrier draft, adopted from the server's own view rather than from a local default, so what
 // the panel shows before a save is what is in force — and so a setting another tab changed appears
 // here without a reload.
 const [carrierDraft, setCarrierDraft] = useState({ socks: "", bypass: [] as string[], remote_resolve: false });
 useEffect(() => {
  if (!data) return;
  setCarrierDraft({
   socks: data.carrier.socks,
   // Null, not [], when the hop has no bypass list: the server marshals a nil Go slice as null
   // (NetworkCarrierView declares string[] | null for exactly this reason). Adopted unguarded, this
   // put null in the draft and the next `.join` on it killed the whole Settings page behind the
   // error boundary (burpsy-react-ui-2qbi). The draft holds string[] because the editor round-trips
   // through text, so the null is normalised here, at the boundary.
   bypass: data.carrier.bypass ?? [],
   remote_resolve: data.carrier.remote_resolve,
  });
 }, [data]);

 return (
  <Card>
   <SectionHeading
    title="Upstream proxy and SOCKS"
    detail="Where this tool's traffic goes on its way out. Ordered rules, first match wins; the default carries whatever no rule matched."
    actions={
     <>
      {data ? (
       <Badge tone={data.empty ? "neutral" : "info"}>{data.empty ? "no proxy configured" : "proxying"}</Badge>
      ) : null}
      <Button
       variant="outline"
       size="small"
       onClick={() => setConfirmClear(true)}
       disabled={!data || data.empty || busy}
      >
       <Trash2 size={13} />
       Clear all
      </Button>
      <RefreshButton onClick={() => void refetch()} loading={isFetching} />
     </>
    }
   />
   {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   {isLoading ? <LoadingPanel label="Loading upstream proxy policy" /> : null}

   {data && !data.wired ? (
    <div className="notice notice-warn">
     <span>
      No upstream proxy policy is wired into this process, so a rule saved here would be consulted by
      nothing. Start burpsy with <code>-upstream-proxy</code> or <code>-upstream-proxy-rule</code> to
      enable it.
     </span>
    </div>
   ) : null}

   {data?.wired ? (
    <>
     <div className="notice">
      <span>
       {data.attached.length
        ? `These rules reach: ${data.attached.join(", ")}.`
        : "No egress surface holds this policy, so these rules currently reach nothing."}{" "}
       {data.persisted
        ? "Edits are mirrored to the database and survive a restart."
        : "Edits apply to this run only — start with -db to persist them."}
      </span>
     </div>
     <p className="field-hint">
      Accepted schemes: {data.schemes.join(", ")}. A bare host:port is refused rather than assumed to be
      HTTP. Credentials go in the URL as <code>user:pass@host:port</code> and are never shown or served
      back — a rule with them set is marked below. <code>socks4://</code> has no password field on the
      wire, so a password with it is refused rather than dropped.
     </p>
    </>
   ) : null}

   {data?.wired ? (
    <Toolbar>
     <Field label="Default upstream proxy" hint="Carries every destination no rule below matches. Empty or “direct” clears it.">
      {(id) => (
       <Input
        id={id}
        value={defaultProxy}
        placeholder={data.default === "direct" ? "direct" : data.default}
        onChange={(event) => setDefaultProxy(event.target.value)}
        onKeyDown={(event) => {
         if (event.key === "Enter") saveDefault();
        }}
       />
      )}
     </Field>
     <Button variant="outline" onClick={saveDefault} disabled={busy}>
      Set default
     </Button>
     <Badge tone={data.default === "direct" ? "neutral" : "info"}>
      now: {data.default}
      {data.default_has_credentials ? " (authenticated)" : ""}
     </Badge>
    </Toolbar>
   ) : null}

   {data?.wired ? (
    <Toolbar>
     <Field label="Host pattern" hint="api.example.com, *.example.com, or * for everything.">
      {(id) => (
       <Input
        id={id}
        value={pattern}
        placeholder="*.internal.example.com"
        onChange={(event) => setPattern(event.target.value)}
       />
      )}
     </Field>
     <Field label="Proxy URL" hint="Use “direct” to exempt this pattern from the default.">
      {(id) => (
       <Input
        id={id}
        value={proxy}
        placeholder="socks5://127.0.0.1:1080"
        onChange={(event) => setProxy(event.target.value)}
        onKeyDown={(event) => {
         if (event.key === "Enter") addRule();
        }}
       />
      )}
     </Field>
     <NeedsValueButton
      onClick={addRule}
      disabled={busy}
      missing={!pattern.trim() ? "needs a host pattern" : !proxy.trim() ? "needs a proxy URL" : null}
     >
      <Plus size={13} />
      Add rule
     </NeedsValueButton>
    </Toolbar>
   ) : null}

   {data?.wired && data.rules.length === 0 ? (
    <Empty
     title="No per-destination rules"
     detail="Every destination takes the default above. Add a rule to send one host somewhere else, or “direct” to keep one off the default."
    />
   ) : null}
   {data && data.rules.length > 0 ? (
    <SimpleTable headers={["Host pattern", "Upstream proxy", "Protocol", "Auth", ""]}>
     {data.rules.map((rule) => (
      <tr key={rule.pattern}>
       <td>
        <code>{rule.pattern}</code>
       </td>
       <td>
        <code>{rule.proxy}</code>
       </td>
       <td>
        <Badge tone={rule.direct ? "neutral" : "info"}>{rule.kind}</Badge>
       </td>
       <td>
        <span className="cell-dim">{rule.has_credentials ? "credentials set" : "—"}</span>
       </td>
       <td>
        <IconButton
         label={`Remove the upstream proxy rule for ${rule.pattern}`}
         size="small"
         disabled={busy}
         onClick={() =>
          remove.mutate(rule.pattern, {
           onSuccess: () => toast.success(`Removed the rule for ${rule.pattern}`),
           onError: (failure: unknown) => fail(failure, "The rule could not be removed"),
          })
         }
        >
         <Trash2 size={13} />
        </IconButton>
       </td>
      </tr>
     ))}
    </SimpleTable>
   ) : null}

   {/*
    The global SOCKS layer, below the rules and above the modal. The order is the meaning: a rule
    answers "which proxy carries this host" and the carrier answers "what opens the socket to reach
    that proxy", so the layer that sits UNDERNEATH them is listed after them. A panel that showed the
    rules and not this would let an operator conclude their HTTP proxy is reachable from anywhere
    (burpsy-react-ui-mr83 part 3).
   */}
   <h3 className="subheading">Global SOCKS carrier</h3>
   <div className="notice">
    <span>
     A TCP layer under every connection this tool opens, including the connections to an upstream proxy
     above — so an HTTP proxy that is itself only reachable through a SOCKS hop works without giving
     up the proxy. Hosts you list below skip it.{" "}
     <code>remote DNS</code> asks the SOCKS server to resolve names, which is what makes an
     internal-only hostname reachable through it; it is refused for an HTTP hop, where it would
     otherwise be silently ignored.
    </span>
   </div>
   <Toolbar>
    <Field label="SOCKS proxy" hint="Blank means no carrier">
     {(id) => (
      <Input
       id={id}
       value={carrierDraft.socks}
       onChange={(event) => setCarrierDraft((d) => ({ ...d, socks: event.target.value }))}
       placeholder="socks5://127.0.0.1:1080"
       style={{ maxWidth: "var(--w-lg)" }}
      />
     )}
    </Field>
    <Field label="Bypass hosts" hint="Comma separated; *.example.com">
     {(id) => (
      <Input
       id={id}
       value={carrierDraft.bypass.join(", ")}
       onChange={(event) =>
        setCarrierDraft((d) => ({
         ...d,
         bypass: event.target.value
          .split(",")
          .map((entry) => entry.trim())
          .filter((entry) => entry !== ""),
        }))
       }
       placeholder="intranet.example.test, *.internal.test"
       style={{ maxWidth: "var(--w-lg)" }}
      />
     )}
    </Field>
    <Field label="Remote DNS" htmlFor="network-carrier-remote">
     <Switch
      id="network-carrier-remote"
      label="Let the SOCKS server resolve destination names"
      checked={carrierDraft.remote_resolve}
      onCheckedChange={(checked) => setCarrierDraft((d) => ({ ...d, remote_resolve: checked }))}
     />
    </Field>
    <Button
     variant="outline"
     size="small"
     onClick={() =>
      save.mutate(
       { carrier: carrierDraft },
       {
        onSuccess: (answer) => {
         setCarrierDraft({
          socks: answer.carrier.socks,
          bypass: answer.carrier.bypass ?? [],
          remote_resolve: answer.carrier.remote_resolve,
         });
         toast.success(answer.carrier.configured ? "SOCKS carrier applied" : "SOCKS carrier cleared");
        },
        onError: (failure: unknown) => fail(failure, "The SOCKS carrier could not be applied"),
       },
      )
     }
     disabled={busy}
    >
     Apply carrier
    </Button>
   </Toolbar>
   <p className="field-hint">
    {data?.carrier.configured
     ? `Carried by ${data.carrier.attached.length || "no"} surface(s) — ${
       data.carrier.attached.join(", ") || "none, so nothing is going through it"
      }.`
     : "No carrier is installed: every connection dials directly, and any upstream proxy above is reached directly too."}
   </p>
   {(data?.carrier.limits ?? []).map((limit) => (
    <p key={limit} className="field-hint">
     <strong>Not carried:</strong> {limit}.
    </p>
   ))}

   <Modal
    open={confirmClear}
    onOpenChange={setConfirmClear}
    title="Clear every upstream proxy rule?"
    description="Every rule and the default go. Traffic then dials origins directly from both the proxy listener and this tool's own senders."
   >
    <div className="page-actions">
     <Button variant="outline" onClick={() => setConfirmClear(false)}>
      Cancel
     </Button>
     <Button
      variant="danger"
      onClick={() => {
       clear.mutate(undefined, {
        onSuccess: () => toast.success("Upstream proxy policy cleared"),
        onError: (failure: unknown) => fail(failure, "The policy could not be cleared"),
       });
       setConfirmClear(false);
      }}
     >
      <Trash2 size={13} />
      Clear all
     </Button>
    </div>
   </Modal>
  </Card>
 );
}

/**
 * Which component renders each section in SETTINGS_SECTIONS.
 *
 * Typed as a total map over the section ids, so adding a row to SETTINGS_SECTIONS without
 * a component here — or removing a component that the nav and the palette still offer —
 * is a typecheck failure rather than a dead nav entry an operator discovers by clicking it.
 * That, not the runtime test, is what makes the one-list rule hold.
 */
/**
 * The Suite-level settings (burpsy-react-ui-fyua). Burp's Settings opens on a "Suite" category with
 * Performance, Startup, Shutdown, Temporary files, Updates and Early adopter; burpsy had none of them
 * as a section, so their absence read as "burpsy cannot do this" rather than "not built" or "lives on
 * a flag". This section names each: the two that are real (startup interception, which is configured
 * under Proxy; and asking before the console closes), where burpsy keeps its state on disk, and the
 * four that are declined, each with the reason — the same honesty the rest of this page already
 * applies to the settings it cannot offer.
 */
function SuiteSection(): JSX.Element {
 const ca = useCaStatus();
 const confirmOnClose = useApp((state) => state.confirmOnClose);
 const setConfirmOnClose = useApp((state) => state.setConfirmOnClose);
 return (
  <Card>
   <SectionHeading
    title="Suite"
    detail="Startup behaviour, where burpsy keeps its state on disk, and the suite-level settings Burp exposes."
   />

   <div className="stack">
    <div>
     <h3>Startup</h3>
     <p className="field-hint">
      Whether Proxy interception is on when the server starts is Burp's one built startup setting
      (enable_proxy_interception_at_startup). It lives with the rest of the Proxy controls.
     </p>
     <Button variant="outline" size="small" onClick={() => requestSettingsSection("proxy")}>
      Open it under Proxy settings
     </Button>
    </div>

    <div>
     <h3>Ask before closing</h3>
     <Switch
      id="suite-confirm-on-close"
      label="Ask before the console tab closes or reloads"
      checked={confirmOnClose}
      onCheckedChange={(on) => {
       setConfirmOnClose(on);
       toast.success(on ? "The browser will ask before you close or reload the console" : "Closing the console no longer prompts");
      }}
     />
     <p className="field-hint">
      Burp's "Suppress confirmation on close", inverted to an opt-in. Off by default — a proxy console is
      not a document with unsaved edits. The browser shows its own generic prompt; it cannot be styled.
     </p>
    </div>

    <div>
     <h3>Where burpsy keeps its state</h3>
     {ca.data?.directory ? (
      <p className="field-hint">
       The signing CA is stored in <code>{ca.data.directory}</code>. Relocating it is a restart-time choice
       (<code>-ca-dir</code>), not a runtime one: the live engine has already loaded the CA from here, so moving
       it under the running process would desync the two — Burp's temporary-files relocation needs a restart for
       the same reason.
      </p>
     ) : (
      <p className="field-hint">
       {ca.data?.configured
        ? "The signing CA is held for this process only (no -ca-dir is set), so a restart returns to the previous one. Start burpsy with -ca-dir to persist it to a directory."
        : "TLS interception is off, so there is no signing CA on disk. The project database (-db) is burpsy's other on-disk state."}
      </p>
     )}
    </div>

    <div>
     <h3>Not built yet</h3>
     <div className="notice notice-warn">
      Four of Burp's Suite settings have no counterpart here, and are named rather than silently absent:
      <ul style={{ margin: "var(--s1) 0 0", paddingLeft: "1.2em" }}>
       <li>
        <strong>Performance feedback</strong> — Burp tunes a desktop JVM's thread and memory budgets; burpsy's
        concurrency is bounded per-run by resource pools (see Resource pools), not by a global suite dial.
       </li>
       <li>
        <strong>Startup tuning</strong> (beyond interception) — Burp restores a saved project and window layout
        at launch; burpsy is a server started against one <code>-db</code>, so there is no project picker or
        layout to restore.
       </li>
       <li>
        <strong>Automatic updates</strong> — burpsy ships as a single binary with no in-process updater; updating
        is replacing the binary, which an in-app toggle would misrepresent as something the process does.
       </li>
       <li>
        <strong>Early adopter channel</strong> — there is one build, not a stable/early split, so a channel
        selector would choose between options that do not exist.
       </li>
      </ul>
     </div>
    </div>
   </div>
  </Card>
 );
}

// The risk classes the Go manifest assigns, least to most powerful, each with the server's own one-
// line definition (route_manifest.go) and a tone. The order is the reading order of "how much can
// this do", so the page descends from static assets to the irreversible.
const RISK_LEGEND: { id: string; label: string; tone: Tone; blurb: string }[] = [
 { id: "riskAsset", label: "Asset", tone: "neutral", blurb: "Serves a static asset — the console itself, the CA certificate." },
 { id: "riskRead", label: "Read", tone: "neutral", blurb: "Reads state and sends nothing outbound." },
 { id: "riskLocal", label: "Local write", tone: "info", blurb: "Changes burpsy's own state — annotations, rules, settings — without sending traffic." },
 { id: "riskEgress", label: "Egress", tone: "info", blurb: "Sends a bounded amount of traffic to the target: one request, or a handful." },
 { id: "riskExecute", label: "Execute", tone: "warn", blurb: "Runs operator-supplied code in this process's privileges — starts a plugin or a script." },
 { id: "riskScope", label: "Scope", tone: "warn", blurb: "Changes what the engagement is allowed to touch — it removes the thing that says no." },
 { id: "riskCredential", label: "Credential", tone: "warn", blurb: "Reads or replays credentials — the cookie jar, session macros." },
 { id: "riskAttack", label: "Attack", tone: "bad", blurb: "Sends unbounded traffic: an attack, an audit, a crawl, a capture." },
 { id: "riskDestructive", label: "Destructive", tone: "bad", blurb: "Irreversibly discards evidence." },
];

/**
 * The REST-API surface (burpsy-react-ui-wt0r). Burp's REST API is a 12-key settings page; burpsy IS a
 * JSON API of ~150 routes, and nothing described, classified, or located it. This renders that
 * inventory from the same manifest route_manifest_test.go asserts against (src/lib/route-risk.ts,
 * generated and drift-checked), grouped by the risk class the server assigns, and shows where the
 * console is bound so an operator can see what is reachable over the network. Read-only; no backend.
 */
function RestApiSection(): JSX.Element {
 const stats = useStats();
 const webBind = stats.data?.web_bind;
 const total = Object.keys(ROUTE_RISK).length;

 // Group patterns by class, and derive which classes are confirmation-gated from the generated gate
 // table, so the "confirm-gated" marks here cannot drift from what the client actually enforces.
 const byClass = new Map<string, string[]>();
 const gatedClasses = new Set<string>();
 for (const [pattern, risk] of Object.entries(ROUTE_RISK)) {
  (byClass.get(risk) ?? byClass.set(risk, []).get(risk)!).push(pattern);
  if (ROUTE_GATED[pattern]) gatedClasses.add(risk);
 }

 // A loopback bind is reachable only from this machine; anything else is reachable from the network,
 // which is the fact an operator most needs to see next to a surface this large.
 const loopback = webBind ? /^(127\.|\[?::1\]?|localhost)/.test(webBind) : false;

 // Render every class the manifest actually uses, not only the ones the legend names: a risk class
 // added in Go must not drop its routes off this page silently. Known classes keep their order and
 // blurb; an unknown one falls to the end with a neutral badge and no blurb until the legend learns it.
 const known = new Set(RISK_LEGEND.map((c) => c.id));
 const extra: { id: string; label: string; tone: Tone; blurb: string }[] = [...byClass.keys()]
  .filter((id) => !known.has(id))
  .sort()
  .map((id) => ({ id, label: id.replace(/^risk/, ""), tone: "neutral" as Tone, blurb: "" }));
 const classes = [...RISK_LEGEND, ...extra];

 return (
  <Card>
   <SectionHeading
    title="REST API"
    detail="Every HTTP route this console exposes, classified by what it can do. Read from the server's own route manifest, so it cannot drift from the routes."
   />
   <p className="field-hint">
    This console is a JSON API of <strong>{total}</strong> routes
    {webBind ? (
     <>
      , bound at <code>{webBind}</code> —{" "}
      {loopback
       ? "loopback only, reachable from this machine."
       : "reachable from the network: anything that can route to this address can call these routes, subject to the confirmation gate below."}
     </>
    ) : (
     ". The bind address is unknown to this view."
    )}
   </p>
   <div className="stack">
    {classes.map((cls) => {
     const patterns = (byClass.get(cls.id) ?? []).sort();
     if (patterns.length === 0) return null;
     const gated = gatedClasses.has(cls.id);
     return (
      <details key={cls.id}>
       <summary style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: "var(--gap-sm)", flexWrap: "wrap" }}>
        <Badge tone={cls.tone}>{cls.label}</Badge>
        <span className="cell-dim">{patterns.length} route{patterns.length === 1 ? "" : "s"}</span>
        {gated ? <Badge tone="accent">confirm-gated</Badge> : null}
        <span>{cls.blurb}</span>
       </summary>
       <ul style={{ margin: "var(--gap-sm) 0 0", paddingLeft: "var(--gap-lg)" }}>
        {patterns.map((pattern) => (
         <li key={pattern}>
          <code>{pattern}</code>
         </li>
        ))}
       </ul>
      </details>
     );
    })}
   </div>
   <p className="field-hint">
    A <strong>confirm-gated</strong> class cannot be mutated without a one-time confirmation token the
    console mints — the same gate that stops an unattended caller from launching an attack or discarding
    evidence by surprise. Reads are never gated. Bind the console to loopback (the <code>-web</code>
    flag) to keep this surface off the network entirely.
   </p>
  </Card>
 );
}

const SECTION_COMPONENTS: Record<SettingsSectionId, () => JSX.Element> = {
 proxy: ProxySettingsSection,
 suite: SuiteSection,
 "rest-api": RestApiSection,
 "resource-pools": ResourcePoolsSection,
 "scheduled-tasks": ScheduledTasksSection,
 protocols: ProtocolSection,
 network: NetworkSection,
 scanner: ScannerSettingsSection,
 "llm-triage": LlmTriageSection,
 skills: SkillsSection,
 "browser-engine": DomEngineSection,
 browser: BrowserSection,
 "upstream-proxy": UpstreamProxySection,
 "platform-auth": PlatformAuthSection,
 "client-certificates": ClientCertificatesSection,
 "server-certificates": ServerCertificatesSection,
 logging: FileLoggingSection,
 appearance: AppearanceSection,
 hotkeys: HotkeysSection,
 certificate: CertificateSection,
 "ca-import": CaImportSection,
 "message-editor": MessageEditorSection,
 "uninteresting-headers": UninterestingHeadersSection,
 "project-backup": ProjectBackupSection,
 diagnostics: DiagnosticsSection,
};

/**
 * The smallest element inside a card that still contains every word of the search.
 *
 * Scrolling a matching *card* to the top is not finding the setting: type "redirect" and
 * Network's heading lands at the top with the Redirections control below the fold, which is
 * the same "somewhere on this page" answer the operator already had. So the page descends
 * from the card into the deepest single element that still matches, which for a field is its
 * label-and-control row, and shows that.
 *
 * Deepest rather than first: an ancestor always contains its descendants' text, so the
 * outermost match is invariably the card itself. The descent stops when no single child
 * carries the whole term — which is the right place to stop, because that is where the words
 * are split across two siblings (a label and its hint) and the pair is what should be shown.
 *
 * The card's own heading is skipped. A word in the title or the standfirst is why the *card*
 * matched, not which setting did: searching "redirect" first landed on Network's one-line
 * description, which says "redirections" and is no more useful than the heading itself. With
 * the heading out of the way the descent reaches the Redirections control, and a term that
 * matches nothing but the heading returns the card — which then scrolls to its top, saying
 * plainly that the section matched and no single field did.
 */
function deepestMatch(card: HTMLElement, term: string): HTMLElement {
 let node: HTMLElement = card;
 for (;;) {
  const child = [...node.children].find(
   (candidate): candidate is HTMLElement =>
    candidate instanceof HTMLElement &&
    !candidate.hidden &&
    !candidate.classList.contains("section-heading") &&
    matchesAllWords(candidate.textContent ?? "", term),
  );
  if (!child) return node;
  node = child;
 }
}

/** How long a found control stays outlined. Long enough to see it land, short enough not to become chrome. */
const HIT_FLASH_MS = 1600;

/**
 * Settings: seventeen cards, a rail to reach them, and a search that reads what they render.
 *
 * Burp's Settings is a dialog with a left tree and a Search box; this page was the same
 * seventeen cards on one scroll with no way to jump or find (burpsy-react-ui-f6a). The rail
 * and the search both render from lib/settings-sections.ts, which the command palette also
 * reads, so the three can never disagree about what a section is.
 *
 * Two deliberate choices about the filter. Non-matching sections are **hidden, not
 * unmounted**: unmounting would throw away each card's loaded data and its unsaved edits
 * (Network holds a dirty draft), and it would also destroy the rendered text the search
 * reads. And the search reads that rendered text rather than a transcribed list of field
 * names, so a field added to a card is findable the day it is added, without anyone
 * remembering to index it.
 *
 * Burp's All/User/Project filter buttons are deliberately not here: burpsy has no
 * project-file concept, so every setting on this page would answer to the same button and
 * the other two would be empty. Filing that as its own gap is honest; drawing three buttons
 * where one distinction exists is not.
 */
export function SettingsPage(): JSX.Element {
 const [term, setTerm] = useState("");
 const [visible, setVisible] = useState<SettingsSection[]>(() => [...SETTINGS_SECTIONS]);
 const [active, setActive] = useState<string>(SETTINGS_SECTIONS[0].id);
 const pageRef = useRef<HTMLDivElement>(null);

 // The filter runs in an effect, not in a memo, because it reads the DOM: it asks each card
 // what it currently prints. Every card stays mounted, so the text of a hidden one is still
 // there to be searched — which is what lets a term bring a section back.
 useEffect(() => {
  setVisible(
   filterSettingsSections(
    term,
    (section) => document.getElementById(settingsSectionAnchor(section.id))?.textContent ?? "",
   ),
  );
 }, [term]);

 /**
  * Scroll a section to the top of the page, and keep it there while the page settles.
  *
  * A jump is not one scroll. Every card fetches its own data, so the page grows *under* the
  * jump — driving the live console, the palette's "Settings › Network" landed 841px short,
  * because Proxy and Resource pools filled in above Network after the scroll had already
  * happened. So this is a scroll followed by a short correction window that re-aligns the
  * target as cards arrive, and any deliberate move by the operator ends the window early: a
  * page that keeps yanking itself back under someone who has started reading is worse than
  * one that landed short.
  */
 const jumpTo = useCallback((id: string, match?: string) => {
  const anchor = settingsSectionAnchor(id);
  // Next frame, so this also works for a jump requested before the target was rendered:
  // the command palette navigates here from another tool and asks for a section in the
  // same tick, and the card does not exist until React has painted.
  requestAnimationFrame(() => {
   const container = pageRef.current;
   const card = document.getElementById(anchor);
   if (!container || !card) return;
   // Focus moves with the scroll, or a keyboard user lands nowhere: the viewport would
   // show the section while Tab continued from the rail button they just pressed. Focus goes
   // to the card even when the search found a control inside it, because the card is what
   // carries the accessible name — "Network", not an anonymous row.
   card.focus({ preventScroll: true });

   // With a term, land on the control that matched rather than on the card's heading, and
   // outline it briefly so it is obvious which of a card's dozen fields answered the search.
   const target = match?.trim() ? deepestMatch(card, match) : card;
   const centred = target !== card;
   for (const stale of document.querySelectorAll("[data-settings-hit]")) stale.removeAttribute("data-settings-hit");
   if (centred) {
    target.setAttribute("data-settings-hit", "true");
    window.setTimeout(() => target.removeAttribute("data-settings-hit"), HIT_FLASH_MS);
   }

   // Smooth scrolling is motion, and this one crosses most of the page. An operator who has
   // asked the system for reduced motion gets the jump instantly instead.
   const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
   // The settings pane is scrolled, and only it: scrollIntoView scrolls EVERY scrollable ancestor,
   // which pulled the document root up and took the menubar and tool tabs off screen (us6r.2).
   {
    const rect = target.getBoundingClientRect();
    const box = container.getBoundingClientRect();
    const want = centred ? box.top + Math.max(0, (container.clientHeight - rect.height) / 2) : box.top;
    container.scrollBy({ top: rect.top - want, behavior: reduced ? "auto" : "smooth" });
   }
   setActive(id);

   // How far the target is from where it should be: the top of the page for a whole card,
   // the middle for a single control — a field put at the top would hide the heading that
   // says which section it belongs to.
   const drift = (): number => {
    const rect = target.getBoundingClientRect();
    const box = container.getBoundingClientRect();
    const want = centred ? box.top + Math.max(0, (container.clientHeight - rect.height) / 2) : box.top;
    return rect.top - want;
   };

   const started = performance.now();
   let cancelled = false;
   const abort = () => {
    cancelled = true;
   };
   const gestures = ["wheel", "touchstart", "keydown", "pointerdown"] as const;
   for (const type of gestures) window.addEventListener(type, abort, { passive: true });
   const release = () => {
    for (const type of gestures) window.removeEventListener(type, abort);
   };
   const settle = () => {
    const now = performance.now();
    if (cancelled || !target.isConnected || now - started > 2000) {
     release();
     return;
    }
    // Corrections wait out the smooth scroll rather than interrupting it, and ignore the
    // pixel or two of resting error an animation leaves behind.
    const off = drift();
    if (now - started > 450 && Math.abs(off) > 8) container.scrollTop += off;
    requestAnimationFrame(settle);
   };
   requestAnimationFrame(settle);
  });
 }, []);

 // A request from the command palette. Two paths because there are two cases: arriving from
 // another tool (the pending id, read once on mount) and a palette fired while this page is
 // already open (the event, where nothing mounts). The search is cleared first — a palette
 // entry that lands on a section a stale filter is hiding would look broken.
 useEffect(() => {
  const open = (id: string) => {
   setTerm("");
   jumpTo(id);
  };
  const pending = takePendingSettingsSection();
  if (pending) open(pending);
  return onSettingsSectionRequest((id) => {
   takePendingSettingsSection();
   open(id);
  });
 }, [jumpTo]);

 // Which section the rail marks as current. `.page` is the scrolling element (it carries
 // overflow-y), so positions are measured against its box rather than the viewport's, and
 // the last card whose top has passed it wins — the one the operator is reading.
 useEffect(() => {
  const container = pageRef.current;
  if (!container) return;
  let frame = 0;
  const update = () => {
   frame = 0;
   // At the bottom of the scroll there is no more travel, so the last sections never reach the
   // top and a "which heading has passed the top" rule would mark the wrong one — jumping to
   // Diagnostics, the last card, left the rail pointing at Uninteresting headers. When the
   // container is scrolled out, the last section on screen is the one being read.
   if (container.scrollTop + container.clientHeight >= container.scrollHeight - 4) {
    const last = visible[visible.length - 1];
    if (last) {
     setActive(last.id);
     return;
    }
   }
   const top = container.getBoundingClientRect().top;
   let current = visible[0]?.id ?? "";
   for (const section of visible) {
    const element = document.getElementById(settingsSectionAnchor(section.id));
    if (!element) continue;
    if (element.getBoundingClientRect().top - top > 24) break;
    current = section.id;
   }
   setActive(current);
  };
  const onScroll = () => {
   if (!frame) frame = requestAnimationFrame(update);
  };
  container.addEventListener("scroll", onScroll, { passive: true });
  update();
  return () => {
   container.removeEventListener("scroll", onScroll);
   if (frame) cancelAnimationFrame(frame);
  };
 }, [visible]);

 const shown = useMemo(() => new Set(visible.map((section) => section.id)), [visible]);

 return (
  <div className="page" ref={pageRef}>
   <PageHeader
    title="Settings"
    description="Protocol reporting, network credentials, appearance, the CA certificate, and the console's own diagnostics. Scope lives under Target."
   />
   <div className="settings-layout">
    <div className="settings-rail">
     <Field
      label="Search settings"
      hint="Matches a section's title and everything the section has rendered — field labels, hints and help text."
     >
      {(id) => (
       <div className="search-field">
        <Search size={15} />
        <Input
         id={id}
         value={term}
         onChange={(event) => setTerm(event.target.value)}
         onKeyDown={(event) => {
          // Enter is the "take me there" key: with a filter applied the first surviving
          // section is the answer, and scrolling to it is how a match inside a card —
          // a field label the heading never mentions — becomes visible.
          const first = visible[0];
          if (event.key === "Enter" && first) jumpTo(first.id, term);
         }}
         placeholder="tls, timeout, hotkey…"
        />
        {term ? (
         <IconButton label="Clear the settings search" size="small" onClick={() => setTerm("")}>
          <X size={13} />
         </IconButton>
        ) : null}
       </div>
      )}
     </Field>
     {/* A flat list, not a tree: these seventeen cards have no children, and inventing a
         level of grouping would be this rail's opinion rather than the page's structure.
         See lib/settings-sections.ts for the full argument. */}
     <nav className="settings-nav" aria-label="Settings sections">
      {visible.map((section) => (
       <button
        key={section.id}
        type="button"
        className={cn("settings-nav-link", active === section.id && "is-current")}
        aria-current={active === section.id ? "true" : undefined}
        onClick={() => jumpTo(section.id)}
       >
        {section.title}
       </button>
      ))}
     </nav>
     <Badge tone={term ? "info" : "neutral"}>
      {term
       ? `${visible.length} of ${SETTINGS_SECTIONS.length} sections`
       : `${SETTINGS_SECTIONS.length} sections`}
     </Badge>
    </div>

    <div className="settings-sections">
     {SETTINGS_SECTIONS.map((section) => {
      const Section = SECTION_COMPONENTS[section.id];
      return (
       // tabIndex -1 so a rail jump can put focus here; the accessible name makes the
       // landing announce which section it is instead of an anonymous group.
       <section
        key={section.id}
        id={settingsSectionAnchor(section.id)}
        className="settings-section"
        aria-label={section.title}
        tabIndex={-1}
        hidden={!shown.has(section.id)}
       >
        <Section />
       </section>
      );
     })}
     {visible.length === 0 ? (
      <Empty
       title={`No setting matches “${term}”`}
       detail="The search reads each section's title and the text it has rendered — its field labels, hints and help. A section still loading matches on less than it eventually will."
      />
     ) : null}
    </div>
   </div>
  </div>
 );
}

/**
 * Named resource pools: Burp's configPanelResourcePools.
 *
 * The panel's job beyond New/Edit/Delete is the support table. A pool is a
 * promise made here and kept three layers away in three tools, and one of them
 * cannot keep all of it — the crawl loop is sequential, so a concurrency
 * ceiling above 1 bounds nothing there. That exception is served as data by
 * GET /api/pools and rendered, so an operator who sets 8 concurrent requests
 * can see which tools will actually send 8 without reading any Go.
 */
function poolRate(pool: Pool): string {
 if (pool.delay_ms <= 0) return "no rate cap";
 const perSecond = 1000 / pool.delay_ms;
 return `${formatCount(pool.delay_ms)} ms apart (${perSecond.toFixed(perSecond < 10 ? 2 : 0)}/s)`;
}

const BLANK_POOL: Pool = { name: "", max_concurrent: 10, delay_ms: 50, throttle: { increment_ms: 50 } };

function PoolDialog({
 open,
 onOpenChange,
 editing,
 initial,
 onSubmit,
 pending,
}: {
 open: boolean;
 onOpenChange: (open: boolean) => void;
 editing: string | null;
 initial: Pool;
 onSubmit: (pool: Pool) => void;
 pending: boolean;
}): JSX.Element {
 const [name, setName] = useState(initial.name);
 const [maxConcurrent, setMaxConcurrent] = useState(String(initial.max_concurrent));
 const [delay, setDelay] = useState(String(initial.delay_ms));
 const [throttle, setThrottle] = useState(Boolean(initial.throttle));
 const [increment, setIncrement] = useState(String(initial.throttle?.increment_ms ?? 50));

 // Keyed on `initial` by the caller, so the form is remounted per pool rather
 // than syncing state in an effect. poolSchema (vlrh.1) turns the text into the Pool and refuses what
 // the server refuses — including automatic throttling over a zero delay, which works by increasing
 // the delay and so has nothing to multiply — so a bad pool is never sent to be rejected.
 const parsed = poolSchema.safeParse({ name, maxConcurrent, delay, throttle, increment });
 const problem = parsed.success ? null : (parsed.error.issues[0]?.message ?? "Check the fields");

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   title={editing ? `Edit pool ${editing}` : "New resource pool"}
   description="These limits bound every tool that names this pool, and are shared between them."
  >
   <div className="form-grid">
    <Field label="Name" hint="What a tool references. Tools name a pool by this and nothing else.">
     {(id) => <Input id={id} value={name} onChange={(event) => setName(event.target.value)} />}
    </Field>
    <Field label="Max concurrent requests" hint="At least 1. Zero would deadlock rather than throttle.">
     {(id) => (
      <Input
       id={id}
       type="number"
       min={1}
       value={maxConcurrent}
       onChange={(event) => setMaxConcurrent(event.target.value)}
      />
     )}
    </Field>
    <Field label="Delay between requests (ms)" hint="0 is no rate cap — concurrency alone bounds the tool.">
     {(id) => <Input id={id} type="number" min={0} value={delay} onChange={(event) => setDelay(event.target.value)} />}
    </Field>
    <Field label="Automatic throttling" hint="Increases the delay when the target answers 429 or 503.">
     {(id) => (
      <Switch id={id} label="Automatic throttling" checked={throttle} onCheckedChange={setThrottle} />
     )}
    </Field>
    {throttle ? (
     <Field label="Increase delay in increments of (ms)" hint="Must be above 0: a throttle that adds nothing is off.">
      {(id) => (
       <Input
        id={id}
        type="number"
        min={1}
        value={increment}
        onChange={(event) => setIncrement(event.target.value)}
       />
      )}
     </Field>
    ) : null}
   </div>
   {problem && name.trim() ? <p className="field-hint">{problem}</p> : null}
   <div className="page-actions">
    <Button variant="outline" onClick={() => onOpenChange(false)}>
     Cancel
    </Button>
    <Button
     disabled={pending || !parsed.success}
     onClick={() => {
      if (parsed.success) onSubmit(parsed.data);
     }}
    >
     {editing ? "Save pool" : "Create pool"}
    </Button>
   </div>
  </Modal>
 );
}

export function ResourcePoolsSection(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = usePools();
 const save = useSavePool();
 const update = useUpdatePool();
 const remove = useDeletePool();
 const [dialog, setDialog] = useState<{ editing: string | null; initial: Pool } | null>(null);
 const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

 const fail = (failure: unknown, fallback: string) =>
  toast.error(failure instanceof Error ? failure.message : fallback);

 const pools = data?.pools ?? [];
 const unhonoured = data?.support.filter((row) => !row.max_concurrent || !row.delay || !row.throttle) ?? [];

 return (
  <Card>
   <SectionHeading
    title="Resource pools"
    detail="Saved limits every tool can reference by name, instead of each run re-specifying its own."
    actions={
     <>
      {data ? (
       <Badge tone={data.count ? "good" : "neutral"}>
        {data.count === 1 ? "1 pool" : `${formatCount(data.count)} pools`}
       </Badge>
      ) : null}
      <Button
       variant="outline"
       size="small"
       onClick={() => setDialog({ editing: null, initial: data?.default ?? BLANK_POOL })}
      >
       <Plus size={13} />
       New pool
      </Button>
      <RefreshButton onClick={() => void refetch()} loading={isFetching} />
     </>
    }
   />
   {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   {isLoading ? <LoadingPanel label="Loading resource pools" /> : null}
   {data && pools.length === 0 ? (
    <Empty
     title="No pools are saved"
     detail="Every tool runs under its own documented default until a pool is saved and named."
    />
   ) : null}
   {pools.length ? (
    <SimpleTable headers={["Pool", "Max concurrent", "Delay between requests", "Automatic throttling", "Referenced by", ""]}>
     {pools.map((pool) => {
      const users = data?.in_use[pool.name] ?? [];
      return (
       <tr key={pool.name}>
        <td>
         <code>{pool.name}</code>
        </td>
        <td>
         <span className="cell-num">{formatCount(pool.max_concurrent)}</span>
        </td>
        <td>{poolRate(pool)}</td>
        <td>
         {pool.throttle ? (
          <Badge tone="good">+{formatCount(pool.throttle.increment_ms)} ms</Badge>
         ) : (
          <Badge tone="neutral">off</Badge>
         )}
        </td>
        <td>
         {users.length ? (
          <span title={users.join(", ")}>
           {users.length === 1 ? "1 schedule" : `${formatCount(users.length)} schedules`}
          </span>
         ) : (
          <span className="field-hint">nothing</span>
         )}
        </td>
        <td>
         <Toolbar>
          <Button
           variant="outline"
           size="small"
           onClick={() => setDialog({ editing: pool.name, initial: pool })}
          >
           Edit
          </Button>
          <IconButton
           label={`Delete pool ${pool.name}`}
           size="small"
           disabled={remove.isPending}
           onClick={() => setConfirmDelete(pool.name)}
          >
           <Trash2 size={13} />
          </IconButton>
         </Toolbar>
        </td>
       </tr>
      );
     })}
    </SimpleTable>
   ) : null}

   {data ? (
    <>
     <SectionHeading
      title="What each tool honours"
      detail={
       unhonoured.length === 0
        ? `${data.support.length === 1 ? "1 tool" : `${formatCount(data.support.length)} tools`} accept a pool, and every one enforces all three bounds.`
        : `${data.support.length === 1 ? "1 tool" : `${formatCount(data.support.length)} tools`} accept a pool; ${unhonoured.length === 1 ? "1 cannot honour" : `${formatCount(unhonoured.length)} cannot honour`
        } every bound.`
      }
     />
     <SimpleTable headers={["Tool", "Route", "Max concurrent", "Delay", "Throttling", "Why not"]}>
      {data.support.map((row) => (
       <tr key={row.route}>
        <td>{row.tool}</td>
        <td>
         <code>{row.route}</code>
        </td>
        <td>
         <Badge tone={row.max_concurrent ? "good" : "warn"}>{row.max_concurrent ? "enforced" : "no effect"}</Badge>
        </td>
        <td>
         <Badge tone={row.delay ? "good" : "warn"}>{row.delay ? "enforced" : "no effect"}</Badge>
        </td>
        <td>
         <Badge tone={row.throttle ? "good" : "warn"}>{row.throttle ? "enforced" : "no effect"}</Badge>
        </td>
        <td>{row.detail ? row.detail : <span className="field-hint">nothing is unenforced</span>}</td>
       </tr>
      ))}
     </SimpleTable>
    </>
   ) : null}

   {dialog ? (
    <PoolDialog
     key={dialog.editing ?? "new"}
     open
     onOpenChange={(open) => (open ? undefined : setDialog(null))}
     editing={dialog.editing}
     initial={dialog.initial}
     pending={save.isPending || update.isPending}
     onSubmit={(pool) => {
      const done = () => {
       toast.success(dialog.editing ? `Saved ${pool.name}` : `Created ${pool.name}`);
       setDialog(null);
      };
      if (dialog.editing) {
       update.mutate({ name: dialog.editing, pool }, { onSuccess: done, onError: (e) => fail(e, "Edit failed") });
      } else {
       save.mutate(pool, { onSuccess: done, onError: (e) => fail(e, "Create failed") });
      }
     }}
    />
   ) : null}

   <Modal
    open={confirmDelete !== null}
    onOpenChange={(open) => (open ? undefined : setConfirmDelete(null))}
    title={confirmDelete ? `Delete pool ${confirmDelete}?` : "Delete pool?"}
    description="Any tool run that named this pool will have to name another one."
   >
    <div className="page-actions">
     <Button variant="outline" onClick={() => setConfirmDelete(null)}>
      Cancel
     </Button>
     <Button
      variant="danger"
      disabled={remove.isPending}
      onClick={() => {
       const name = confirmDelete;
       if (!name) return;
       remove.mutate(name, {
        onSuccess: () => {
         toast.success(`Deleted ${name}`);
         setConfirmDelete(null);
        },
        // A pool a schedule still references is refused, and the refusal
        // names the schedules — shown as-is rather than replaced with a
        // generic failure, because the message is the fix.
        onError: (failure) => fail(failure, "Delete failed"),
       });
      }}
     >
      <Trash2 size={13} />
      Delete pool
     </Button>
    </div>
   </Modal>
  </Card>
 );
}

/**
 * Scheduled tasks: Burp's configPanelScheduledTasks and configPanelTaskAutoStart.
 *
 * Two things here are load-bearing beyond the list. First, `running`: a list of
 * armed schedules served by a process with no ticker would look armed while
 * nothing could ever fire, so that is stated rather than assumed. Second, the
 * missed-window policy, served as prose by the API — an occurrence that came
 * due while burpsy was down does not fire late, and an operator who learns
 * that from an incident learned it too late.
 */
function localDateTimeValue(ms: number): string {
 const at = new Date(ms);
 const pad = (n: number) => String(n).padStart(2, "0");
 return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}T${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

function ScheduleDialog({
 open,
 onOpenChange,
 editing,
 initial,
 kinds,
 pools,
 onSubmit,
 pending,
}: {
 open: boolean;
 onOpenChange: (open: boolean) => void;
 editing: string | null;
 initial: Schedule | null;
 kinds: string[];
 pools: string[];
 onSubmit: (schedule: Partial<Schedule>) => void;
 pending: boolean;
}): JSX.Element {
 const [name, setName] = useState(initial?.name ?? "");
 const [kind, setKind] = useState(initial?.kind ?? kinds[0] ?? "");
 const [enabled, setEnabled] = useState(initial?.enabled ?? true);
 const [first, setFirst] = useState(localDateTimeValue(initial?.first_ms ?? Date.now() + 3_600_000));
 const [repeat, setRepeat] = useState((initial?.interval_secs ?? 0) > 0);
 const [intervalHours, setIntervalHours] = useState(String((initial?.interval_secs ?? 86_400) / 3600));
 const [pool, setPool] = useState(initial?.pool ?? "");
 const intervalSecs = intervalHoursSchema.safeParse(intervalHours);
 const [params, setParams] = useState(initial?.params ? JSON.stringify(initial.params, null, 2) : "");

 // Parsed here so a malformed blob is caught before it is armed rather than at
 // the hour it was armed for.
 let paramsError = "";
 if (params.trim()) {
  try {
   JSON.parse(params);
  } catch (failure) {
   paramsError = failure instanceof Error ? failure.message : "The parameters are not valid JSON";
  }
 }
 const firstMs = first ? new Date(first).getTime() : 0;

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   title={editing ? `Edit schedule ${editing}` : "New scheduled task"}
   description="Starts registered work at a wall-clock time, or repeatedly. Editing the timing re-arms it."
  >
   <div className="form-grid">
    <Field label="Name">
     {(id) => <Input id={id} value={name} onChange={(event) => setName(event.target.value)} />}
    </Field>
    <Field label="What to start" hint="Only what this build can actually start is offered.">
     {(id) => (
      <Select id={id} value={kind} onChange={(event) => setKind(event.target.value)}>
       {kinds.map((option) => (
        <option key={option} value={option}>
         {option}
        </option>
       ))}
      </Select>
     )}
    </Field>
    <Field label="First run">
     {(id) => <Input id={id} type="datetime-local" value={first} onChange={(event) => setFirst(event.target.value)} />}
    </Field>
    <Field label="Enabled" hint="Off keeps the schedule and stops it firing.">
     {(id) => <Switch id={id} label="Enabled" checked={enabled} onCheckedChange={setEnabled} />}
    </Field>
    <Field label="Repeat" hint="Off runs it once.">
     {(id) => <Switch id={id} label="Repeat" checked={repeat} onCheckedChange={setRepeat} />}
    </Field>
    {repeat ? (
     <Field label="Every (hours)" hint="At least 1 minute; an interval shorter than a run would overlap itself.">
      {(id) => (
       <Input
        id={id}
        type="number"
        min={0.5}
        step="0.5"
        value={intervalHours}
        onChange={(event) => setIntervalHours(event.target.value)}
       />
      )}
     </Field>
    ) : null}
    <Field label="Resource pool" hint="What bounds the run. Blank leaves the tool on its own defaults.">
     {(id) => (
      <Select id={id} value={pool} onChange={(event) => setPool(event.target.value)}>
       <option value="">the tool&apos;s own defaults</option>
       {pools.map((option) => (
        <option key={option} value={option}>
         {option}
        </option>
       ))}
      </Select>
     )}
    </Field>
   </div>
   <Field
    label="Parameters (JSON)"
    hint={
     kind === "crawl"
      ? 'A crawl request, e.g. {"seeds":["https://target.test/"],"max_requests":500}'
      : kind === "backup"
       ? 'A backup request, e.g. {"dir":"/mnt/backups","retention":7}. Blank writes beside the live database and keeps 7.'
       : 'An audit request, e.g. {"exchange_id":12,"config":"thorough"}'
    }
   >
    {(id) => (
     <Textarea id={id} rows={5} value={params} onChange={(event) => setParams(event.target.value)} />
    )}
   </Field>
   {paramsError ? <p className="field-hint">{paramsError}</p> : null}
   {repeat && !intervalSecs.success ? <p className="field-hint">{intervalSecs.error.issues[0]?.message}</p> : null}
   <div className="page-actions">
    <Button variant="outline" onClick={() => onOpenChange(false)}>
     Cancel
    </Button>
    <Button
     disabled={pending || !name.trim() || !kind || !firstMs || Boolean(paramsError) || (repeat && !intervalSecs.success)}
     onClick={() =>
      onSubmit({
       name: name.trim(),
       kind,
       enabled,
       first_ms: firstMs,
       interval_secs: repeat && intervalSecs.success ? intervalSecs.data : 0,
       pool: pool || undefined,
       params: params.trim() ? JSON.parse(params) : undefined,
      })
     }
    >
     {editing ? "Save schedule" : "Create schedule"}
    </Button>
   </div>
  </Modal>
 );
}

export function ScheduledTasksSection(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useSchedules();
 const save = useSaveSchedule();
 const update = useUpdateSchedule();
 const remove = useDeleteSchedule();
 const [dialog, setDialog] = useState<{ editing: string | null; initial: Schedule | null } | null>(null);

 const fail = (failure: unknown, fallback: string) =>
  toast.error(failure instanceof Error ? failure.message : fallback);

 const schedules = data?.schedules ?? [];

 return (
  <Card>
   <SectionHeading
    title="Scheduled tasks"
    detail="Start a crawl or an audit at a wall-clock time, or on an interval. The schedule survives a restart."
    actions={
     <>
      {data ? (
       <Badge tone={data.running ? "good" : "warn"}>{data.running ? "clock running" : "clock not running"}</Badge>
      ) : null}
      {data ? (
       <Badge tone={data.count ? "good" : "neutral"}>
        {data.count === 1 ? "1 schedule" : `${formatCount(data.count)} schedules`}
       </Badge>
      ) : null}
      <Button
       variant="outline"
       size="small"
       disabled={!data || data.kinds.length === 0}
       onClick={() => setDialog({ editing: null, initial: null })}
      >
       <Plus size={13} />
       New schedule
      </Button>
      <RefreshButton onClick={() => void refetch()} loading={isFetching} />
     </>
    }
   />
   {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   {isLoading ? <LoadingPanel label="Loading scheduled tasks" /> : null}
   {data && !data.running ? (
    <p className="field-hint">
     Nothing in this process is consulting the clock, so no schedule below can fire. The scheduler starts with the
     web server.
    </p>
   ) : null}
   {data ? (
    <div className="metric-grid wide">
     <Metric label="Fired" value={formatCount(data.totals.fired)} detail="Occurrences whose work was started" />
     <Metric
      label="Failed"
      value={formatCount(data.totals.failed)}
      tone={data.totals.failed ? "bad" : "neutral"}
      detail="Of those, the starts that returned an error"
     />
     <Metric
      label="Missed"
      value={formatCount(data.totals.missed)}
      tone={data.totals.missed ? "warn" : "neutral"}
      detail="Came due while nothing was running"
     />
     <Metric
      label="Unstartable"
      value={formatCount(data.totals.unstarted)}
      tone={data.totals.unstarted ? "bad" : "neutral"}
      detail="Due for something this build cannot start"
     />
    </div>
   ) : null}
   {data && schedules.length === 0 ? (
    <Empty title="Nothing is scheduled" detail="A saved schedule starts work at a time you choose and survives a restart." />
   ) : null}
   {schedules.length ? (
    <SimpleTable headers={["Schedule", "Starts", "Next run", "Repeat", "Pool", "Runs", "Missed", "Last note", ""]}>
     {schedules.map((schedule) => (
      <tr key={schedule.name}>
       <td>
        <code>{schedule.name}</code>
        {schedule.enabled ? null : (
         <>
          {" "}
          <Badge tone="neutral">off</Badge>
         </>
        )}
       </td>
       <td>{schedule.kind}</td>
       <td>{schedule.next_ms ? new Date(schedule.next_ms).toLocaleString() : <span className="field-hint">no next run</span>}</td>
       <td>
        {schedule.interval_secs > 0 ? `every ${formatDuration(schedule.interval_secs * 1000)}` : "once"}
       </td>
       <td>{schedule.pool ? <code>{schedule.pool}</code> : <span className="field-hint">tool defaults</span>}</td>
       <td>
        {/* Runs and failures together: 30 runs with 30 failures is a
                    schedule failing every night, and either number alone reads
                    as healthy. */}
        <span className="cell-num">{formatCount(schedule.runs)}</span>
        {schedule.failures ? <Badge tone="bad">{formatCount(schedule.failures)} failed</Badge> : null}
       </td>
       <td>
        <span className="cell-num">{formatCount(schedule.missed)}</span>
       </td>
       <td>{schedule.last_note ? schedule.last_note : <span className="field-hint">nothing yet</span>}</td>
       <td>
        <Toolbar>
         <Button
          variant="outline"
          size="small"
          onClick={() => setDialog({ editing: schedule.name, initial: schedule })}
         >
          Edit
         </Button>
         <IconButton
          label={`Delete schedule ${schedule.name}`}
          size="small"
          disabled={remove.isPending}
          onClick={() =>
           remove.mutate(schedule.name, {
            onSuccess: () => toast.success(`Deleted ${schedule.name}`),
            onError: (failure) => fail(failure, "Delete failed"),
           })
          }
         >
          <Trash2 size={13} />
         </IconButton>
        </Toolbar>
       </td>
      </tr>
     ))}
    </SimpleTable>
   ) : null}
   {data ? <p className="field-hint">{data.missed_window_policy}</p> : null}

   {dialog ? (
    <ScheduleDialog
     key={dialog.editing ?? "new"}
     open
     onOpenChange={(open) => (open ? undefined : setDialog(null))}
     editing={dialog.editing}
     initial={dialog.initial}
     kinds={data?.kinds ?? []}
     pools={data?.pools ?? []}
     pending={save.isPending || update.isPending}
     onSubmit={(schedule) => {
      const done = () => {
       toast.success(dialog.editing ? `Saved ${schedule.name}` : `Created ${schedule.name}`);
       setDialog(null);
      };
      if (dialog.editing) {
       update.mutate(
        { name: dialog.editing, schedule },
        { onSuccess: done, onError: (e) => fail(e, "Edit failed") },
       );
      } else {
       save.mutate(schedule, { onSuccess: done, onError: (e) => fail(e, "Create failed") });
      }
     }}
    />
   ) : null}
  </Card>
 );
}

/**
 * The LLM triage endpoint (ei0v): the post-scan second look's OpenAI-compatible endpoint.
 *
 * The key is WRITE-ONLY here: GET answers configured/not and the stored shape, and the PUT
 * keeps a stored key when this form omits one, so re-saving the other fields never clears
 * the credential. Enabling with no base URL is refused by the server — the two-gate rule,
 * and the refusal names what to fill in.
 */
function LlmTriageSection(): JSX.Element {
 const { get, put } = useTriageSettings();
 const [draft, setDraft] = useState<TriageSettingsView | null>(null);

 // Seed the draft from the GET once; a null api_key means "keep whatever is stored".
 useEffect(() => {
  if (get.data && draft === null) {
   setDraft({ enabled: get.data.enabled, base_url: get.data.base_url, model: get.data.model, configured: get.data.configured });
  }
 }, [get.data, draft]);

 if (get.error) return <ErrorNotice error={get.error} />;
 if (!get.data || draft === null) return <LoadingPanel />;

 const save = () => {
  put.mutate(
   { enabled: draft.enabled, base_url: draft.base_url, model: draft.model, api_key: "", configured: false },
   {
    onSuccess: () => toast.success("LLM triage settings applied"),
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "LLM triage settings were refused"),
   },
  );
 };

 return (
  <Card>
   <SectionHeading
    title="LLM triage"
    detail="The post-scan second look: an OpenAI-compatible endpoint that advises on gated findings (High any-confidence, Medium tentative-or-better). Advice only — a triage note never moves a finding's severity or confidence. No default endpoint: the pass is off until one is configured here AND enabled."
   />
   <div className="stack">
    <Field label="Enabled" hint="Two gates: an endpoint configured AND this switch on. The pass refuses with 503 otherwise.">
     {() => <Switch checked={draft.enabled} onCheckedChange={(on) => setDraft({ ...draft, enabled: on })} label="LLM triage" />}
    </Field>
    <Field label="Base URL" hint="The OpenAI-compatible root, e.g. https://api.openai.com/v1 — /chat/completions is appended.">
     {(id) => <Input id={id} value={draft.base_url} onChange={(e) => setDraft({ ...draft, base_url: e.target.value })} placeholder="https://api.openai.com/v1" />}
    </Field>
    <Field label="Model" hint="What to call, e.g. gpt-4o-mini. The model name rides every triage note.">
     {(id) => <Input id={id} value={draft.model} onChange={(e) => setDraft({ ...draft, model: e.target.value })} placeholder="gpt-4o-mini" />}
    </Field>
    <Field label="API key" hint={get.data.configured ? "A key is stored. Send a new one only to replace it; saving without one keeps the stored key." : "Not configured yet."}>
     {(id) => <Input id={id} value={draft.api_key ?? ""} onChange={(e) => setDraft({ ...draft, api_key: e.target.value })} placeholder={get.data.configured ? "(unchanged)" : "sk-…"} type="password" />}
    </Field>
    <div>
     <Button variant="primary" size="small" disabled={put.isPending} onClick={save}>
      {put.isPending ? "Applying…" : "Apply"}
     </Button>
     <span className="cell-dim" style={{ marginLeft: 8 }}>
      {get.data.configured ? "Endpoint configured." : "No endpoint key stored; the pass stays off."}
     </span>
    </div>
   </div>
  </Card>
 );
}

/**
 * The skill library (burpsy-react-ui-ulsy): packaged prompt techniques from the operator's -skills
 * directory, which burpsy-mcp publishes as MCP prompts. This card is where an engagement switches a
 * skill off — a project setting, so another project keeps its own choice. A skill that needs the
 * scripting runtime is listed as unavailable with the reason rather than hidden, and every manifest
 * that did not load is listed with why: a library that silently showed fewer skills than its
 * directory holds would read as complete.
 */
function SkillsSection(): JSX.Element {
 const { get, setDisabled } = useSkills();
 const heading = (
  <SectionHeading
   title="Skills"
   detail="Packaged prompt techniques from the directory burpsy was started with (-skills DIR). An MCP client lists them as prompts, each naming the tools it calls. Turn a skill off here to stop offering it in this project."
  />
 );
 if (get.error) {
  return (
   <Card>
    {heading}
    <ErrorNotice error={get.error} />
   </Card>
  );
 }
 if (!get.data) {
  return (
   <Card>
    {heading}
    <LoadingPanel />
   </Card>
  );
 }
 const view: SkillsView = get.data;
 const toggle = (name: string, on: boolean) => {
  const next = on ? view.disabled.filter((n) => n !== name) : [...view.disabled, name];
  setDisabled.mutate(next, {
   onSuccess: () => toast.success(on ? `Skill ${name} enabled for this project` : `Skill ${name} disabled for this project`),
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "The skill setting was refused"),
  });
 };
 return (
  <Card>
   {heading}
   {!view.configured ? (
    <Empty title="No skill library is loaded" detail={view.hint ?? "Start burpsy with -skills DIR."} />
   ) : (
    <div className="stack">
     <p className="field-hint">
      Loaded from <code>{view.dir}</code>: {formatCount(view.skills.length)} skill{view.skills.length === 1 ? "" : "s"}
      {view.refused.length > 0 ? `, ${formatCount(view.refused.length)} refused` : ""}.{" "}
      {view.persisted ? "Which skills are off is saved with this project." : "No project database is attached, so which skills are off lasts until burpsy exits."}
     </p>
     {view.disabled_error ? <ErrorNotice error={new Error(`The stored list of disabled skills could not be read: ${view.disabled_error}`)} /> : null}
     {view.skills.length === 0 ? (
      <Empty title="The directory holds no loadable skill" detail="Add a <name>.json manifest with a name, a description and a prompt." />
     ) : (
      <SimpleTable headers={["Skill", "Calls", "Status", "On for this project"]}>
       {view.skills.map((skill) => (
        <tr key={skill.name}>
         <td>
          <code>{skill.name}</code>
          <div className="cell-dim">{skill.description}</div>
         </td>
         <td>{skill.tools.length > 0 ? skill.tools.join(", ") : <span className="cell-dim">no tools named</span>}</td>
         <td>
          {skill.available ? <Badge tone="good">Available</Badge> : <Badge tone="warn">Unavailable</Badge>}
          {skill.unavailable_reason ? <div className="cell-dim">{skill.unavailable_reason}</div> : null}
         </td>
         <td>
          <Switch
           checked={!skill.disabled}
           onCheckedChange={(on) => {
            if (!setDisabled.isPending) toggle(skill.name, on);
           }}
           label={`Skill ${skill.name}`}
          />
         </td>
        </tr>
       ))}
      </SimpleTable>
     )}
     {view.refused.length > 0 ? (
      <SimpleTable headers={["Refused manifest", "Why"]}>
       {view.refused.map((r) => (
        <tr key={r.file}>
         <td>
          <code>{r.file}</code>
         </td>
         <td>{r.error}</td>
        </tr>
       ))}
      </SimpleTable>
     ) : null}
    </div>
   )}
  </Card>
 );
}
