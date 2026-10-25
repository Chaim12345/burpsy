import { useState } from "react";
import { Play, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { formatDuration } from "../lib/api";
import { useRunAudit, useScannerConfigs, useScannerCoverage, useScannerLive, useSetScannerLive } from "../lib/data.attack";
import { useScannerConfig, useSaveScannerConfig } from "../lib/data";
import { useSecretDetection, useSetSecretDetection } from "../lib/data.secrets";
import type { ScannerConfig, XssBrowserTarget } from "../lib/types";
import { useApp } from "../lib/store";
import type { AuditResult } from "../lib/types.attack";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, ErrorNotice, Field, Input, Metric, NeedsValueButton, Select, Switch } from "../ui/primitives";
import { DetailList, JsonView } from "../ui/json";
import { SimpleTable } from "../ui/table";

/* ---- audit checks ------------------------------------------------------------------------------
   Moved from Settings (burpsy-react-ui-1yd): Burp puts scan configuration in the scan-launch
   dialogue, not in global settings, and the switches' effect — what the next audit sends — is only
   readable next to the thing that launches one. Same wiring as before: draft-then-Save, PUT through
   /api/scanner/config, persisted for future starts too. */

type AuditRow = { key: keyof ScannerConfig; label: string; hint?: string; defaultOn?: boolean };

// Grouped by what a check does to the target, not by family: the operator is deciding how loud a
// run is. `defaultOn` mirrors the server's own defaults (scanner.NewActiveScanner, j1mk.37); a
// switch without it starts off and is its own opt-in.
const AUDIT_CHECK_GROUPS: { title: string; detail: string; rows: AuditRow[] }[] = [
 {
  title: "Passive",
  detail: "Response inspection that sends no request of its own.",
  rows: [
   { key: "check_headers", label: "Security headers & cookies", defaultOn: true },
   { key: "check_passive_posture", label: "Security posture", defaultOn: true },
   { key: "check_passive_analysis", label: "Advanced passive analysis", defaultOn: true },
   { key: "check_host_discovery", label: "Host discovery notes", defaultOn: true },
   { key: "check_cookie_attributes", label: "Cookie prefix & SameSite", hint: "Read from captured Set-Cookie headers" },
   {
    key: "check_subdomain_takeover",
    label: "Subdomain takeover",
    hint: "Sends nothing to the target, but resolves DNS for every audited hostname",
   },
  ],
 },
 {
  title: "Active injection",
  detail:
   "Inert probes: a marker, an arithmetic expression, a malformed fragment or a file read, each proven by evidence a reflection cannot fake.",
  rows: [
   { key: "check_sqli", label: "SQL injection", defaultOn: true },
   { key: "check_xss", label: "Cross-site scripting", defaultOn: true },
   { key: "check_path_traversal", label: "File path traversal", defaultOn: true },
   {
    key: "check_ssrf",
    label: "Server-side request forgery",
    defaultOn: true,
    hint: "Its out-of-band row also needs Extended active checks and a collaborator; the in-band technique has its own switch below",
   },
   {
    key: "check_xxe",
    label: "XML external entity",
    defaultOn: true,
    hint: "File read through an external entity. Needs the target to accept XML. Entity expansion is under Extended active checks",
   },
   {
    key: "check_active_injection",
    label: "OS command, LDAP, XPath, template & code injection",
    defaultOn: true,
    hint:
     "Twelve checks: OS command, LDAP, XPath, XML, file path manipulation, server-side template, expression language and five code-injection rows. Each is proven by a computed value, an error signature, a control differential or file content",
   },
   {
    key: "check_reflection_probes",
    label: "Reflection probing",
    defaultOn: true,
    hint:
     "Input reflection, open redirect, link manipulation, response header injection, unidentified code injection and server-side includes (an #if expression, never #exec)",
   },
   { key: "check_jwt_weak", label: "Weak JWT secrets" },
   { key: "check_js_vulns", label: "JavaScript vulnerabilities" },
   { key: "check_cache_poisoning", label: "Web cache poisoning" },
   { key: "check_response_dependence", label: "Response-dependence analysis" },
  ],
 },
 {
  title: "Opt-in active probes",
  detail: "Off until switched on. They send request shapes a monitoring system may flag, or replay captured requests in altered form.",
  rows: [
   {
    key: "check_sqli_heavy_query",
    label: "SQL injection: heavy-query delays",
    hint: "Time delays that cost the database CPU rather than a waiting connection",
   },
   {
    key: "check_sqli_or_boolean",
    label: "SQL injection: widening OR shapes",
    hint: "An always-true OR can widen an UPDATE or DELETE to every row",
   },
   {
    key: "check_sqli_stacked",
    label: "SQL injection: stacked queries",
    hint: "Annotates a proven finding; several multi-second sleeps per confirmation",
   },
   { key: "check_nosql_injection", label: "NoSQL injection", hint: "Reads only (GET, or a POST naming a read or a login)" },
   { key: "check_server_side_parameter_pollution", label: "Server-side parameter pollution" },
   {
    key: "check_llm_prompt_injection",
    label: "LLM prompt injection",
    hint: "Appends a benign instruction to text values a model may answer",
   },
   { key: "check_weak_crypto", label: "Weak cryptography", hint: "Submits random markers; on a login form they are failed logins" },
   {
    key: "check_idor",
    label: "Insecure direct object references",
    hint: "Swaps an object id for a neighbour with read-only probes, confirmed against two controls",
   },
   {
    key: "check_graphql_hardening",
    label: "GraphQL hardening",
    hint: "Query batching, depth and debug errors: shapes a gateway's abuse monitoring alerts on",
   },
   { key: "check_host_header", label: "Host header injection", hint: "Sends requests naming hosts the target does not serve" },
   { key: "check_client_ip_spoofing", label: "Spoofable client-IP headers", hint: "Claims loopback to refused pages" },
   {
    key: "check_jwt_forgery",
    label: "JWT forgery",
    hint: "Replays the request with only the token changed: unverified signature, none algorithm, jwk, jku, x5u, expired",
   },
   { key: "check_jwt_exposure", label: "JWT credential exposure", hint: "Replays with the signature altered and with the token removed" },
   {
    key: "check_insecure_deserialization",
    label: "Insecure deserialization",
    hint: "Benign accepted/rejected value pairs; no gadget is sent",
   },
   {
    key: "check_websocket_hijacking",
    label: "Cross-site WebSocket hijacking",
    hint: "Opens authenticated sockets as the captured session",
   },
   {
    key: "check_request_smuggling",
    label: "HTTP request smuggling",
    hint: "Timing only; each confirmed attack holds a back-end connection open for its read window",
   },
   {
    key: "check_extended_active",
    label: "Extended active checks",
    hint:
     "Admits GraphQL, JWT forgery, SMTP header injection, CORS, cross-domain policy files, XML entity expansion, request smuggling, file-upload and OpenAPI discovery, React2Shell fingerprinting, session comparisons and more. Slower, noisier",
   },
  ],
 },
 {
  title: "Intrusive",
  detail: "Leaves state on the target or acts on an account. Use a test account or a disposable environment.",
  rows: [
   {
    key: "check_file_upload",
    label: "File upload",
    hint: "Re-sends an upload as HTML, SVG and server-script files and fetches the stored copies back: it leaves files on the target",
   },
   {
    key: "check_login_rate_limit",
    label: "Login rate limiting",
    hint: "A burst of failed logins under an invented identity: what monitoring is built to alert on",
   },
   { key: "check_username_enumeration", label: "Username enumeration", hint: "Failed logins for the captured, real username" },
   {
    key: "check_password_reset",
    label: "Password reset tokens",
    hint: "Changes the test identity's password and triggers reset mail; does nothing without listed test identities",
   },
   {
    key: "check_session_management",
    label: "Session management",
    hint: "Replays the captured login, with its credentials, for fresh sessions",
   },
  ],
 },
 {
  title: "Engines & coverage",
  detail: "Cross-cutting engines and where the scanner is allowed to spend effort.",
  rows: [
   { key: "check_corpus", label: "BCheck corpus actives", hint: "The bundled PortSwigger corpus, or one loaded via --bchecks" },
   { key: "check_dom", label: "DOM-based checks", hint: "Needs -dom chrome (or ws://) at startup" },
   {
    key: "check_xss_browser_confirm",
    label: "Browser confirmation of reflected XSS",
    hint: "Needs -dom. A point on a route not listed under XSS browser routes is declined, not reported clean",
   },
   { key: "check_out_of_band", label: "Out-of-band callbacks", hint: "interactsh confirmation for blind findings" },
   {
    key: "check_ssrf_in_band",
    label: "In-band SSRF canary",
    hint: "Plants a URL this scanner serves on a loopback listener and sees whether the application fetches it",
   },
   { key: "check_stored", label: "Stored-input rendering" },
   { key: "check_extended_coverage", label: "Extended crawl coverage" },
  ],
 },
];

const XSS_SINKS = [
 "Function",
 "innerHTML",
 "document.write",
 "location",
 "setTimeout(string)",
 "script.src",
 "jQuery.html",
 "localStorage",
 "sessionStorage",
 "postMessage",
 "WebSocket(url)",
 "document.domain",
 "XMLHttpRequest.open",
 "document.cookie",
 "SQLTransaction.executeSql",
 "document.evaluate",
 "JSON.parse",
 "anchor.href",
 "RegExp",
 "FileReader.read*",
 "Object.prototype",
 "XMLHttpRequest.setRequestHeader",
];

const BLANK_ROUTE: XssBrowserTarget = {
 match: "",
 root_url: "",
 master_selector: "",
 master_text: "",
 level_selector: "",
 level_text: "",
 level_from_path: false,
 input_selector: "",
 submit_selector: "",
 click_trigger: false,
 sink: "",
};

const ROUTE_TEXT_FIELDS: {
 key: Exclude<keyof XssBrowserTarget, "level_from_path" | "click_trigger" | "sink">;
 label: string;
 required?: boolean;
}[] = [
 { key: "match", label: "match (URL substring, blank = any)" },
 { key: "root_url", label: "root URL", required: true },
 { key: "master_selector", label: "master selector", required: true },
 { key: "master_text", label: "master text", required: true },
 { key: "level_selector", label: "level selector" },
 { key: "level_text", label: "level text" },
 { key: "input_selector", label: "input selector", required: true },
 { key: "submit_selector", label: "submit selector" },
];

/** The routes the browser XSS confirmation drives. The scanner ships none and cannot guess an
 *  application's navigation, so a point on a route listed nowhere is declined rather than reported
 *  clean. The list is saved whole, with the rest of the card. */
function XssRoutes({ routes, onChange }: { routes: XssBrowserTarget[]; onChange: (routes: XssBrowserTarget[]) => void }): JSX.Element {
 const patch = (i: number, change: Partial<XssBrowserTarget>) => onChange(routes.map((r, at) => (at === i ? { ...r, ...change } : r)));
 return (
  <section aria-label="XSS browser routes" style={{ marginTop: "var(--gap)" }}>
   <h4>XSS browser routes</h4>
   <p className="cell-dim" style={{ margin: 0 }}>
    How the browser confirmation reaches an application's page: where to start, what to click to reach the form, and where to type. Without
    a route, reflected points the server-side check cannot prove are declined. Marked fields are required.
   </p>
   {routes.map((route, i) => (
    <div key={i} className="card" style={{ marginTop: "var(--gap)" }}>
     <div className="metric-grid wide">
      {ROUTE_TEXT_FIELDS.map((f) => (
       <Field key={f.key} label={f.required ? `${f.label} *` : f.label}>
        {(id) => (
         <Input
          id={id}
          aria-label={`Route ${i + 1} ${f.label.replace(/ \(.*\)$/, "")}`}
          value={route[f.key]}
          onChange={(event) => patch(i, { [f.key]: event.target.value })}
         />
        )}
       </Field>
      ))}
      <Field label="sink">
       {(id) => (
        <Select id={id} aria-label={`Route ${i + 1} sink`} value={route.sink} onChange={(event) => patch(i, { sink: event.target.value })}>
         <option value="">innerHTML family (default)</option>
         {XSS_SINKS.map((name) => (
          <option key={name} value={name}>
           {name}
          </option>
         ))}
        </Select>
       )}
      </Field>
     </div>
     <label className="switch-row">
      <span>Level text comes from the URL path</span>
      <Switch
       label={`Route ${i + 1} level from path`}
       checked={route.level_from_path}
       onCheckedChange={(on) => patch(i, { level_from_path: on })}
      />
     </label>
     <label className="switch-row">
      <span>Click the submit selector to trigger</span>
      <Switch
       label={`Route ${i + 1} click trigger`}
       checked={route.click_trigger}
       onCheckedChange={(on) => patch(i, { click_trigger: on })}
      />
     </label>
     <Button
      variant="outline"
      size="small"
      onClick={() => onChange(routes.filter((_, at) => at !== i))}
      aria-label={`Remove route ${i + 1}`}
     >
      Remove route
     </Button>
    </div>
   ))}
   <div style={{ marginTop: "var(--gap)" }}>
    <Button variant="outline" size="small" onClick={() => onChange([...routes, { ...BLANK_ROUTE }])} disabled={routes.length >= 32}>
     Add route
    </Button>
   </div>
  </section>
 );
}

function AuditChecksSection(): JSX.Element {
 const config = useScannerConfig();
 const save = useSaveScannerConfig();
 const [draft, setDraft] = useState<ScannerConfig | null>(null);

 const confirmed = config.data ?? null;
 const current = draft ?? confirmed;
 const dirty =
  current !== null &&
  confirmed !== null &&
  (Object.keys(confirmed) as (keyof ScannerConfig)[]).some((key) => current[key] !== confirmed[key]);

 const toggle = (key: keyof ScannerConfig) => setDraft({ ...current!, [key]: !current![key] } as ScannerConfig);

 const persist = () => {
  if (!current || !confirmed) return;
  const patch: Partial<ScannerConfig> = {};
  const writable = patch as Record<string, unknown>;
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
       <section key={group.title} aria-label={group.title} style={{ marginTop: "var(--gap)" }}>
        <h4>{group.title}</h4>
        <p className="cell-dim" style={{ margin: 0 }}>
         {group.detail}
        </p>
        <div className="switch-grid">
         {group.rows.map((row) => (
          <label key={row.key} className="switch-row" htmlFor={`audit-${row.key}`}>
           <span>
            <span>{row.label}</span>
            {row.defaultOn ? (
             <>
              {" "}
              <Badge tone="info">on by default</Badge>
             </>
            ) : null}
            {row.hint ? (
             <span className="cell-dim" style={{ display: "block" }}>
              {row.hint}
             </span>
            ) : null}
           </span>
           <Switch id={`audit-${row.key}`} label={row.label} checked={Boolean(current[row.key])} onCheckedChange={() => toggle(row.key)} />
          </label>
         ))}
        </div>
       </section>
      ))}
      <XssRoutes routes={current.xss_browser_targets ?? []} onChange={(routes) => setDraft({ ...current, xss_browser_targets: routes })} />
     </div>
    </>
   ) : null}
  </Card>
 );
}

/* ---- live audit + coverage ----------------------------------------------------------------------
   Moved verbatim from pages/scanner.tsx: the launch surface owns the live toggle and what the
   passive checks have covered; the Issues page keeps reading findings. */

/**
 * Secret detection (burpsy-react-ui-8j0d): the gitleaks rule corpus over every captured response —
 * proxy, crawl, Repeater, API scan — raising one finding per leaked key with its rule, its line and a
 * redacted excerpt. Passive: it reads responses already captured and sends nothing. Off until
 * switched on, so a project never starts filing findings nobody asked for.
 */
function SecretDetectionCard(): JSX.Element {
 const { data, error, refetch } = useSecretDetection();
 const set = useSetSecretDetection();
 return (
  <Card>
   <SectionHeading
    title="Secret detection"
    detail="Scans every captured response — decompressed and dechunked first — for leaked API keys, cloud credentials, tokens and private keys. Passive: nothing is sent."
    actions={
     data ? (
      <Switch
       id="secret-detection"
       label="Scan captured responses for leaked secrets"
       checked={data.enabled}
       onCheckedChange={(on) =>
        set.mutate(on, {
         onSuccess: () => toast.success(on ? "Secret detection is on for new captures" : "Secret detection is off"),
         onError: (err) => toast.error(err.message),
        })
       }
      />
     ) : null
    }
   />
   {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   {data ? (
    <p className="cell-dim">
     {data.enabled ? "On" : "Off"} — {data.rules.toLocaleString()} rules from {data.corpus}, plus {data.extra.join(", ")}.{" "}
     {Object.entries(data.excluded)
      .map(([rule, why]) => `Not reported: ${rule} (${why}).`)
      .join(" ")}{" "}
     Applies to responses captured from now on; a body over 4 MiB is scanned up to that size.
    </p>
   ) : null}
  </Card>
 );
}

function LiveAuditCard(): JSX.Element {
 const { data, error, isFetching } = useScannerLive();
 const setLive = useSetScannerLive();

 const toggle = () => {
  if (!data?.wired) {
   toast.error("Live active audit is not wired up on this server");
   return;
  }
  setLive.mutate({ enabled: !data.enabled }, { onError: (err) => toast.error(err instanceof Error ? err.message : String(err)) });
 };

 const gaps: string[] = [];
 // The backlog's age is the half of the number that says whether the sweep is keeping up: the same
 // "400 behind" reads as a busy moment at forty seconds and as a stalled sweep at forty minutes
 // (burpsy-react-ui-iosv). formatDuration renders "—" for a non-finite value, which cannot happen
 // here because the field is only read when the backlog exists.
 if (data && data.behind > 0)
  gaps.push(`${data.behind.toLocaleString()} not reached yet (behind for ${formatDuration(data.behind_for_ms)})`);
 if (data?.skipped) gaps.push(`${data.skipped.toLocaleString()} given up on`);
 if (data?.stalled_at !== undefined) gaps.push(`waiting on #${data.stalled_at}`);

 return (
  <Card>
   <SectionHeading
    title="Live active audit"
    detail="Audits new in-scope traffic as it is captured. Active checks are never sent automatically while this is off."
    actions={
     <>
      {/* The per-source gate (zk35), Burp's scope source choice: "proxy" admits only
                the operator's own captures (the default — a sweep that audited its own
                probes would be a feedback loop), "everything" admits any tool's in-scope
                captures. The choice posts with the switch's own mutation. */}
      <Select
       aria-label="Live audit traffic source"
       value={data?.traffic_source ?? "proxy"}
       onChange={(event) => {
        setLive.mutate(
         { enabled: data?.enabled ?? false, traffic_source: event.target.value },
         { onError: (err) => toast.error(err instanceof Error ? err.message : String(err)) },
        );
       }}
       style={{ width: "auto" }}
      >
       <option value="proxy">Proxy traffic only</option>
       <option value="everything">Everything in scope</option>
      </Select>
      {data?.stalled_at !== undefined ? (
       <Button
        variant="outline"
        size="small"
        disabled={setLive.isPending}
        title="Wait on the stalled exchange again, with its stall budget carried rather than restarted"
        onClick={() => {
         setLive.mutate(
          { enabled: data?.enabled ?? false, retry_stalled: true },
          {
           onSuccess: (next) => {
            if (next.stalled_at === undefined) {
             toast.success("Re-queued — the sweep will wait on the stalled exchange again");
            }
           },
           onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
          },
         );
        }}
       >
        Retry stalled
       </Button>
      ) : null}
      <Switch checked={data?.enabled ?? false} onCheckedChange={toggle} label="Live active audit" />
     </>
    }
   />
   {error ? <ErrorNotice error={error} /> : null}
   {data && !data.wired ? <div className="notice notice-warn">{data.hint ?? "not available"}</div> : null}
   {data && data.wired ? (
    <>
     <div className="metric-grid compact">
      <Metric label="Exchanges swept" value={(data.swept ?? 0).toLocaleString()} />
      <Metric label="Findings" value={(data.findings ?? 0).toLocaleString()} />
     </div>
     <div className="chip-row">
      {data.behind > 0 ? (
       <Badge
        tone="warn"
        title="captured but not yet reached by the sweep cursor — the age says whether the sweep is keeping up, the bound says how hard it is working at it"
       >
        {data.behind.toLocaleString()} not swept yet · behind {formatDuration(data.behind_for_ms)}
        {data.batch_limit > 0 ? ` · sweeping ${data.batch_limit.toLocaleString()}/tick` : ""}
       </Badge>
      ) : null}
      {data.skipped ? (
       <Badge tone="warn" title="the sweep stopped waiting for a response; not counted as clean">
        {data.skipped.toLocaleString()} given up on
       </Badge>
      ) : null}
      {data.stalled_at !== undefined ? (
       <Badge
        tone="warn"
        title="the sweep is waiting for this exchange's response; press retry to wait on it again with its stall budget carried"
       >
        waiting on #{data.stalled_at}
       </Badge>
      ) : null}
      {data.refused_source ? (
       <Badge tone="warn" title="in-scope captures the source gate skipped — not the tool you chose">
        {data.refused_source.toLocaleString()} not this source
       </Badge>
      ) : null}
      {data.retried ? (
       <Badge title="exchanges the sweep had given up on whose response landed; audited on their second chance">
        {data.retried.toLocaleString()} taken back
       </Badge>
      ) : null}
      {data.collapsed ? (
       <Badge title="checks the shared ledger refused as already covered — this work ran, it is not a gap">
        {data.collapsed.toLocaleString()} already covered
       </Badge>
      ) : null}
      {data.ledger_resets ? <Badge tone="warn">{data.ledger_resets.toLocaleString()} ledger reset(s)</Badge> : null}
     </div>
     <p className="field-hint">
      {gaps.length === 0
       ? "complete — the sweep is caught up, nothing skipped and nothing waiting"
       : `a floor, not a total: ${gaps.join("; ")}`}
      {data.query ? ` · filtered to ${data.query}` : ""}
     </p>
    </>
   ) : null}
   {!data && isFetching ? <LoadingPanel /> : null}
  </Card>
 );
}

function CoverageCard(): JSX.Element {
 const { data, error, isFetching } = useScannerCoverage();
 return (
  <Card>
   <SectionHeading
    title="Passive check coverage"
    detail={
     data
      ? (data.summary ?? `${data.loaded ?? 0} BCheck(s) loaded`)
      : "How much of the captured traffic each passive check has actually run against."
    }
   />
   {error ? <ErrorNotice error={error} /> : null}
   {!data && isFetching ? <LoadingPanel /> : null}
   {data && !data.enabled ? <div className="notice notice-warn">{data.hint ?? "passive BCheck scanning is not enabled"}</div> : null}
   {data?.enabled ? (
    <>
     {data.partition?.length ? (
      <div className="chip-row">
       {data.partition.map((p) => (
        <Badge key={p.state}>
         {p.count} {p.state}
        </Badge>
       ))}
      </div>
     ) : null}
     {(data.undecoded_bodies ?? 0) > 0 ? (
      <div className="notice notice-warn">
       {data.undecoded_bodies!.toLocaleString()} response(s) were scanned with a body this build cannot decode (an encoding chain or a
       corrupt stream) — the body checks read encoded bytes there, so a clean result on them is not evidence the body is clean. Proxy
       settings › Strip Accept-Encoding from requests asks origins for uncompressed responses.
      </div>
     ) : null}
     <SimpleTable headers={["Check", "Ran", "Findings", "Errored", "State"]}>
      {(data.checks ?? []).map((check) => (
       <tr key={check.name}>
        <td>{check.name}</td>
        <td className="cell-num">{check.ran.toLocaleString()}</td>
        <td className="cell-num">{check.findings.toLocaleString()}</td>
        <td className="cell-num">{check.errored.toLocaleString()}</td>
        <td>
         <Badge tone={check.errored > 0 ? "warn" : "good"} title={check.last_error}>
          {check.state}
         </Badge>
        </td>
       </tr>
      ))}
     </SimpleTable>
    </>
   ) : null}
  </Card>
 );
}

/* ---- targeted audit -----------------------------------------------------------------------------
   The one-exchange launch: same strip the Audit-settings modal used to carry, promoted to the page
   where a scan is started. The result panel stays here rather than on Issues — it describes the run
   (checks that ran, what was refused), not a finding. */

function TargetedAudit(): JSX.Element {
 const configsQuery = useScannerConfigs();
 const runAudit = useRunAudit();
 const [exchangeId, setExchangeId] = useState("");
 const [configName, setConfigName] = useState("");
 const [auditResult, setAuditResult] = useState<AuditResult | null>(null);

 const run = () => {
  const id = Number(exchangeId);
  // `< 0` and Number.isInteger, not `<= 0` and isFinite: exchange 0 is a real exchange, and 1.5 is
  // finite but is not an id.
  if (!exchangeId.trim() || !Number.isInteger(id) || id < 0) {
   toast.error("Enter an exchange id — a whole number, counting from 0");
   return;
  }
  runAudit.mutate(
   { exchangeId: id, config: configName || undefined },
   {
    onSuccess: (result) => {
     setAuditResult(result);
     toast.success(result.error ? `Audit refused: ${result.error}` : `Audit ran against #${id}`);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
   },
  );
 };

 return (
  <>
   <Card>
    <div className="audit-strip">
     <div>
      <ShieldAlert size={20} />
      <span>
       <strong>Targeted audit</strong>
       <small>Run the configured checks against one captured exchange.</small>
      </span>
     </div>
     <Select
      aria-label="Scan configuration"
      title="Scan configuration"
      value={configName}
      onChange={(event) => setConfigName(event.target.value)}
     >
      <option value="">server default</option>
      {(configsQuery.data?.configs ?? []).map((c) => (
       <option key={c.name} value={c.name}>
        {c.name}
       </option>
      ))}
     </Select>
     <Input
      type="number"
      value={exchangeId}
      onChange={(event) => setExchangeId(event.target.value)}
      aria-label="Exchange ID"
      title="Exchange ID"
      placeholder="Exchange ID"
      style={{ maxWidth: "var(--w-xs)" }}
     />
     <NeedsValueButton onClick={run} disabled={runAudit.isPending} missing={exchangeId ? null : "needs an exchange id"}>
      <Play size={14} />
      {runAudit.isPending ? "Auditing…" : "Audit"}
     </NeedsValueButton>
    </div>
   </Card>
   {auditResult ? (
    <Card>
     <SectionHeading
      title={`Audit result — exchange #${auditResult.exchange_id}`}
      detail={auditResult.summary ?? (auditResult.error ? "refused" : "completed")}
      actions={<Badge tone={auditResult.error ? "bad" : "good"}>{auditResult.config_name || "server default"}</Badge>}
     />
     {auditResult.error ? <ErrorNotice error={auditResult.error} /> : null}
     <DetailList
      rows={[
       { label: "Active checks", value: auditResult.active_checks },
       { label: "Unimplemented checks", value: auditResult.unimplemented },
       { label: "Time budget", value: formatDuration(auditResult.config.time_budget_ms) },
       { label: "Max requests", value: auditResult.config.max_requests ?? "uncapped" },
      ]}
     />
     {/* The engine's outcome/dispositions/breakdown are scanner-internal and not worth a bespoke
              shape here; JsonView is the documented fallback for an irregular payload. */}
     {auditResult.breakdown ? <JsonView value={auditResult.breakdown} label="breakdown" defaultOpen={1} /> : null}
     {auditResult.outcome ? <JsonView value={auditResult.outcome} label="outcome" defaultOpen={1} /> : null}
     {auditResult.dispositions ? <JsonView value={auditResult.dispositions} label="dispositions" defaultOpen={0} /> : null}
    </Card>
   ) : null}
  </>
 );
}

/**
 * The Scanner surface (burpsy-react-ui-1yd): one page an operator can find and launch a scan from.
 * Burp has a SCANNER tool; burpsy had the capability split across a modal on the Issues page, two
 * dashboard dialogs, and ~21 check switches sitting under global Settings — every piece wired, none
 * of them where a Burp user looks for a scanner. This page composes the existing pieces: the live
 * toggle and the targeted-audit strip move here from the Issues page's modal, and the check-family
 * switches move here from Settings, so the thing a switch changes is on the same screen. Findings
 * stay on Issues, which remains the results view it already was.
 */
export function ScannerLaunchPage(): JSX.Element {
 const setRoute = useApp((state) => state.setRoute);
 return (
  <div className="page">
   <PageHeader
    title="Scanner"
    description="Launch an audit, choose what it runs, and watch the live sweep. Findings are read on Issues; what each exchange was skipped for is on the Audit queue."
    actions={
     <>
      <Button variant="outline" size="small" onClick={() => setRoute("scanner")}>
       Issues
      </Button>
      <Button variant="outline" size="small" onClick={() => setRoute("auditqueue")}>
       Audit queue
      </Button>
     </>
    }
   />
   <TargetedAudit />
   <LiveAuditCard />
   <SecretDetectionCard />
   <AuditChecksSection />
   <CoverageCard />
  </div>
 );
}
