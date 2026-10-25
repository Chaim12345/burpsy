import { useState } from "react";
import { Play, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { formatDuration } from "../lib/api";
import { useRunAudit, useScannerConfigs, useScannerCoverage, useScannerLive, useSetScannerLive } from "../lib/data.attack";
import { useScannerConfig, useSaveScannerConfig } from "../lib/data";
import { useSecretDetection, useSetSecretDetection } from "../lib/data.secrets";
import type { ScannerConfig } from "../lib/types";
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
      { key: "check_corpus", label: "BCheck corpus actives", hint: "The bundled PortSwigger corpus, or one loaded via --bchecks" },
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
    setLive.mutate(
      { enabled: !data.enabled },
      { onError: (err) => toast.error(err instanceof Error ? err.message : String(err)) },
    );
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
              <Badge tone="warn" title="the sweep is waiting for this exchange's response; press retry to wait on it again with its stall budget carried">
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
        detail={data ? (data.summary ?? `${data.loaded ?? 0} BCheck(s) loaded`) : "How much of the captured traffic each passive check has actually run against."}
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
              {data.undecoded_bodies!.toLocaleString()} response(s) were scanned with a body this build cannot decode (an encoding
              chain or a corrupt stream) — the body checks read encoded bytes there, so a clean result on them is not evidence the body is clean.
              Proxy settings › Strip Accept-Encoding from requests asks origins for uncompressed responses.
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
          <Select aria-label="Scan configuration" title="Scan configuration" value={configName} onChange={(event) => setConfigName(event.target.value)}>
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
