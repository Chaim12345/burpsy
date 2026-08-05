import { useMemo, useState } from "react";
import { Download, Play, ShieldAlert, X } from "lucide-react";
import { toast } from "sonner";
import { formatDuration } from "../lib/api";
import { useDebounced } from "../lib/data";
import {
  useIssuesDetailed,
  useRunAudit,
  useScannerConfigs,
  useScannerCoverage,
  useScannerLive,
  useSetScannerLive,
} from "../lib/data.attack";
import { useApp } from "../lib/store";
import type { AuditResult, FindingDetail } from "../lib/types.attack";
import { LoadingPanel, PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNotice,
  IconButton,
  Input,
  LinkButton,
  Metric,
  Select,
  Switch,
  Toolbar,
  type Tone,
} from "../ui/primitives";
import { SimpleTable, VirtualTable, type Column } from "../ui/table";
import { DetailList, JsonView } from "../ui/json";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
const CONFIDENCES = ["Certain", "Firm", "Tentative"];
const SEVERITY_RANK: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 };
const REPORT_FORMATS = [
  { format: "html", label: "HTML" },
  { format: "json", label: "JSON" },
  { format: "sarif", label: "SARIF" },
];

function severityRank(severity: string): number {
  return SEVERITY_RANK[severity] ?? -1;
}

function severityTone(severity: string): Tone {
  switch (severity) {
    case "Critical":
    case "High":
      return "bad";
    case "Medium":
      return "warn";
    case "Low":
      return "info";
    default:
      return "neutral";
  }
}

function confidenceTone(confidence: string): Tone {
  switch (confidence) {
    case "Certain":
      return "good";
    case "Firm":
      return "info";
    default:
      return "neutral";
  }
}

/** The live active-audit sweep and the passive-check coverage it runs alongside. Both are read from
 * the scanner's own counters, never inferred from findings, so a pane that shows neither can never
 * claim more coverage than actually happened (mirrors liveaudit.ts's chips/verdict split). */
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
  if (data && data.behind > 0) gaps.push(`${data.behind.toLocaleString()} not reached yet`);
  if (data?.skipped) gaps.push(`${data.skipped.toLocaleString()} given up on`);
  if (data?.stalled_at !== undefined) gaps.push(`waiting on #${data.stalled_at}`);

  return (
    <Card>
      <div className="section-heading">
        <div>
          <h3>Live active audit</h3>
          <p>Audits new in-scope traffic as it is captured. Active checks are never sent automatically while this is off.</p>
        </div>
        <Switch checked={data?.enabled ?? false} onCheckedChange={toggle} label="Live active audit" />
      </div>
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
              <Badge tone="warn" title="captured but not yet reached by the sweep cursor">
                {data.behind.toLocaleString()} not swept yet
              </Badge>
            ) : null}
            {data.skipped ? (
              <Badge tone="warn" title="the sweep stopped waiting for a response; not counted as clean">
                {data.skipped.toLocaleString()} given up on
              </Badge>
            ) : null}
            {data.stalled_at !== undefined ? <Badge tone="warn">waiting on #{data.stalled_at}</Badge> : null}
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
      <div className="section-heading">
        <div>
          <h3>Passive check coverage</h3>
          <p>{data ? (data.summary ?? `${data.loaded ?? 0} BCheck(s) loaded`) : "How much of the captured traffic each passive check has actually run against."}</p>
        </div>
      </div>
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

export function ScannerPage(): JSX.Element {
  const { data: issues, error, isFetching, refetch } = useIssuesDetailed();
  const configsQuery = useScannerConfigs();
  const runAudit = useRunAudit();
  const focusExchange = useApp((state) => state.focusExchange);
  const setRoute = useApp((state) => state.setRoute);

  const [severity, setSeverity] = useState("all");
  const [confidence, setConfidence] = useState("all");
  const [term, setTerm] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [exchangeId, setExchangeId] = useState("");
  const [configName, setConfigName] = useState("");
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);

  const debouncedTerm = useDebounced(term, 260);

  const rows = useMemo(() => {
    const all = issues?.findings ?? [];
    const needle = debouncedTerm.trim().toLowerCase();
    return all
      .filter((f) => severity === "all" || f.severity === severity)
      .filter((f) => confidence === "all" || f.confidence === confidence)
      .filter((f) => {
        if (!needle) return true;
        const haystack = `${f.check_name ?? ""} ${f.issue_name ?? ""} ${f.host} ${f.detail ?? ""}`.toLowerCase();
        return haystack.includes(needle);
      })
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  }, [issues, severity, confidence, debouncedTerm]);

  const selected = useMemo(() => rows.find((f) => f.id === selectedId) ?? null, [rows, selectedId]);

  const columns = useMemo<Column<FindingDetail>[]>(
    () => [
      {
        id: "severity",
        header: "Sev",
        size: 88,
        accessorFn: (row) => severityRank(row.severity),
        cell: (info) => <Badge tone={severityTone(info.row.original.severity)}>{info.row.original.severity}</Badge>,
      },
      {
        accessorKey: "confidence",
        header: "Conf",
        size: 86,
        cell: (info) => <Badge tone={confidenceTone(info.getValue<string>())}>{info.getValue<string>()}</Badge>,
      },
      {
        id: "name",
        header: "Issue",
        size: 260,
        accessorFn: (row) => row.issue_name ?? row.check_name ?? "Unnamed finding",
        cell: (info) => <span title={info.getValue<string>()}>{info.getValue<string>()}</span>,
      },
      { accessorKey: "host", header: "Host", size: 170 },
      {
        accessorKey: "times_seen",
        header: "Seen",
        size: 70,
        cell: (info) => <span className="cell-num">{info.getValue<number>()}</span>,
      },
    ],
    [],
  );

  const runOnExchange = () => {
    const id = Number(exchangeId);
    if (!Number.isFinite(id) || id <= 0) {
      toast.error("Enter a numeric exchange id");
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

  const detail = selected ? (
    <div className="detail-panel">
      <div className="detail-head">
        <div className="detail-head-title">
          <span className="eyebrow">{selected.confidence} confidence</span>
          <strong>{selected.issue_name ?? selected.check_name ?? "Unnamed finding"}</strong>
        </div>
        <div className="detail-actions">
          <Badge tone={severityTone(selected.severity)}>{selected.severity}</Badge>
          <IconButton label="Clear selection" size="small" onClick={() => setSelectedId(null)}>
            <X size={13} />
          </IconButton>
        </div>
      </div>
      <DetailList
        rows={[
          { label: "Check", value: selected.check_name ?? "—" },
          { label: "Host", value: selected.host || "—" },
          { label: "Times seen", value: selected.times_seen },
        ]}
      />
      <div>
        <h4>Evidence</h4>
        <p className="prose">{selected.detail ?? "no detail recorded"}</p>
      </div>
      <div>
        <h4>Remediation</h4>
        <p className="prose">{selected.remediation ?? "no remediation recorded"}</p>
      </div>
      <div>
        <h4>Occurrences ({selected.occurrences.length})</h4>
        {selected.occurrences.length === 0 ? (
          <p className="field-hint">no occurrences recorded</p>
        ) : (
          <div className="actions">
            {selected.occurrences.map((occurrence, index) => (
              <Button
                key={`${occurrence.exchange_id}-${index}`}
                variant="outline"
                size="small"
                onClick={() => {
                  focusExchange(occurrence.exchange_id);
                  setRoute("history");
                }}
              >
                #{occurrence.exchange_id} {occurrence.path}
              </Button>
            ))}
          </div>
        )}
      </div>
    </div>
  ) : (
    <Empty title="Select a finding" detail="Review evidence, confidence, occurrences, and remediation. Click an occurrence to jump to it in HTTP history." />
  );

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Scanner"
          actions={
            <>
              {REPORT_FORMATS.map((f) => (
                <LinkButton key={f.format} href={`/api/report/${f.format}`} download>
                  <Download size={13} />
                  {f.label}
                </LinkButton>
              ))}
              <RefreshButton onClick={() => void refetch()} loading={isFetching} />
            </>
          }
        />

        <div className="two-col" style={{ marginBottom: 10 }}>
          <LiveAuditCard />
          <CoverageCard />
        </div>

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
            placeholder="Exchange ID"
            style={{ maxWidth: "var(--w-xs)" }}
          />
          <Button onClick={runOnExchange} disabled={!exchangeId || runAudit.isPending}>
            <Play size={14} />
            {runAudit.isPending ? "Auditing…" : "Audit"}
          </Button>
        </div>

        {auditResult ? (
          <Card>
            <div className="section-heading">
              <div>
                <h3>Audit result — exchange #{auditResult.exchange_id}</h3>
                <p>{auditResult.summary ?? (auditResult.error ? "refused" : "completed")}</p>
              </div>
              <Badge tone={auditResult.error ? "bad" : "good"}>{auditResult.config_name || "server default"}</Badge>
            </div>
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

        <Toolbar style={{ marginTop: 10 }}>
          <Input
            aria-label="Filter findings"
            value={term}
            onChange={(event) => setTerm(event.target.value)}
            placeholder="Filter by check, issue, host or detail"
          />
          <Select aria-label="Severity filter" value={severity} onChange={(event) => setSeverity(event.target.value)} style={{ maxWidth: "var(--w-sm)" }}>
            <option value="all">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
          <Select aria-label="Confidence filter" value={confidence} onChange={(event) => setConfidence(event.target.value)} style={{ maxWidth: "var(--w-sm)" }}>
            <option value="all">All confidence</option>
            {CONFIDENCES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </Select>
          <Badge>{rows.length.toLocaleString()} finding(s)</Badge>
        </Toolbar>
        {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
        {issues && !issues.enabled ? <div className="notice notice-warn">{issues.hint ?? "passive scanning is not enabled"}</div> : null}
      </div>

      <SplitPane
        storageId="scanner"
        orientation="vertical"
        defaultMasterSize="52"
        master={
          <VirtualTable
            ariaLabel="Scanner findings"
            data={rows}
            columns={columns}
            getRowId={(row) => String(row.id)}
            selectedId={selectedId === null ? null : String(selectedId)}
            onSelect={(row) => setSelectedId(row.id)}
            loading={isFetching && !issues}
            empty={
              <Empty
                title={term || severity !== "all" || confidence !== "all" ? "No finding matches this filter" : "No findings yet"}
                detail={issues?.hint ?? "Captured and audited traffic has not produced findings."}
              />
            }
          />
        }
        detail={detail}
      />
    </div>
  );
}
