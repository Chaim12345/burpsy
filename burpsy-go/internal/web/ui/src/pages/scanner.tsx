import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Download, ExternalLink, Globe, Play, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { toast } from "sonner";
import { formatDuration } from "../lib/api";
import { useDebounced, useHistory, useMessage } from "../lib/data";
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
import type { AdvisoryLink, Occurrence } from "../lib/types";
import { HttpEditor } from "../ui/editor";
import { LoadingPanel, PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNotice,
  Input,
  LinkButton,
  Metric,
  Modal,
  Select,
  Switch,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Toolbar,
  Tooltip,
  type Tone,
} from "../ui/primitives";
import { SimpleTable } from "../ui/table";
import { DetailList, JsonView } from "../ui/json";
import { cn } from "../lib/cn";

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

function findingName(f: FindingDetail): string {
  return f.issue_name ?? f.check_name ?? "Unnamed finding";
}

/** Burp marks a node with the worst severity underneath it, so a collapsed host still shows that
 * something critical is inside. A small square rather than a full badge: at tree density a badge per
 * row is louder than the row label it is meant to qualify. */
function SeverityDot({ severity }: { severity: string }): JSX.Element {
  return <span className={`sev-dot sev-${severity.toLowerCase()}`} title={severity} aria-label={severity} />;
}

/* ---- audit configuration, kept out of the way ---------------------------------------------------
   These three panels are settings, not findings. They used to sit above the table and pushed the
   first finding below the fold on a laptop; they now live behind one toolbar button. */

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

/* ---- the issue tree ---------------------------------------------------------------------------- */

interface IssueLeaf {
  key: string;
  finding: FindingDetail;
  /** Null when the finding recorded no location; it still belongs to its host. */
  occurrence: Occurrence | null;
}

interface PathGroup {
  path: string;
  leaves: IssueLeaf[];
  worst: number;
}

interface HostGroup {
  host: string;
  paths: PathGroup[];
  worst: number;
  count: number;
}

/** Burp lists an issue under every path it was found at, so one finding with three occurrences is
 * three tree leaves and one advisory — not one leaf that hides where it actually happened. */
/**
 * The issue-definition catalogue entry for a finding.
 *
 * The catalogue is 183 entries of long-form description, remediation and taxonomy — the thing that
 * turns a one-line check name into something an operator can act on and put in front of a client. It
 * was already resolved server-side and served on /api/issues, and then rendered nowhere: this panel
 * showed only the check's own two lines. This is the missing half.
 *
 * Prose arrives pre-split into plain-text paragraphs, so there is no markup to trust here. Links are
 * separate typed fields, rendered as real anchors from data rather than parsed out of a string.
 */
function AdvisoryPanel({ finding }: { finding: FindingDetail }): JSX.Element | null {
  const advisory = finding.advisory;
  if (!advisory) {
    // A deliberate absence is stated. "No catalogue entry, and here is why" and "nothing looked" are
    // different claims, and a blank panel reads as a loading failure.
    return finding.advisory_note ? (
      <div>
        <h4>Issue definition</h4>
        <p className="prose cell-dim">{finding.advisory_note}</p>
      </div>
    ) : null;
  }
  return (
    <div className="advisory-catalogue">
      <h4>
        Issue definition — {advisory.name} <span className="cell-dim">({advisory.type_index})</span>
      </h4>
      {advisory.typical_severity ? (
        <p className="field-hint">This issue class is typically {advisory.typical_severity.toLowerCase()} severity.</p>
      ) : null}
      {(advisory.description_paragraphs ?? []).map((text, i) => (
        <p className="prose" key={`d${i}`}>
          {text}
        </p>
      ))}
      {(advisory.remediation_paragraphs ?? []).length ? (
        <>
          <h4>Recommended remediation</h4>
          {(advisory.remediation_paragraphs ?? []).map((text, i) => (
            <p className="prose" key={`r${i}`}>
              {text}
            </p>
          ))}
        </>
      ) : null}
      <AdvisoryLinks label="Classifications" links={advisory.classifications} />
      <AdvisoryLinks label="References" links={advisory.references} />
    </div>
  );
}

function AdvisoryLinks({ label, links }: { label: string; links?: AdvisoryLink[] }): JSX.Element | null {
  if (!links || links.length === 0) return null;
  return (
    <div className="stack-tight">
      <span className="eyebrow">{label}</span>
      {links.map((link) => (
        <a key={link.url} href={link.url} target="_blank" rel="noopener noreferrer" className="advisory-link">
          {link.title || link.url}
          <ExternalLink size={11} />
        </a>
      ))}
    </div>
  );
}

function groupFindings(findings: FindingDetail[]): HostGroup[] {
  const byHost = new Map<string, Map<string, IssueLeaf[]>>();
  for (const finding of findings) {
    const host = finding.host || "(no host)";
    const paths = byHost.get(host) ?? new Map<string, IssueLeaf[]>();
    byHost.set(host, paths);
    const spots: (Occurrence | null)[] = finding.occurrences.length ? finding.occurrences : [null];
    spots.forEach((occurrence, index) => {
      const path = occurrence?.path || "(no location)";
      const leaves = paths.get(path) ?? [];
      leaves.push({ key: `${finding.id}:${occurrence?.exchange_id ?? "none"}:${index}`, finding, occurrence });
      paths.set(path, leaves);
    });
  }

  const out: HostGroup[] = [];
  for (const [host, paths] of byHost) {
    const pathGroups: PathGroup[] = [];
    let hostWorst = -1;
    let count = 0;
    for (const [path, leaves] of paths) {
      leaves.sort((a, b) => severityRank(b.finding.severity) - severityRank(a.finding.severity));
      const worst = leaves.reduce((acc, leaf) => Math.max(acc, severityRank(leaf.finding.severity)), -1);
      hostWorst = Math.max(hostWorst, worst);
      count += leaves.length;
      pathGroups.push({ path, leaves, worst });
    }
    // Worst-first, then alphabetical, so the thing that matters is never scrolled to.
    pathGroups.sort((a, b) => b.worst - a.worst || a.path.localeCompare(b.path));
    out.push({ host, paths: pathGroups, worst: hostWorst, count });
  }
  out.sort((a, b) => b.worst - a.worst || a.host.localeCompare(b.host));
  return out;
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
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [exchangeId, setExchangeId] = useState("");
  const [configName, setConfigName] = useState("");
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const debouncedTerm = useDebounced(term, 260);
  // Same cache key the history tab uses: the advisory's Request/Response tabs need the message ids,
  // which a finding's occurrence does not carry.
  const { data: history } = useHistory("", 1000);

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
      });
  }, [issues, severity, confidence, debouncedTerm]);

  const groups = useMemo(() => groupFindings(rows), [rows]);

  const selected = useMemo(() => {
    for (const host of groups) {
      for (const path of host.paths) {
        const leaf = path.leaves.find((l) => l.key === selectedKey);
        if (leaf) return leaf;
      }
    }
    return null;
  }, [groups, selectedKey]);

  const severityCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const f of rows) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
    return SEVERITIES.filter((s) => counts.has(s)).map((s) => ({ severity: s, count: counts.get(s) ?? 0 }));
  }, [rows]);

  const exchange = useMemo(() => {
    const id = selected?.occurrence?.exchange_id;
    if (id === undefined) return null;
    return (history ?? []).find((ex) => ex.id === id) ?? null;
  }, [history, selected]);
  const request = useMessage(exchange?.request);
  const response = useMessage(exchange?.response ?? null);

  const runOnExchange = () => {
    const id = Number(exchangeId);
    // `< 0` and Number.isInteger, not `<= 0` and isFinite: exchange 0 is a real exchange, and 1.5 is
    // finite but is not an id.
    if (!Number.isInteger(id) || id < 0) {
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

  const treePane = (
    <div className="pane">
      <Toolbar className="pane-toolbar">
        <Input
          aria-label="Filter findings"
          value={term}
          onChange={(event) => setTerm(event.target.value)}
          placeholder="Filter by check, issue, host or detail"
        />
      </Toolbar>
      {isFetching && !issues ? (
        <LoadingPanel />
      ) : groups.length === 0 ? (
        <Empty
          title={term || severity !== "all" || confidence !== "all" ? "No finding matches this filter" : "No findings yet"}
          detail={issues?.hint ?? "Captured and audited traffic has not produced findings."}
        />
      ) : (
        <div className="row-list tree-pane" role="tree" aria-label="Findings by host and path">
          {groups.map((host) => {
            const hostKey = `h:${host.host}`;
            const hostOpen = !collapsed[hostKey];
            return (
              <div key={hostKey} role="group">
                <div
                  role="treeitem"
                  aria-level={1}
                  aria-expanded={hostOpen}
                  className="tree-row"
                  style={{ paddingLeft: 8 }}
                  onClick={() => setCollapsed((c) => ({ ...c, [hostKey]: hostOpen }))}
                >
                  <button type="button" className="tree-toggle" aria-label={hostOpen ? `Collapse ${host.host}` : `Expand ${host.host}`}>
                    {hostOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                  </button>
                  <span className="tree-row-icon" aria-hidden="true">
                    <Globe size={12} />
                  </span>
                  <span className="tree-row-label" title={host.host}>
                    {host.host}
                  </span>
                  <span className="tree-row-meta">
                    <span className="tree-row-count cell-num">{host.count}</span>
                  </span>
                </div>
                {hostOpen
                  ? host.paths.map((path) => {
                      const pathKey = `p:${host.host}:${path.path}`;
                      const pathOpen = !collapsed[pathKey];
                      return (
                        <div key={pathKey} role="group">
                          <div
                            role="treeitem"
                            aria-level={2}
                            aria-expanded={pathOpen}
                            className="tree-row"
                            style={{ paddingLeft: 22 }}
                            onClick={() => setCollapsed((c) => ({ ...c, [pathKey]: pathOpen }))}
                          >
                            <button type="button" className="tree-toggle" aria-label={pathOpen ? `Collapse ${path.path}` : `Expand ${path.path}`}>
                              {pathOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                            </button>
                            <span className="tree-row-icon" aria-hidden="true" />
                            <span className="tree-row-label" title={path.path}>
                              {path.path}
                            </span>
                            <span className="tree-row-meta">
                              <span className="tree-row-count cell-num">{path.leaves.length}</span>
                            </span>
                          </div>
                          {pathOpen
                            ? path.leaves.map((leaf) => (
                                <div
                                  key={leaf.key}
                                  role="treeitem"
                                  aria-level={3}
                                  aria-selected={leaf.key === selectedKey}
                                  className={cn("tree-row", leaf.key === selectedKey && "active")}
                                  style={{ paddingLeft: 36 }}
                                  onClick={() => setSelectedKey(leaf.key)}
                                >
                                  <span className="tree-toggle" />
                                  <span className="tree-row-icon" aria-hidden="true">
                                    <SeverityDot severity={leaf.finding.severity} />
                                  </span>
                                  <span className="tree-row-label" title={findingName(leaf.finding)}>
                                    {findingName(leaf.finding)}
                                  </span>
                                  <span className="tree-row-meta">
                                    <span className="cell-dim tree-row-params">{leaf.finding.confidence}</span>
                                  </span>
                                </div>
                              ))
                            : null}
                        </div>
                      );
                    })
                  : null}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );

  const advisory = selected ? (
    <div className="pane">
      <div className="detail-head">
        <div className="detail-head-title">
          <span className="eyebrow">
            {selected.finding.host}
            {selected.occurrence ? selected.occurrence.path : ""}
          </span>
          <h3>{findingName(selected.finding)}</h3>
        </div>
        <div className="detail-actions">
          <Badge tone={severityTone(selected.finding.severity)}>{selected.finding.severity}</Badge>
          <Badge tone={confidenceTone(selected.finding.confidence)}>{selected.finding.confidence}</Badge>
          {selected.occurrence ? (
            <Tooltip content="Open this exchange in HTTP history">
              <Button
                variant="outline"
                size="small"
                onClick={() => {
                  focusExchange(selected.occurrence?.exchange_id ?? null);
                  setRoute("history");
                }}
              >
                <ExternalLink size={13} />
                In history
              </Button>
            </Tooltip>
          ) : null}
        </div>
      </div>
      <Tabs defaultValue="advisory" className="tabs-fill">
        <TabsList>
          <TabsTrigger value="advisory">Advisory</TabsTrigger>
          <TabsTrigger value="request">Request</TabsTrigger>
          <TabsTrigger value="response">Response</TabsTrigger>
        </TabsList>
        <TabsContent value="advisory" className="advisory-body">
          <DetailList
            rows={[
              { label: "Check", value: selected.finding.check_name ?? "—" },
              { label: "Host", value: selected.finding.host || "—" },
              { label: "Path", value: selected.occurrence?.path ?? "—" },
              // Only rendered when the finding names a parameter: an insertion-point BCheck or a
              // DOM sink is attributable to one input, a resource-level finding is not, and a row
              // that can only ever say "—" is noise.
              ...(selected.finding.param
                ? [{ label: "Parameter", value: selected.finding.param }]
                : []),
              { label: "Times seen", value: selected.finding.times_seen },
              { label: "Occurrences", value: selected.finding.occurrences.length },
            ]}
          />
          <div>
            <h4>Issue detail</h4>
            <p className="prose">{selected.finding.detail ?? "no detail recorded"}</p>
          </div>
          <div>
            <h4>Remediation</h4>
            <p className="prose">{selected.finding.remediation ?? "no remediation recorded"}</p>
          </div>
          <AdvisoryPanel finding={selected.finding} />
          {selected.finding.occurrences.length > 1 ? (
            <div>
              <h4>All occurrences ({selected.finding.occurrences.length})</h4>
              <div className="actions">
                {selected.finding.occurrences.map((occurrence, index) => (
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
            </div>
          ) : null}
        </TabsContent>
        <TabsContent value="request" className="advisory-editor">
          {selected.occurrence === null ? (
            <Empty title="No request recorded" detail="This finding was not tied to a captured exchange." />
          ) : exchange === null ? (
            <Empty
              title="Exchange not in the loaded history"
              detail={`Finding points at exchange #${selected.occurrence.exchange_id}, which is outside the last 1000 captured.`}
            />
          ) : (
            <HttpEditor
              label="Request"
              readOnly
              value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
              filename={`finding-${selected.finding.id}-request.txt`}
            />
          )}
        </TabsContent>
        <TabsContent value="response" className="advisory-editor">
          {selected.occurrence === null ? (
            <Empty title="No response recorded" detail="This finding was not tied to a captured exchange." />
          ) : exchange === null ? (
            <Empty
              title="Exchange not in the loaded history"
              detail={`Finding points at exchange #${selected.occurrence.exchange_id}, which is outside the last 1000 captured.`}
            />
          ) : (
            <HttpEditor
              label="Response"
              readOnly
              value={
                exchange.response === null
                  ? "No response was captured for this exchange."
                  : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."))
              }
              filename={`finding-${selected.finding.id}-response.txt`}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  ) : (
    <Empty
      title="Select a finding"
      detail="Choose an issue in the tree to read its advisory and the exact request and response it was found in."
    />
  );

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Issues"
          actions={
            <>
              {severityCounts.map(({ severity: s, count }) => (
                <Badge key={s} tone={severityTone(s)} title={`${count} ${s} finding(s)`}>
                  {count} {s}
                </Badge>
              ))}
              <Tooltip content="Live audit, passive coverage, and targeted audit">
                <Button variant="outline" size="small" onClick={() => setSettingsOpen(true)}>
                  <SlidersHorizontal size={13} />
                  Audit settings
                </Button>
              </Tooltip>
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
        <Toolbar style={{ marginTop: 8 }}>
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

      <SplitPane storageId="issues" orientation="horizontal" defaultMasterSize="34" minMasterSize="20" master={treePane} detail={advisory} />

      <Modal open={settingsOpen} onOpenChange={setSettingsOpen} title="Audit settings" description="What the scanner runs, and what it has already covered." wide>
        <div className="stack">
          <LiveAuditCard />
          <CoverageCard />
          <div className="audit-strip">
            <div>
              <ShieldAlert size={20} />
              <span>
                <strong>Targeted audit</strong>
                <small>Run the configured checks against one captured exchange.</small>
              </span>
            </div>
            <Select aria-label="Scan configuration" value={configName} onChange={(event) => setConfigName(event.target.value)}>
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
        </div>
      </Modal>
    </div>
  );
}
