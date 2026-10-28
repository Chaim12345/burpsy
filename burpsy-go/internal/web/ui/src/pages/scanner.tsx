import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { filterByIssueSource, ISSUE_SOURCE_FILTERS, type IssueSourceFilter } from "../lib/issue-source-filter";
import { formatFoundAt, foundAtTitle } from "../lib/issue-provenance";
import {
 ChevronDown,
 ChevronRight,
 Copy,
 Download,
 ExternalLink,
 FileDown,
 Globe,
 Combine,
 SlidersHorizontal,
 Sparkles,
} from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { confirmDialog, promptDialog } from "../lib/dialogs";
import { usePluginExchangeActions } from "../lib/plugin-exchange-actions";
import { useDebounced, useHistory, useMessage } from "../lib/data";
import { useIssue, useIssueLLMTriage, useIssueTriage, useIssuesDetailed } from "../lib/data.attack";
import { triageMenuGroups } from "../lib/issue-triage";
import { useApp } from "../lib/store";
import type { FindingDetail } from "../lib/types.attack";
import type { IssueTriagePatch } from "../lib/issue-triage";
import type { Occurrence } from "../lib/types";
import { AdvisoryReader } from "../ui/advisory";
import { HttpEditor } from "../ui/editor";
import { ContextMenu, type MenuGroup } from "../ui/menu";
import { LoadingPanel, PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { ConsolidationDialog } from "../ui/consolidation-dialog";
import {
 DEFAULT_REPORT_SETTINGS,
 ReportSettingsDialog,
 reportSettingsActive,
 reportSettingsQuery,
 type ReportSettings,
} from "../ui/report-settings-dialog";
import {
 Badge,
 Button,
 Checkbox,
 Empty,
 ErrorNotice,
 Input,
 LinkButton,
 Select,
 Tabs,
 TabsContent,
 TabsList,
 TabsTrigger,
 Textarea,
 Toolbar,
 Tooltip,
 type Tone,
} from "../ui/primitives";
import { DetailList } from "../ui/json";
import { cn } from "../lib/cn";
import { severityTone } from "../lib/severity";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
const CONFIDENCES = ["Certain", "Firm", "Tentative"];
const SEVERITY_RANK: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 };
const REPORT_FORMATS = [
 { format: "html", label: "HTML" },
 { format: "xml", label: "XML" },
 { format: "json", label: "JSON" },
 { format: "sarif", label: "SARIF" },
];

function severityRank(severity: string): number {
 return SEVERITY_RANK[severity] ?? -1;
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

/**
 * The advisory pane's operator-comment editor (burpsy-react-ui-pwd). Local draft state — the save
 * button sends the whole editor's text as the new comment, and an empty draft sent deliberately
 * clears the comment, which is why the button reads "Clear comment" once there is one: both
 * directions are one write on the wire, and hiding that behind a separate control would make
 * clearing look different from editing when the server treats them identically.
 */
function TriageCommentEditor({ finding, onSave }: { finding: FindingDetail; onSave: (comment: string) => void }): JSX.Element {
 const [draft, setDraft] = useState(finding.comment);
 const unchanged = draft === finding.comment;
 return (
  <div>
   <h3>Operator comment</h3>
   <Textarea
    aria-label="Operator comment"
    value={draft}
    onChange={(event) => setDraft(event.target.value)}
    placeholder="A note for whoever works this issue next — why it was marked, what it duplicates…"
    rows={3}
   />
   <div className="actions">
    <Button variant="outline" size="small" disabled={unchanged} onClick={() => onSave(draft)}>
     {draft.trim() === "" && finding.comment ? "Clear comment" : "Save comment"}
    </Button>
    {finding.comment && !unchanged ? (
     <Button variant="ghost" size="small" onClick={() => setDraft(finding.comment)}>
      Discard
     </Button>
    ) : null}
   </div>
  </div>
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

type IssueTreeRow =
 | { kind: "host"; key: string; host: HostGroup; open: boolean }
 | { kind: "path"; key: string; host: string; path: PathGroup; open: boolean }
 | { kind: "leaf"; key: string; leaf: IssueLeaf };

/** Hosts, paths and leaves in the order the tree paints them, with collapsed branches omitted.
 * The Issues page virtualizes this list: a few thousand findings used to mount a context menu
 * per leaf, and that is what froze the console once the count grew. */
function flattenIssueTree(groups: HostGroup[], collapsed: Record<string, boolean>): IssueTreeRow[] {
 const out: IssueTreeRow[] = [];
 for (const host of groups) {
  const hostKey = `h:${host.host}`;
  const open = !collapsed[hostKey];
  out.push({ kind: "host", key: hostKey, host, open });
  if (!open) continue;
  for (const path of host.paths) {
   const pathKey = `p:${host.host}:${path.path}`;
   const pathOpen = !collapsed[pathKey];
   out.push({ kind: "path", key: pathKey, host: host.host, path, open: pathOpen });
   if (!pathOpen) continue;
   for (const leaf of path.leaves) out.push({ kind: "leaf", key: leaf.key, leaf });
  }
 }
 return out;
}

const NO_ISSUE_NAMES: string[] = [];

export function ScannerPage(): JSX.Element {
 const { data: issues, error, isFetching, refetch } = useIssuesDetailed();
 const focusExchange = useApp((state) => state.focusExchange);
 const setRoute = useApp((state) => state.setRoute);
 const setHistoryQuery = useApp((state) => state.setHistoryQuery);
 const actions = usePluginExchangeActions();
 const triage = useIssueTriage();
 // The LLM second look (ei0v): advice, never promotion. The sweep button lives in the
 // pane toolbar; the per-finding hand lives in the leaf menu.
 const llmTriage = useIssueLLMTriage();

 const [severities, setSeverities] = useState<Set<string>>(new Set());
 const [confidences, setConfidences] = useState<Set<string>>(new Set());
 const [hideFalsePositives, setHideFalsePositives] = useState(false);
 const [consolidationOpen, setConsolidationOpen] = useState(false);
 // Report settings (burpsy-react-ui-a9qy): Burp's reporting-wizard choices,
 // applied to the export links below. Session state, like the wizard - each
 // export is configured for itself, not persisted as a tool preference.
 const [reportSettings, setReportSettings] = useState<ReportSettings>(DEFAULT_REPORT_SETTINGS);
 const [reportSettingsOpen, setReportSettingsOpen] = useState(false);
 // The source facet (burpsy-react-ui-exiu): which producer raised a finding. Two states only —
 // see lib/issue-source-filter for why this does not split BCheck from a native check.
 const [sourceFilter, setSourceFilter] = useState<IssueSourceFilter>("");
 // A host substring for the report export only (burpsy-react-ui-8r6): "the findings on this
 // host" without reshaping the tree.
 const [hostReportFilter, setHostReportFilter] = useState("");
 const [term, setTerm] = useState("");
 const [selectedKey, setSelectedKey] = useState<string | null>(null);
 const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
 // Another page asked to select one finding (the Dashboard's Issue activity feed is the first
 // sender). Consumed exactly like History's historyFocus: read, act, clear — the flag is
 // session-only, and leaving it set would re-select on every return to this page.
 const issueFocus = useApp((state) => state.issueFocus);
 const focusIssue = useApp((state) => state.focusIssue);

 /**
  * One triage write, one toast (burpsy-react-ui-pwd). A refusal is surfaced rather than swallowed:
  * a false-positive mark that silently failed comes back on the next refetch as an unfixed
  * finding, which reads as the operator's edit being ignored.
  */
 const applyTriage = (finding: FindingDetail, patch: IssueTriagePatch, message: string) => {
  triage.triage.mutate(
   { id: finding.id, patch },
   {
    onSuccess: () => toast.success(message),
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not save that triage change"),
   },
  );
 };

 /** Deletion is the one irreversible triage act, so it asks — Burp's own "Delete issue" does. */
 const removeFinding = (finding: FindingDetail) => {
  void confirmDialog({
   title: `Delete "${findingName(finding)}"?`,
   description: `On ${finding.host}. A re-audit of the same endpoint will re-raise it.`,
   confirmLabel: "Delete issue",
   cancelLabel: "Keep it",
   danger: true,
  }).then((confirmed) => {
   if (confirmed) deleteFinding(finding);
  });
 };

 const deleteFinding = (finding: FindingDetail) => {
  triage.remove.mutate(finding.id, {
   onSuccess: () => {
    toast.success("Issue deleted");
    if (selectedKey?.startsWith(`${finding.id}:`)) setSelectedKey(null);
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not delete that issue"),
  });
 };

 const editComment = (finding: FindingDetail) => {
  void promptDialog({
   title: `Comment on "${findingName(finding)}"`,
   description: "An empty comment clears it.",
   label: "Comment",
   initial: finding.comment,
   confirmLabel: "Save comment",
   allowEmpty: true,
  }).then((next) => {
   if (next === null || next === finding.comment) return;
   applyTriage(finding, { comment: next.trim() }, next.trim() === "" ? "Comment cleared" : "Comment saved");
  });
 };

 const debouncedTerm = useDebounced(term, 260);
 // Same cache key the history tab uses: the advisory's Request/Response tabs need the message ids,
 // which a finding's occurrence does not carry.
 const { data: history } = useHistory("", 1000);

 const rows = useMemo(() => {
  // The source facet narrows the pool before anything else reads it, so every other filter — and
  // the tree, and the empty state — sees one list.
  const all = filterByIssueSource(issues?.findings ?? [], sourceFilter);
  const needle = debouncedTerm.trim().toLowerCase();
  return (
   all
    // Burp's "Show only" checkboxes (burpsy-react-ui-4d5c): an empty set shows everything, a
    // non-empty one is an allow-list, so High+Medium can be shown while Low+Info are not.
    // False positives are opt-out like Burp's hide-false-positive — they stay listed by
    // default because the operator marked them deliberately.
    .filter((f) => severities.size === 0 || severities.has(f.severity))
    .filter((f) => confidences.size === 0 || confidences.has(f.confidence))
    .filter((f) => !hideFalsePositives || !f.false_positive)
    .filter((f) => {
     if (!needle) return true;
     const haystack = `${f.check_name ?? ""} ${f.issue_name ?? ""} ${f.host} ${f.detail ?? ""}`.toLowerCase();
     return haystack.includes(needle);
    })
  );
 }, [issues, severities, confidences, hideFalsePositives, sourceFilter, debouncedTerm]);

 const groups = useMemo(() => groupFindings(rows), [rows]);
 // Only the consolidation dialog reads these, so a closed dialog must not walk every finding on
 // each render (a scroll re-renders this page; with tens of thousands of findings that walk,
 // a Set and a sort ran per scroll tick).
 const issueNames = useMemo(
  () => (consolidationOpen ? [...new Set((issues?.findings ?? []).flatMap((finding) => (finding.check_name ? [finding.check_name] : [])))].sort() : NO_ISSUE_NAMES),
  [consolidationOpen, issues],
 );
 const flatRows = useMemo(() => flattenIssueTree(groups, collapsed), [groups, collapsed]);
 const treeRef = useRef<HTMLDivElement>(null);
 const rowVirtualizer = useVirtualizer({
  count: flatRows.length,
  getScrollElement: () => treeRef.current,
  estimateSize: () => 32,
  overscan: 16,
 });
 useEffect(() => {
  if (!selectedKey) return;
  const index = flatRows.findIndex((row) => row.kind === "leaf" && row.key === selectedKey);
  if (index >= 0) rowVirtualizer.scrollToIndex(index, { align: "auto" });
  // The virtualizer's identity is stable for one scroll element; depending on it loops.
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [selectedKey, flatRows]);

 useEffect(() => {
  if (issueFocus === null) return;
  // Clear only once the finding is actually selectable. `groups` is empty while /api/issues is
  // still fetching (a cold-cache deep-link from the Dashboard feed navigates before data lands),
  // and clearing there would drop the request — the operator arrives on Issues with nothing
  // selected and no way to know why.
  // The leaf key is `${finding.id}:...` (groupFindings) — startsWith matches the finding's first
  // leaf, which is the one to open: an advisory is per-finding, occurrences are beneath it.
  let found = false;
  for (const host of groups) {
   for (const path of host.paths) {
    const leaf = path.leaves.find((l) => l.key.startsWith(`${issueFocus}:`));
    if (leaf) {
     setSelectedKey(leaf.key);
     found = true;
     // Expand the host and path the leaf sits under, so the selection is visible, not folded.
     setCollapsed((current) => {
      const next = { ...current };
      // The tree's own keys: `h:<host>` and `p:<host>:<path>` (renderTree below).
      delete next[`h:${host.host}`];
      delete next[`p:${host.host}:${path.path}`];
      return next;
     });
     break;
    }
   }
  }
  if (found) focusIssue(null);
  // Data loaded but the id is not in it (deleted, or outside the loaded set): give up once rather
  // than leaving the flag set — but only when data EXISTS. While `issues` is undefined the fetch
  // has not landed, so the flag survives to the next run of this effect and the deep-link still
  // opens when the findings arrive.
  else if (issues !== undefined) focusIssue(null);
 }, [issueFocus, groups, focusIssue, issues]);

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

 // The export query (burpsy-react-ui-8r6): the file carries what the tree shows — severity,
 // false-positive exclusion, plus an optional host substring that is an export-only axis.
 // The count in the links' tooltip says what the file will contain, because a download that
 // silently carries 200 rows when the tree shows 3 is exactly the mismatch this fixes.
 // Confidence filtering and the search term stay view-only — the API does not take them —
 // and when either is active the tooltip says so rather than claiming "the tree's current
 // filter" over a file that holds more rows than the tree shows (burpsy-react-ui-zqrm,
 // finding 2: the count and the file must not diverge silently).
 const viewOnlyActive = confidences.size > 0 || debouncedTerm.trim() !== "";
 const exportScope = viewOnlyActive
  ? `the export carries the severity, false-positive and host axes only — the ${[
     confidences.size > 0 ? "confidence filter" : null,
     debouncedTerm.trim() ? "search term" : null,
    ]
     .filter(Boolean)
     .join(" and ")} applies to the view, not the file`
  : "the tree's current filter";
 const reportQuery = useMemo(() => {
  const params = new URLSearchParams();
  if (severities.size > 0) params.set("severity", [...severities].join(","));
  if (hostReportFilter.trim()) params.set("host", hostReportFilter.trim());
  if (hideFalsePositives) params.set("exclude_false_positives", "true");
  const qs = params.toString();
  return qs ? `?${qs}` : "";
 }, [severities, hostReportFilter, hideFalsePositives]);
 // One href per format: the filter query the tree already builds, plus the
 // report settings this format actually consumes (title, organisation and
 // TOC depth are HTML-only; sections and messages reach XML too).
 const exportHrefQuery = (format: string) => {
  const filterQS = reportQuery.replace(/^\?/, "");
  const settingsQS = reportSettingsQuery(reportSettings, format);
  const qs = [filterQS, settingsQS].filter(Boolean).join("&");
  return qs ? "?" + qs : "";
 };

 const exchange = useMemo(() => {
  const id = selected?.occurrence?.exchange_id;
  if (id === undefined) return null;
  return (history ?? []).find((ex) => ex.id === id) ?? null;
 }, [history, selected]);
 const request = useMessage(exchange?.request);
 const response = useMessage(exchange?.response ?? null);

 /**
  * The issue-triage menu, on a tree leaf.
  *
  * # What is here
  *
  * Burp's issue context menu carries Set severity, Set confidence, Add comment, False positive,
  * Report issue, Go to issue and Delete issue. The triage five (burpsy-react-ui-pwd) now exist:
  * PUT/DELETE /api/issues/{id} are real write paths, so the menu builds them via
  * triageMenuGroups rather than offering entries that would drop the choice on the floor.
  *
  * What is here: Burp's "Go to issue" (both directions — the finding's exchange in HTTP history,
  * and the host filtered in history), its "Report issue" as the three report exports the command
  * palette already offers, the copies an operator writing a ticket needs, and — when the
  * finding's exchange is inside the loaded window — the full cross-tool matrix on that exchange,
  * because retesting a finding means sending its request to Repeater.
  *
  * The exchange is resolved per leaf rather than reused from the selection: right-clicking a leaf
  * that is not selected must act on the leaf under the pointer.
  */
 const menuForLeaf = (leaf: IssueLeaf): MenuGroup[] => {
  const finding = leaf.finding;
  const exchangeId = leaf.occurrence?.exchange_id;
  const leafExchange = exchangeId === undefined ? null : ((history ?? []).find((ex) => ex.id === exchangeId) ?? null);
  const groups: MenuGroup[] = [
   ...triageMenuGroups(finding, {
    apply: (patch, message) => applyTriage(finding, patch, message),
    editComment: () => editComment(finding),
    remove: () => removeFinding(finding),
   }),
   {
    id: "llm-triage",
    actions: [
     {
      id: "llm-second-look",
      label: "LLM second look",
      icon: Sparkles,
      disabled: llmTriage.one.isPending,
      onSelect: () => {
       llmTriage.one.mutate(finding.id, {
        onSuccess: () => toast.success("Second look attached — the note rides beside the severity, it never moves it"),
        onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "The second look failed"),
       });
      },
     },
    ],
   },
   {
    id: "goto",
    actions: [
     ...(exchangeId === undefined
      ? []
      : [
         {
          id: "goto-exchange",
          label: `Show exchange #${exchangeId} in HTTP history`,
          icon: ExternalLink,
          onSelect: () => {
           focusExchange(exchangeId);
           setRoute("history");
          },
         },
        ]),
     {
      id: "goto-host",
      label: `Filter history by ${finding.host}`,
      icon: Globe,
      onSelect: () => {
       setHistoryQuery(`host = ${finding.host}`);
       setRoute("history");
      },
     },
    ],
   },
   {
    id: "copy",
    actions: [
     {
      id: "copy-name",
      label: "Copy issue name",
      icon: Copy,
      onSelect: () => {
       void copyToClipboard(findingName(finding));
       toast.success("Issue name copied");
      },
     },
     {
      id: "copy-location",
      label: "Copy issue location",
      icon: Copy,
      onSelect: () => {
       void copyToClipboard(`${findingName(finding)} — ${finding.host}${leaf.occurrence?.path ?? ""}`);
       toast.success("Issue location copied");
      },
     },
     {
      id: "copy-detail",
      label: "Copy issue detail",
      icon: Copy,
      disabled: !finding.detail,
      onSelect: () => {
       void copyToClipboard(finding.detail ?? "");
       toast.success("Issue detail copied");
      },
     },
    ],
   },
   {
    id: "report",
    title: "Report",
    actions: [
     // THIS finding, with the bytes behind it (burpsy-react-ui-exiu). The scan-wide exports below
     // describe the whole scan and their Evidence entries carry only a method, host, path and
     // status — a description of a finding is not evidence for it, and an assessor handed one still
     // has to assemble the request and response by hand. This one carries them.
     {
      id: "this-finding",
      label: "Export this issue (with evidence)",
      icon: FileDown,
      onSelect: () => window.open(`/api/report/finding/${finding.id}`, "_blank"),
     },
     // The whole-scan exports, unchanged: a scan of a large project has thousands of rows and
     // their request bodies between them, and inlining those would make the document unusable as a
     // document. That split is why the entry above exists.
     { id: "html", label: "Export scan report (HTML)", icon: FileDown, onSelect: () => window.open("/api/report/html", "_blank") },
     { id: "json", label: "Export scan report (JSON)", icon: FileDown, onSelect: () => window.open("/api/report/json", "_blank") },
     { id: "sarif", label: "Export scan report (SARIF)", icon: FileDown, onSelect: () => window.open("/api/report/sarif", "_blank") },
    ],
   },
  ];
  return leafExchange ? [...groups, ...actions.menu(leafExchange)] : groups;
 };

 const treePane = (
  <div className="pane">
   <Toolbar className="pane-toolbar">
    <Input
     aria-label="Filter findings"
     title="Filter findings"
     value={term}
     onChange={(event) => setTerm(event.target.value)}
     placeholder="Filter by check, issue, host or detail"
    />
    {/* The source facet (burpsy-react-ui-exiu). "Manual" means nothing tracked it — a recording a
        person added, or a result imported from elsewhere — which is a different claim from "a run
        raised this" and had no way to be told apart before. Burp splits this further by BCheck /
        Scan check / Extension; this does not, because the finding does not record which and a guess
        from the check name would be an unverifiable claim in a filter. */}
    <Select
     aria-label="Filter by source"
     title="Filter by what raised the finding"
     value={sourceFilter}
     onChange={(event) => setSourceFilter(event.target.value as IssueSourceFilter)}
    >
     {ISSUE_SOURCE_FILTERS.map((option) => (
      <option key={option.value || "all"} value={option.value}>
       {option.label}
      </option>
     ))}
    </Select>
   </Toolbar>
   {isFetching && !issues ? (
    <LoadingPanel />
   ) : groups.length === 0 ? (
    <Empty
     title={
      term || severities.size > 0 || confidences.size > 0 || hideFalsePositives || sourceFilter
       ? "No finding matches this filter"
       : "No findings yet"
     }
     detail={issues?.hint ?? "Captured and audited traffic has not produced findings."}
    />
   ) : (
    <div ref={treeRef} className="row-list tree-pane" role="tree" aria-label="Findings by host and path">
     <div style={{ height: rowVirtualizer.getTotalSize(), width: "100%", position: "relative" }}>
      {rowVirtualizer.getVirtualItems().map((virtualRow) => {
       const row = flatRows[virtualRow.index];
       if (!row) return null;
       const place = {
        position: "absolute" as const,
        top: 0,
        left: 0,
        width: "100%",
        transform: `translateY(${virtualRow.start}px)`,
       };
       if (row.kind === "host") {
        return (
         <div
          key={row.key}
          data-index={virtualRow.index}
          ref={rowVirtualizer.measureElement}
          role="treeitem"
          aria-level={1}
          aria-expanded={row.open}
          className="tree-row"
          style={{ ...place, paddingLeft: 8 }}
          onClick={() => setCollapsed((c) => ({ ...c, [row.key]: row.open }))}
         >
          <button type="button" className="tree-toggle" aria-label={row.open ? `Collapse ${row.host.host}` : `Expand ${row.host.host}`}>
           {row.open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
          <span className="tree-row-icon" aria-hidden="true">
           <Globe size={12} />
          </span>
          <span className="tree-row-label" title={row.host.host}>
           {row.host.host}
          </span>
          <span className="tree-row-meta">
           <span className="tree-row-count cell-num">{row.host.count}</span>
          </span>
         </div>
        );
       }
       if (row.kind === "path") {
        return (
         <div
          key={row.key}
          data-index={virtualRow.index}
          ref={rowVirtualizer.measureElement}
          role="treeitem"
          aria-level={2}
          aria-expanded={row.open}
          className="tree-row"
          style={{ ...place, paddingLeft: 22 }}
          onClick={() => setCollapsed((c) => ({ ...c, [row.key]: row.open }))}
         >
          <button type="button" className="tree-toggle" aria-label={row.open ? `Collapse ${row.path.path}` : `Expand ${row.path.path}`}>
           {row.open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
          <span className="tree-row-icon" aria-hidden="true" />
          <span className="tree-row-label" title={row.path.path}>
           {row.path.path}
          </span>
          <span className="tree-row-meta">
           <span className="tree-row-count cell-num">{row.path.leaves.length}</span>
          </span>
         </div>
        );
       }
       const leaf = row.leaf;
       return (
        <div key={row.key} data-index={virtualRow.index} ref={rowVirtualizer.measureElement} style={place}>
         <ContextMenu groups={menuForLeaf(leaf)} docTopic="issues">
          <div
           role="treeitem"
           aria-level={3}
           aria-selected={leaf.key === selectedKey}
           className={cn("tree-row", leaf.key === selectedKey && "active", leaf.finding.false_positive && "tree-row-false-positive")}
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
            {leaf.finding.params && leaf.finding.params.length > 1 ? (
             <span className="cell-dim tree-row-params" title={`Affects ${leaf.finding.params.length} parameters: ${leaf.finding.params.join(", ")}`}>
              {leaf.finding.params.length} params
             </span>
            ) : null}
            {leaf.finding.false_positive ? (
             <span className="tree-row-params" title="Marked false positive by an operator">
              FP
             </span>
            ) : null}
            {leaf.finding.severity_override ? (
             <span className="tree-row-params" title={`Severity overridden from ${leaf.finding.original_severity}`}>
              ⇩
             </span>
            ) : null}
            <span className="cell-dim tree-row-params">{leaf.finding.confidence}</span>
            <span
             className="cell-dim tree-row-params"
             title={
              leaf.finding.source === "manual"
               ? "Recorded outside a run — no task raised this"
               : leaf.finding.task_id
                 ? `Raised by task ${leaf.finding.task_id}`
                 : "Raised by a run that did not record which"
             }
            >
             {leaf.finding.source === "manual" ? "manual" : "scan"}
            </span>
            <span className="cell-dim tree-row-params" title={foundAtTitle(leaf.finding.timestamp_unix_ms)}>
             {formatFoundAt(leaf.finding.timestamp_unix_ms)}
            </span>
           </span>
          </div>
         </ContextMenu>
        </div>
       );
      })}
     </div>
    </div>
   )}
  </div>
 );

 // The list is a summary. Detail, remediation and the catalogue advisory are one finding,
 // fetched when the row is opened, so the tree does not wait on every issue's prose.
 const openIssue = useIssue(selected?.finding.id ?? null);
 const shown = openIssue.data ?? selected?.finding ?? null;
 const advisory = selected && shown ? (
  <div className="pane">
   <div className="detail-head">
    <div className="detail-head-title">
     <span className="eyebrow">
      {shown.host}
      {selected.occurrence ? selected.occurrence.path : ""}
     </span>
     {/* The advisory pane's own heading, and the parent of the h3 sections inside it. It was
              an h3 sitting directly under the page's h1 with nothing at h2, which reads to a
              screen reader as a level gone missing. The <strong> keeps the console's pane-title
              treatment, which `.detail-head-title strong` already defines. */}
     <h2>
      <strong>{findingName(shown)}</strong>
     </h2>
    </div>
    <div className="detail-actions">
     <Badge tone={severityTone(shown.severity)}>{shown.severity}</Badge>
     {/* The engine word rides alongside whenever an operator has overruled it: without it,
              "Informational" and "Informational, because an operator said so" render identically,
              and one of those is a decision worth arguing with. */}
     {shown.original_severity ? (
      <Badge tone="neutral" title={`Engine severity, overridden by an operator`}>
       engine: {shown.original_severity}
      </Badge>
     ) : null}
     <Badge tone={confidenceTone(shown.confidence)}>{shown.confidence}</Badge>
     {shown.false_positive ? <Badge tone="warn">False positive</Badge> : null}
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
       { label: "Check", value: shown.check_name ?? "—" },
       { label: "Host", value: shown.host || "—" },
       { label: "Path", value: selected.occurrence?.path ?? "—" },
       // Only rendered when the finding names a parameter: an insertion-point BCheck or a
       // DOM sink is attributable to one input, a resource-level finding is not, and a row
       // that can only ever say "—" is noise.
       //
       // Findings of one type against one target are merged into a single row, so this shows
       // every parameter the row covers rather than only the first observed. Showing one of
       // five would make the merge look like it had lost the other four. Singular label when
       // there is one, so the common case does not read as a list of one.
       ...(shown.params && shown.params.length > 1
        ? [
           {
            label: `Parameters (${shown.params.length})`,
            value: shown.params.join(", "),
           },
          ]
        : shown.param
          ? [{ label: "Parameter", value: shown.param }]
          : []),
       { label: "Times seen", value: shown.times_seen },
       // How many later reports of this issue were merged into it (oorl) — shown only when some
       // were, so a finding seen once does not carry a row of zeros.
       ...((shown.merged_count ?? 0) > 0 ? [{ label: "Duplicates merged", value: shown.merged_count ?? 0 }] : []),
       // The quoted excerpt — for a leaked secret, the redacted key that says WHICH one (8j0d).
       ...(shown.evidence ? [{ label: "Evidence", value: shown.evidence }] : []),
       { label: "Occurrences", value: shown.occurrences.length },
       // Triage state, shown only when there is something to show: a row of "no comment"
       // placeholders for every untouched finding trains the eye to skip the block.
       ...(shown.original_confidence ? [{ label: "Engine confidence", value: shown.original_confidence }] : []),
       ...(shown.comment ? [{ label: "Operator comment", value: shown.comment }] : []),
      ]}
     />
     <div>
      <h3>Issue detail</h3>
      <p className="prose">
       {openIssue.data
        ? (openIssue.data.detail ?? "no detail recorded")
        : openIssue.isError
          ? "The issue record could not be loaded."
          : "Loading the issue record…"}
      </p>
     </div>
     <div>
      <h3>Remediation</h3>
      <p className="prose">
       {openIssue.data ? (openIssue.data.remediation ?? "no remediation recorded") : openIssue.isError ? "The issue record could not be loaded." : "Loading the issue record…"}
      </p>
     </div>
     {/*
              The comment editor, in the pane as well as the context menu (burpsy-react-ui-pwd):
              comments are written while reading the advisory, and a right-click away is a
              round trip the writing does not survive. The block is keyed on the finding id, so
              switching findings resets the draft instead of leaking one finding's half-written
              note into the next pane — state that follows the selection is how the wrong issue
              gets annotated. It waits for the full record: the list row has no comment, and
              seeding the editor from that empty string would keep the empty draft after the
              real comment arrived.
            */}
     {openIssue.data ? (
      <TriageCommentEditor
       key={`${openIssue.data.id}:${openIssue.data.comment}`}
       finding={openIssue.data}
       onSave={(comment) => {
        const record = openIssue.data;
        if (!record) return;
        applyTriage(record, { comment }, comment.trim() === "" ? "Comment cleared" : "Comment saved");
       }}
      />
     ) : null}
     {/* The catalogue entry the check resolved to, rendered by the same component the browsable
              Issue definitions screen uses. Passing the note as well as the advisory is what keeps
              "no catalogue entry, and here is why" distinct from "nothing looked". */}
     {openIssue.data ? <AdvisoryReader advisory={openIssue.data.advisory} note={openIssue.data.advisory_note} /> : null}
     {shown.occurrences.length > 1 ? (
      <div>
       <h3>All occurrences ({shown.occurrences.length})</h3>
       <div className="actions">
        {shown.occurrences.map((occurrence, index) => (
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
       bodyBase64={request.data?.body_base64}
       filename={`finding-${shown.id}-request.txt`}
       menuGroups={actions.menu(exchange)}
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
       bodyBase64={response.data?.body_base64}
       requestPath={exchange.path}
       filename={`finding-${shown.id}-response.txt`}
       menuGroups={actions.menu(exchange)}
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
       {/* burpsy-react-ui-1yd: the launch controls (live audit, targeted audit, the check
                  switches) moved to the Scanner leaf, so a scan is started from one surface. */}
       <Button variant="outline" size="small" onClick={() => setRoute("scannerlaunch")}>
        <SlidersHorizontal size={13} />
        Scanner controls
       </Button>
       {/* burpsy-react-ui-oorl: keep existing / keep both / keep new on a duplicate issue. */}
       <Button variant="outline" size="small" onClick={() => setConsolidationOpen(true)}>
        <Combine size={13} />
        Consolidation
       </Button>
       <Input
        aria-label="Report host filter"
        value={hostReportFilter}
        onChange={(event) => setHostReportFilter(event.target.value)}
        placeholder="report host filter…"
        style={{ maxWidth: "var(--w-sm)" }}
       />
       <Button variant="outline" size="small" onClick={() => setReportSettingsOpen(true)}>
        <SlidersHorizontal size={13} />
        Report settings{reportSettingsActive(reportSettings) ? " *" : ""}
       </Button>
       {REPORT_FORMATS.map((f) => (
        <LinkButton
         key={f.format}
         // The settings this format consumes, composed with the filter query:
         // title, organisation and TOC depth are HTML-only; the sections and
         // the message choices reach the XML export too. JSON and SARIF take
         // neither - a parameter that quietly did nothing is worse than absent.
         href={`/api/report/${f.format}${exportHrefQuery(f.format)}`}
         download
         title={`Exports ${rows.length.toLocaleString()} finding(s) — ${exportScope}${hostReportFilter.trim() ? ` on hosts matching “${hostReportFilter.trim()}”` : ""}${reportSettingsActive(reportSettings) ? " - report settings applied" : ""}`}
        >
         <Download size={13} />
         {f.label}
        </LinkButton>
       ))}
       <RefreshButton onClick={() => void refetch()} loading={isFetching} />
      </>
     }
    />
    <Toolbar style={{ marginTop: 8 }}>
     {/* Burp's Issues filter bar (burpsy-react-ui-4d5c): "Show only" checkboxes that
                combine, so High+Medium can be shown while Low+Info are not, plus
                hide-false-positive. An empty set means no constraint, which keeps the bar
                honest: nothing ticked shows everything, not nothing. */}
     <span className="filter-group" role="group" aria-label="Show only severity">
      <span className="filter-group-label">Show only</span>
      {SEVERITIES.map((s) => (
       <Checkbox
        key={s}
        label={s}
        checked={severities.has(s)}
        onCheckedChange={(on) =>
         setSeverities((current) => {
          const next = new Set(current);
          if (on) next.add(s);
          else next.delete(s);
          return next;
         })
        }
       />
      ))}
     </span>
     <span className="filter-group" role="group" aria-label="Show only confidence">
      <span className="filter-group-label">Confidence</span>
      {CONFIDENCES.map((c) => (
       <Checkbox
        key={c}
        label={c}
        checked={confidences.has(c)}
        onCheckedChange={(on) =>
         setConfidences((current) => {
          const next = new Set(current);
          if (on) next.add(c);
          else next.delete(c);
          return next;
         })
        }
       />
      ))}
     </span>
     <Checkbox label="Hide false positives" checked={hideFalsePositives} onCheckedChange={setHideFalsePositives} />
     <Badge>{rows.length.toLocaleString()} finding(s)</Badge>
    </Toolbar>
    {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
    {issues && !issues.enabled ? <div className="notice notice-warn">{issues.hint ?? "passive scanning is not enabled"}</div> : null}
   </div>

   <SplitPane storageId="issues" orientation="horizontal" defaultMasterSize="34" minMasterSize="20" master={treePane} detail={advisory} />

   <ReportSettingsDialog
    open={reportSettingsOpen}
    onOpenChange={setReportSettingsOpen}
    settings={reportSettings}
    onApply={setReportSettings}
   />
   <ConsolidationDialog
    open={consolidationOpen}
    onOpenChange={setConsolidationOpen}
    issueNames={issueNames}
   />
  </div>
 );
}
