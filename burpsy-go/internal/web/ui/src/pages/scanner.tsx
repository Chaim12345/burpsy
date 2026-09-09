import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Copy, Download, ExternalLink, FileDown, Globe, SlidersHorizontal } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { useExchangeActions } from "../lib/actions";
import { useDebounced, useHistory, useMessage } from "../lib/data";
import { useIssueTriage, useIssuesDetailed } from "../lib/data.attack";
import { triageMenuGroups } from "../lib/issue-triage";
import { useApp } from "../lib/store";
import type { FindingDetail } from "../lib/types.attack";
import type { IssueTriagePatch } from "../lib/issue-triage";
import type { Occurrence } from "../lib/types";
import { AdvisoryReader } from "../ui/advisory";
import { HttpEditor } from "../ui/editor";
import { ContextMenu, type MenuGroup } from "../ui/menu";
import { LoadingPanel, PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import {
 Badge,
 Button,
 Checkbox,
 Empty,
 ErrorNotice,
 Input,
 LinkButton,
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

export function ScannerPage(): JSX.Element {
 const { data: issues, error, isFetching, refetch } = useIssuesDetailed();
 const focusExchange = useApp((state) => state.focusExchange);
 const setRoute = useApp((state) => state.setRoute);
 const setHistoryQuery = useApp((state) => state.setHistoryQuery);
 const actions = useExchangeActions();
 const triage = useIssueTriage();

 const [severities, setSeverities] = useState<Set<string>>(new Set());
 const [confidences, setConfidences] = useState<Set<string>>(new Set());
 const [hideFalsePositives, setHideFalsePositives] = useState(false);
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
  if (!window.confirm(`Delete "${findingName(finding)}" on ${finding.host}? A re-audit of the same endpoint will re-raise it.`)) return;
  triage.remove.mutate(finding.id, {
   onSuccess: () => {
    toast.success("Issue deleted");
    if (selectedKey?.startsWith(`${finding.id}:`)) setSelectedKey(null);
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not delete that issue"),
  });
 };

 const editComment = (finding: FindingDetail) => {
  const next = window.prompt(`Comment on "${findingName(finding)}"`, finding.comment);
  if (next === null || next === finding.comment) return;
  applyTriage(finding, { comment: next.trim() }, next.trim() === "" ? "Comment cleared" : "Comment saved");
 };

 const debouncedTerm = useDebounced(term, 260);
 // Same cache key the history tab uses: the advisory's Request/Response tabs need the message ids,
 // which a finding's occurrence does not carry.
 const { data: history } = useHistory("", 1000);

 const rows = useMemo(() => {
  const all = issues?.findings ?? [];
  const needle = debouncedTerm.trim().toLowerCase();
  return all
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
   });
 }, [issues, severities, confidences, hideFalsePositives, debouncedTerm]);

 const groups = useMemo(() => groupFindings(rows), [rows]);

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
     // The whole-scan exports, not a per-issue one: /api/report/{fmt} reports the scan, and
     // there is no per-finding report endpoint to point a single-issue entry at.
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
   </Toolbar>
   {isFetching && !issues ? (
    <LoadingPanel />
   ) : groups.length === 0 ? (
    <Empty
     title={term || severities.size > 0 || confidences.size > 0 || hideFalsePositives ? "No finding matches this filter" : "No findings yet"}
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
              <ContextMenu key={leaf.key} groups={menuForLeaf(leaf)}>
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
                 {/*
                                      A merged row covers several parameters, and the count is the
                                      one fact that distinguishes it from a single observation at a
                                      glance. Without it a five-parameter finding and a
                                      one-parameter finding are the same line, and the merge reads
                                      as though four results went missing.
                                    */}
                 {leaf.finding.params && leaf.finding.params.length > 1 ? (
                  <span
                   className="cell-dim tree-row-params"
                   title={`Affects ${leaf.finding.params.length} parameters: ${leaf.finding.params.join(", ")}`}
                  >
                   {leaf.finding.params.length} params
                  </span>
                 ) : null}
                 {/*
                                      A false-positive mark must not ride on colour alone (a struck
                                      label at tree density disappears into the strikethrough of
                                      long names), so the row carries the letters too. The title
                                      spells out what the mark means.
                                    */}
                 {leaf.finding.false_positive ? (
                  <span className="tree-row-params" title="Marked false positive by an operator">
                   FP
                  </span>
                 ) : null}
                 {leaf.finding.severity_override ? (
                  <span
                   className="tree-row-params"
                   title={`Severity overridden from ${leaf.finding.original_severity}`}
                  >
                   ⇩
                  </span>
                 ) : null}
                 <span className="cell-dim tree-row-params">{leaf.finding.confidence}</span>
                </span>
               </div>
              </ContextMenu>
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
     {/* The advisory pane's own heading, and the parent of the h3 sections inside it. It was
              an h3 sitting directly under the page's h1 with nothing at h2, which reads to a
              screen reader as a level gone missing. The <strong> keeps the console's pane-title
              treatment, which `.detail-head-title strong` already defines. */}
     <h2>
      <strong>{findingName(selected.finding)}</strong>
     </h2>
    </div>
    <div className="detail-actions">
     <Badge tone={severityTone(selected.finding.severity)}>{selected.finding.severity}</Badge>
     {/* The engine word rides alongside whenever an operator has overruled it: without it,
              "Informational" and "Informational, because an operator said so" render identically,
              and one of those is a decision worth arguing with. */}
     {selected.finding.original_severity ? (
      <Badge tone="neutral" title={`Engine severity, overridden by an operator`}>
       engine: {selected.finding.original_severity}
      </Badge>
     ) : null}
     <Badge tone={confidenceTone(selected.finding.confidence)}>{selected.finding.confidence}</Badge>
     {selected.finding.false_positive ? <Badge tone="warn">False positive</Badge> : null}
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
       //
       // Findings of one type against one target are merged into a single row, so this shows
       // every parameter the row covers rather than only the first observed. Showing one of
       // five would make the merge look like it had lost the other four. Singular label when
       // there is one, so the common case does not read as a list of one.
       ...(selected.finding.params && selected.finding.params.length > 1
        ? [
         {
          label: `Parameters (${selected.finding.params.length})`,
          value: selected.finding.params.join(", "),
         },
        ]
        : selected.finding.param
         ? [{ label: "Parameter", value: selected.finding.param }]
         : []),
       { label: "Times seen", value: selected.finding.times_seen },
       { label: "Occurrences", value: selected.finding.occurrences.length },
       // Triage state, shown only when there is something to show: a row of "no comment"
       // placeholders for every untouched finding trains the eye to skip the block.
       ...(selected.finding.original_confidence ? [{ label: "Engine confidence", value: selected.finding.original_confidence }] : []),
       ...(selected.finding.comment ? [{ label: "Operator comment", value: selected.finding.comment }] : []),
      ]}
     />
     <div>
      <h3>Issue detail</h3>
      <p className="prose">{selected.finding.detail ?? "no detail recorded"}</p>
     </div>
     <div>
      <h3>Remediation</h3>
      <p className="prose">{selected.finding.remediation ?? "no remediation recorded"}</p>
     </div>
     {/*
              The comment editor, in the pane as well as the context menu (burpsy-react-ui-pwd):
              comments are written while reading the advisory, and a right-click away is a
              round trip the writing does not survive. The block is keyed on the finding id, so
              switching findings resets the draft instead of leaking one finding's half-written
              note into the next pane — state that follows the selection is how the wrong issue
              gets annotated.
            */}
     <TriageCommentEditor
      key={selected.finding.id}
      finding={selected.finding}
      onSave={(comment) => applyTriage(selected.finding, { comment }, comment.trim() === "" ? "Comment cleared" : "Comment saved")}
     />
     {/* The catalogue entry the check resolved to, rendered by the same component the browsable
              Issue definitions screen uses. Passing the note as well as the advisory is what keeps
              "no catalogue entry, and here is why" distinct from "nothing looked". */}
     <AdvisoryReader advisory={selected.finding.advisory} note={selected.finding.advisory_note} />
     {selected.finding.occurrences.length > 1 ? (
      <div>
       <h3>All occurrences ({selected.finding.occurrences.length})</h3>
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
       filename={`finding-${selected.finding.id}-response.txt`}
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

  </div>
 );
}
