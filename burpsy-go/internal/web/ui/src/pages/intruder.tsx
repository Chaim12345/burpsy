import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, ArrowRightLeft, Combine, Copy, Crosshair, Download, FileSearch, Pause, Play, Plus, Repeat2, RotateCcw, Search, Square, Trash2, X, Zap } from "lucide-react";
import { toast } from "sonner";
import { api, copyToClipboard, downloadText, formatBytes, formatCount, formatDuration, statusTone } from "../lib/api";
import { fetchRaw } from "../lib/actions";
import {
  intruderExportFilenames,
  intruderPayloadResolver,
  intruderReportToCSV,
  payloadLabel,
} from "../lib/intruder-export";
import {
  AttackActionStale,
  useIntruderAttackAction,
  useIntruderAttacks,
  useIntruderPoints,
  useIntruderRun,
  type IntruderRunRequest,
  useWordlists,
} from "../lib/data.tools";
import { usePools } from "../lib/data.pools";
import { useMessage } from "../lib/data";
import { addManualSpan, displayText, selectionToRawSpan } from "../lib/intruder-marks";
import { delayVariationFields } from "../lib/intruder-variation";
import { filterTableRows } from "../lib/table-filter";
import {
  DEFAULT_PAYLOADS,
  emptyIntruderConfig,
  useApp,
  type IntruderConfig,
  type IntruderPayloadSnapshot,
} from "../lib/store";
import {
  ATTACK_MODES,
  HASH_ALGORITHMS,
  PAYLOAD_LAYERS,
  PAYLOAD_RULES,
  customIteratorSize,
  customIteratorSlots,
  dateSetSize,
  emptyRule,
  estimateRequests,
  attackProgress,
  quoteRegex,
  parseCharSubstitutions,
  FOLLOW_REDIRECTS_MODES,
  type Attempt,
  type AttackMode,
  type ErrorBucket,
  type FollowRedirectsMode,
  type IntruderAttacksResp,
  type PayloadRuleName,
  type PayloadRuleSpec,
  type PayloadSetReport,
  type ResolvedPayload,
  type ResultBucket,
  type RunView,
  type SetSize,
} from "../lib/types.tools";
import { HttpEditor } from "../ui/editor";
import { PageHeader, SectionHeading } from "../ui/layout";
import { JsonView } from "../ui/json";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Empty,
  ErrorNotice,
  Field,
  IconButton,
  Input,
  Select,
  Switch,
  Modal,
  Textarea,
  Tooltip,
} from "../ui/primitives";
import { SortableTable, type Column } from "../ui/table";
import type { MenuGroup } from "../ui/menu";

/**
 * The filter field above each result table, with the honest count (burpsy-react-ui-4rd).
 *
 * The filter is client-side over the rows the server already sent, so "N of M" is
 * exact rather than a page-sized sample, and a filter that hides everything says so
 * instead of leaving an empty-looking table that reads as "no results".
 */
function ResultFilter({
  label,
  value,
  onChange,
  shown,
  total,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  shown: number;
  total: number;
}): JSX.Element {
  return (
    <div className="results-filter">
      <div className="search-field">
        <Search size={15} />
        <Input
          aria-label={label}
          title={label}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder="Filter rows"
        />
        {value ? (
          <IconButton label={`Clear ${label.toLowerCase()}`} size="small" onClick={() => onChange("")}>
            <X size={13} />
          </IconButton>
        ) : null}
      </div>
      {value ? (
        <span className="cell-dim">
          {formatCount(shown)} of {formatCount(total)} rows
        </span>
      ) : null}
    </div>
  );
}

function countPayloads(text: string): number {
  return text.split("\n").filter((line) => line.trim() !== "").length;
}

function payloadList(text: string): string[] {
  return text.split("\n").filter((line) => line.trim() !== "");
}

/**
 * Renders an attempt's `time_of_day` (an RFC 3339 string) the way the rest of this app renders a
 * wall-clock moment (collaborator.tsx, extensions.tsx: `toLocaleTimeString()`), never
 * "Invalid Date" for a value this browser cannot parse — an older server that omitted the field
 * would otherwise render the literal string `Invalid Date` in every row.
 */
function formatTimeOfDay(iso: string): string {
  const at = new Date(iso);
  return Number.isNaN(at.getTime()) ? "—" : at.toLocaleTimeString();
}

/** Editor for one payload processing rule; the visible fields depend on the rule. */
function RuleRow({
  rule,
  index,
  onChange,
  onRemove,
}: {
  rule: PayloadRuleSpec;
  index: number;
  onChange: (next: PayloadRuleSpec) => void;
  onRemove: () => void;
}): JSX.Element {
  const spec = PAYLOAD_RULES.find((entry) => entry.value === rule.rule);
  const uses = spec?.uses ?? [];
  return (
    <div className="rule-row">
      <span className="cell-dim">{index + 1}</span>
      <Select
        aria-label={`Rule ${index + 1} operation`}
        value={rule.rule}
        onChange={(event) => onChange({ ...emptyRule(event.target.value as PayloadRuleName) })}
      >
        {PAYLOAD_RULES.map((entry) => (
          <option key={entry.value} value={entry.value}>
            {entry.label}
          </option>
        ))}
      </Select>
      {uses.includes("text") ? (
        <Input
          aria-label={`Rule ${index + 1} text`}
          placeholder="text"
          value={rule.text}
          onChange={(event) => onChange({ ...rule, text: event.target.value })}
        />
      ) : null}
      {uses.includes("pattern") ? (
        <Input
          aria-label={`Rule ${index + 1} pattern`}
          placeholder="regex pattern"
          value={rule.pattern}
          onChange={(event) => onChange({ ...rule, pattern: event.target.value })}
        />
      ) : null}
      {uses.includes("replace") ? (
        <Input
          aria-label={`Rule ${index + 1} replacement`}
          placeholder="replacement ($1 for a group)"
          value={rule.replace}
          onChange={(event) => onChange({ ...rule, replace: event.target.value })}
        />
      ) : null}
      {uses.includes("layer") ? (
        <Select
          aria-label={`Rule ${index + 1} codec`}
          value={rule.layer}
          onChange={(event) => onChange({ ...rule, layer: event.target.value })}
        >
          {PAYLOAD_LAYERS.map((layer) => (
            <option key={layer} value={layer}>
              {layer}
            </option>
          ))}
        </Select>
      ) : null}
      {uses.includes("algorithm") ? (
        <Select
          aria-label={`Rule ${index + 1} algorithm`}
          value={rule.algorithm}
          onChange={(event) => onChange({ ...rule, algorithm: event.target.value })}
        >
          {HASH_ALGORITHMS.map((algorithm) => (
            <option key={algorithm} value={algorithm}>
              {algorithm}
            </option>
          ))}
        </Select>
      ) : null}
      {uses.includes("all") ? (
        <Checkbox checked={rule.all} onCheckedChange={(all) => onChange({ ...rule, all })} label="every match" />
      ) : null}
      <IconButton label={`Remove rule ${index + 1}`} size="small" onClick={onRemove}>
        <Trash2 size={13} />
      </IconButton>
    </div>
  );
}

/**
 * A payload cell. Three visibly different states, never collapsed into one:
 * resolved text, a position-only reference, and no answer at all.
 */
function PayloadCell({ parts, ordinal }: { parts: ResolvedPayload[] | null; ordinal: number }): JSX.Element {
  if (!parts) {
    return (
      <span
        className="cell-dim"
        title={`Attempt ${ordinal} could not be decoded: the report does not carry enough of the plan to place its payloads.`}
      >
        unknown
      </span>
    );
  }
  const { text, complete } = payloadLabel(parts);
  return (
    <code
      title={
        complete
          ? text
          : `${text} — the payloads of a server-side set (a file, or a set a processing rule changed) never cross the wire, so only their position in the set is known.`
      }
      className={complete ? undefined : "cell-dim"}
    >
      {text}
    </code>
  );
}

/** The stored request or response behind a result row, opened from the Results tab. */
function StoredMessage({ id, label, onClose }: { id: number; label: string; onClose: () => void }): JSX.Element {
  const message = useMessage(id);
  return (
    <Modal
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={label}
      description={`Stored message ${id}`}
      wide
    >
      <HttpEditor
        label={label}
        readOnly
        value={
          message.data?.text ??
          (message.isFetching
            ? "Loading the stored response…"
            : message.error
              ? `Could not load message ${id}: ${message.error instanceof Error ? message.error.message : String(message.error)}`
              : "No bytes stored for this message.")
        }
        filename={`intruder-message-${id}.txt`}
      />
    </Modal>
  );
}

/** Open-the-response control. Absent responses say so rather than showing a dead button. */
function ResponseCell({
  id,
  label,
  onOpen,
}: {
  id: number | null;
  label: string;
  onOpen: (id: number, label: string) => void;
}): JSX.Element {
  if (id === null) {
    return (
      <span className="cell-dim" title="No response was stored for this attempt.">
        —
      </span>
    );
  }
  return (
    <Button variant="outline" size="small" onClick={() => onOpen(id, label)}>
      <FileSearch size={13} />
      View
    </Button>
  );
}

/**
 * What a results row can hand to another tool.
 *
 * A row is described by the message ids the server stored for it, not by the row type: a bucket
 * and an attempt differ in what they count, and not at all in what "send this request to Repeater"
 * means. Either id is `null` when nothing was stored — a send that failed, a detail row past the
 * engine's DetailLimit, or a server older than the recording itself — and the menu greys the
 * matching action rather than offering one that would resolve nothing.
 */
interface ResultHandoff {
  requestId: number | null;
  responseId: number | null;
  /** How the row names itself in a Repeater tab title and in the toasts. */
  label: string;
}

/**
 * Repeater's protocol has to come from the target the attack actually used.
 *
 * `openRepeaterTab` defaults `protocol` to "https", so an http attack's request would arrive in
 * Repeater as https and fail the handshake against a server that never offered TLS — the same bug
 * `schemeOf` in lib/actions.ts exists to prevent for captured exchanges. The intruder target is
 * URL-shaped ("http://host:port", from exchangeAuthority), with the bare-authority form handled
 * the way targetParts does it server-side.
 */
function targetScheme(target: string): "http" | "https" {
  const t = target.trim();
  const scheme = t.indexOf("://");
  if (scheme >= 0) return t.slice(0, scheme).toLowerCase() === "https" ? "https" : "http";
  return /:443$/.test(t) ? "https" : "http";
}

/**
 * The cross-tool actions an Intruder result supports (burpsy-react-ui-79u).
 *
 * Until this existed a result was a dead end: the Results tab could show a response and nothing
 * else, so the way to retest an interesting row was to read the payload off the table and rebuild
 * the request by hand in Repeater. Burp's results rows carry the suite context menu, and
 * `configure-attack/settings.html` names "Send requests or responses to other Burp tools" as one
 * of the three reasons its store-requests setting exists.
 *
 * This is deliberately not `useExchangeActions`: that menu is keyed on an `Exchange`, and an
 * attack ordinal is not one. Fabricating an exchange id to reuse the menu would put the rest of
 * its actions — Add to scope, Record an issue, annotate — behind an id that names nothing.
 */
function useResultMenu(target: string): (row: ResultHandoff) => MenuGroup[] {
  const openRepeaterTab = useApp((state) => state.openRepeaterTab);
  const setComparerSlot = useApp((state) => state.setComparerSlot);
  const setRoute = useApp((state) => state.setRoute);

  return useCallback(
    (row: ResultHandoff): MenuGroup[] => {
      // One loader for every action: the bytes are fetched on select, not on right-click, so
      // opening a menu over a table of 500 rows costs nothing.
      const withBytes = (id: number | null, what: string, use: (raw: string) => void) => () => {
        if (id === null) return;
        void (async () => {
          try {
            use(await fetchRaw(id));
          } catch (error) {
            toast.error(`Could not load ${what} bytes: ${error instanceof Error ? error.message : String(error)}`);
          }
        })();
      };
      const noRequest = row.requestId === null;
      const noResponse = row.responseId === null;
      const compare = (id: number | null, what: string, slot: "a" | "b") =>
        withBytes(id, what, (raw) => {
          setComparerSlot(slot, raw);
          setRoute("comparer");
          toast.success(`${row.label} ${what} loaded into slot ${slot.toUpperCase()}`);
        });
      return [
        {
          id: "tools",
          actions: [
            {
              id: "repeater",
              label: "Send to Repeater",
              icon: Repeat2,
              disabled: noRequest,
              onSelect: withBytes(row.requestId, "request", (raw) => {
                openRepeaterTab({
                  name: row.label.slice(0, 42),
                  target,
                  protocol: targetScheme(target),
                  request: raw,
                });
                setRoute("repeater");
                toast.success(`${row.label} sent to Repeater`);
              }),
            },
          ],
        },
        {
          id: "comparer",
          title: "Send to Comparer",
          actions: [
            {
              id: "compare-request-a",
              label: "Request to slot A",
              icon: Combine,
              disabled: noRequest,
              onSelect: compare(row.requestId, "request", "a"),
            },
            {
              id: "compare-request-b",
              label: "Request to slot B",
              icon: ArrowRightLeft,
              disabled: noRequest,
              onSelect: compare(row.requestId, "request", "b"),
            },
            {
              id: "compare-response-a",
              label: "Response to slot A",
              icon: Combine,
              disabled: noResponse,
              onSelect: compare(row.responseId, "response", "a"),
            },
            {
              id: "compare-response-b",
              label: "Response to slot B",
              icon: ArrowRightLeft,
              disabled: noResponse,
              onSelect: compare(row.responseId, "response", "b"),
            },
          ],
        },
        {
          id: "clipboard",
          actions: [
            {
              id: "copy-request",
              label: "Copy request",
              icon: Copy,
              disabled: noRequest,
              onSelect: withBytes(row.requestId, "request", (raw) => {
                void copyToClipboard(raw).then(() => toast.success(`${row.label} request copied`));
              }),
            },
          ],
        },
      ];
    },
    [openRepeaterTab, setComparerSlot, setRoute, target],
  );
}

/**
 * The attack report, presented as accounting rather than a payload dump: every
 * bound the engine applied (capped, truncated, skipped, unbucketed) is shown, so
 * a small result set is never mistaken for a complete one.
 */
function AttackResult({
  view,
  examples,
  snapshot,
  onOpenMessage,
  bucketMenu,
  attemptMenu,
}: {
  view: RunView;
  examples: Map<number, string[]>;
  snapshot: IntruderPayloadSnapshot | null;
  onOpenMessage: (id: number, label: string) => void;
  // Two typed builders rather than one over a `ResultBucket | Attempt` union: the two row shapes
  // name their stored bytes under different field names, and a union would push that branch into
  // this component, which has no reason to know either.
  bucketMenu?: (bucket: ResultBucket) => MenuGroup[];
  attemptMenu?: (attempt: Attempt) => MenuGroup[];
}): JSX.Element {
  const { report, payload_sets: sets, redirects_followed: redirectsFollowed } = view;

  // Ordinal → payload combination, shared with the CSV export so the sheet and the
  // table can never disagree about what a row's payloads were (lib/intruder-export.ts
  // carries the full story: server examples first, plan arithmetic as the fallback).
  const payloadsAt = useMemo(
    () => intruderPayloadResolver({ report, sets, examples, snapshot }),
    [examples, report.kind, report.planned, sets, snapshot],
  );
  /**
   * A stopped attack describes a *prefix* of its payload sets, and the denominator has to say so.
   *
   * An intruder task is cancellable from the Dashboard (api_tools.go:711 registers the cancel;
   * dashboard.tsx offers Cancel on any cancellable running task), so this is reachable today. With
   * `planned` as the denominator the panel read "Sent 12 of 400 planned" — asserting the target was
   * asked 400 times and answered 12, when it was asked 12. `enumerated` is how many plan positions
   * were actually reached, which is the count the results are a prefix of.
   *
   * The absent-field fallback lives in attackProgress, where it is pinned by test.
   */
  const { stopped, paused, reached } = attackProgress(report);

  /**
   * Sorting and filtering for the four result tables (burpsy-react-ui-4rd).
   *
   * Sort accessors expose the raw values (statuses as numbers, nulls as
   * undefined with sortUndefined pinning them last), so ordering follows the
   * data rather than the formatted text; cell renderers keep the exact markup
   * the static tables had. The filter runs over the same accessor values, so
   * typing "404" or "refused" finds the rows whose visible cells carry those
   * words.
   */
  const [bucketFilter, setBucketFilter] = useState("");
  const [errorFilter, setErrorFilter] = useState("");
  const [setFilter, setSetFilter] = useState("");
  const [attemptFilter, setAttemptFilter] = useState("");

  /**
   * Burp's Comment column ("any user-applied comment", viewing-results.html) — an annotation the
   * operator types against one result row. There is no server-side row for it to live on: a report
   * is generated once per run and never persisted (api_tools.go builds and returns it inline), so a
   * comment is a browser-only fact, keyed by ordinal like the payload resolver above. Reset whenever
   * a new report arrives — `view` is a fresh object every run, and a comment surviving onto a
   * different attack's ordinal 3 would annotate the wrong request.
   */
  const [comments, setComments] = useState<Map<number, string>>(new Map());
  useEffect(() => setComments(new Map()), [view]);

  const bucketColumns: Column<ResultBucket>[] = [
    {
      accessorFn: (bucket) => bucket.status ?? undefined,
      id: "status",
      header: "Status",
      sortUndefined: "last",
      cell: ({ row }) =>
        row.original.status === null ? (
          <Badge tone="bad">error</Badge>
        ) : (
          <Badge tone={statusTone(row.original.status)}>{row.original.status}</Badge>
        ),
    },
    { accessorKey: "response_len", header: "Length", cell: ({ getValue }) => <span className="cell-num">{formatBytes(getValue<number>())}</span> },
    {
      accessorFn: (bucket) => (bucket.reflected ? "yes" : "no"),
      id: "reflected",
      header: "Reflected",
      cell: ({ row }) =>
        row.original.reflected ? <Badge tone="warn">reflected</Badge> : <span className="cell-dim">no</span>,
    },
    { accessorKey: "count", header: "Count", cell: ({ getValue }) => <span className="cell-num">{formatCount(getValue<number>())}</span> },
    // Per-expression totals for the bucket table (irt): the slot-wise sum over every response
    // the bucket holds, so a bucket can be sorted by how often a given error string appeared.
    ...(view.report.grep_match_labels ?? []).map((label, li) => ({
      accessorFn: (bucket: ResultBucket) => {
        const totals = bucket.grep_match_totals ?? [];
        const v = totals[li];
        return v !== undefined && v > 0 ? v : undefined;
      },
      id: `bucket_grep_item_${li}`,
      header: label.length > 18 ? label.slice(0, 17) + "…" : label,
      sortUndefined: "last" as const,
      cell: ({ row }: { row: { original: ResultBucket } }) => {
        const totals = row.original.grep_match_totals ?? [];
        const v = totals[li];
        return v !== undefined && v > 0 ? <Badge tone="info">{v}</Badge> : <span className="cell-dim">0</span>;
      },
    })),
    {
      accessorFn: (bucket) => (bucket.grep_matches ? bucket.grep_matches : undefined),
      id: "grep",
      header: "Grep",
      sortUndefined: "last",
      cell: ({ row }) => (
        <>
          {row.original.grep_matches ? <Badge tone="info">{row.original.grep_matches}</Badge> : <span className="cell-dim">—</span>}
          {row.original.grep_extract ? <code title={row.original.grep_extract}> {row.original.grep_extract}</code> : null}
        </>
      ),
    },
    {
      id: "first_payload",
      header: "First payload",
      enableSorting: false,
      cell: ({ row }) => <PayloadCell parts={payloadsAt(row.original.first_ordinal)} ordinal={row.original.first_ordinal} />,
    },
    {
      id: "response",
      header: "Response",
      enableSorting: false,
      cell: ({ row }) => (
        <ResponseCell
          id={row.original.example_response_id}
          label={`Response to attempt ${row.original.first_ordinal}`}
          onOpen={onOpenMessage}
        />
      ),
    },
  ];
  const bucketRows = filterTableRows(report.buckets, bucketColumns, bucketFilter);

  const errorColumns: Column<ErrorBucket>[] = [
    { accessorKey: "error", header: "Error", cell: ({ row }) => <span title={row.original.error}>{row.original.error}</span> },
    { accessorKey: "count", header: "Count", cell: ({ getValue }) => <span className="cell-num">{formatCount(getValue<number>())}</span> },
    {
      accessorFn: (bucket) => bucket.first_ordinal ?? undefined,
      id: "first_ordinal",
      header: "First ordinal",
      sortUndefined: "last",
      cell: ({ getValue }) => <span className="cell-num">{getValue<number | undefined>() ?? "—"}</span>,
    },
  ];
  const errorRows = filterTableRows(report.errors, errorColumns, errorFilter);

  const setColumns: Column<PayloadSetReport>[] = [
    {
      id: "set",
      header: "Set",
      accessorFn: (set) => sets.indexOf(set) + 1,
      cell: ({ getValue }) => <span className="cell-num">{getValue<number>()}</span>,
    },
    { accessorKey: "kind", header: "Kind", cell: ({ row }) => <Badge>{row.original.kind}</Badge> },
    { accessorKey: "count", header: "Used", cell: ({ getValue }) => <span className="cell-num">{formatCount(getValue<number>())}</span> },
    {
      accessorKey: "total",
      header: "Described",
      cell: ({ row }) => (
        <span className="cell-num">
          {formatCount(row.original.total)}
          {row.original.total_exact ? "" : "+"}
        </span>
      ),
    },
    {
      accessorFn: (set) => (set.truncated ? "yes" : "no"),
      id: "truncated",
      header: "Truncated",
      cell: ({ row }) =>
        row.original.truncated ? (
          <Badge tone="warn">at {formatCount(row.original.max_count)}</Badge>
        ) : (
          <span className="cell-dim">no</span>
        ),
    },
    { accessorKey: "skipped", header: "Skipped", cell: ({ getValue }) => <span className="cell-num">{formatCount(getValue<number>())}</span> },
    {
      id: "dropped",
      header: "Dropped because",
      enableSorting: false,
      cell: ({ row }) =>
        row.original.dropped.length ? (
          row.original.dropped.map((reason) => (
            <Badge tone="warn" key={reason.reason}>
              {reason.reason} ×{reason.count}
            </Badge>
          ))
        ) : (
          <span className="cell-dim">—</span>
        ),
    },
  ];
  const setRows = filterTableRows(sets, setColumns, setFilter);

  const attemptColumns: Column<Attempt>[] = [
    { accessorKey: "ordinal", header: "#", cell: ({ getValue }) => <span className="cell-num">{getValue<number>()}</span> },
    {
      id: "payload",
      header: "Payload",
      // The resolved combination is what the cell shows, so it is also what
      // sorting and filtering see — including the "set 2 payload #18" text a
      // server-side set renders.
      accessorFn: (attempt) => {
        const parts = payloadsAt(attempt.ordinal);
        return parts ? payloadLabel(parts).text : undefined;
      },
      cell: ({ row }) => <PayloadCell parts={payloadsAt(row.original.ordinal)} ordinal={row.original.ordinal} />,
    },
    {
      accessorFn: (attempt) => attempt.status ?? undefined,
      id: "status",
      header: "Status",
      sortUndefined: "last",
      cell: ({ row }) =>
        row.original.status === null ? (
          <Badge tone="bad">—</Badge>
        ) : (
          <Badge tone={statusTone(row.original.status)}>{row.original.status}</Badge>
        ),
    },
    {
      // Burp's "Time of day - the time of day the request was made" (viewing-results.html),
      // distinct from the "Time" column above, which is a duration. attempt.time_of_day is
      // RFC 3339 (Go's default time.Time encoding); an unparseable value reads as "—" rather than
      // "Invalid Date" — the same defensive parse formatTimeOfDay does for every row.
      accessorFn: (attempt) => Date.parse(attempt.time_of_day) || undefined,
      id: "time_of_day",
      header: "Time of day",
      sortUndefined: "last",
      cell: ({ row }) => <span className="cell-num">{formatTimeOfDay(row.original.time_of_day)}</span>,
    },
    { accessorKey: "response_len", header: "Length", cell: ({ getValue }) => <span className="cell-num">{formatBytes(getValue<number>())}</span> },
    { accessorKey: "duration_ms", header: "Time", cell: ({ getValue }) => <span className="cell-num">{formatDuration(getValue<number>())}</span> },
    {
      accessorFn: (attempt) => (attempt.reflected ? "yes" : "no"),
      id: "reflected",
      header: "Reflected",
      cell: ({ row }) => (row.original.reflected ? <Badge tone="warn">yes</Badge> : <span className="cell-dim">no</span>),
    },
    {
      accessorFn: (attempt) => (attempt.grep_matched ? "match" : undefined),
      id: "grep",
      header: "Grep",
      sortUndefined: "last",
      cell: ({ row }) =>
        row.original.grep_matched ? <Badge tone="info">match</Badge> : <span className="cell-dim">—</span>,
    },
    // One column per expression (irt): "Burp adds a results column for each expression in the
    // list. This records the number of times the expression is found in the response." Sorting
    // on the header sorts by that expression's count, which is how the table is read. Labels
    // come from the report — the expressions as the operator typed them.
    ...(view.report.grep_match_labels ?? []).map((label, li) => ({
      accessorFn: (attempt: Attempt) => {
        const counts = attempt.grep_match_counts ?? [];
        const v = counts[li];
        return v !== undefined && v > 0 ? v : undefined;
      },
      id: `grep_item_${li}`,
      header: label.length > 18 ? label.slice(0, 17) + "…" : label,
      sortUndefined: "last" as const,
      cell: ({ row }: { row: { original: Attempt } }) => {
        const counts = row.original.grep_match_counts ?? [];
        const v = counts[li];
        return v !== undefined && v > 0 ? <Badge tone="info">{v}</Badge> : <span className="cell-dim">0</span>;
      },
    })),
    {
      accessorFn: (attempt) => attempt.error ?? undefined,
      id: "error",
      header: "Error",
      sortUndefined: "last",
      cell: ({ row }) => (row.original.error ? <span title={row.original.error}>{row.original.error}</span> : <span className="cell-dim">—</span>),
    },
    {
      // Burp lists Timeout as its own column, distinct from Error, so a target that stalls on
      // every Nth payload is visible as a pattern rather than buried inside error-message text.
      accessorFn: (attempt) => (attempt.timeout ? "yes" : "no"),
      id: "timeout",
      header: "Timeout",
      cell: ({ row }) => (row.original.timeout ? <Badge tone="bad">timeout</Badge> : <span className="cell-dim">no</span>),
    },
    {
      // Burp: "Cookies - any cookies received in the response". Names only — see Attempt.cookies'
      // own doc for why values never surface here.
      accessorFn: (attempt) => (attempt.cookies.length ? attempt.cookies.join(", ") : undefined),
      id: "cookies",
      header: "Cookies",
      sortUndefined: "last",
      cell: ({ row }) =>
        row.original.cookies.length ? (
          <span title={row.original.cookies.join(", ")}>{row.original.cookies.join(", ")}</span>
        ) : (
          <span className="cell-dim">—</span>
        ),
    },
    {
      id: "response",
      header: "Response",
      enableSorting: false,
      cell: ({ row }) => (
        <ResponseCell id={row.original.response_id} label={`Response to attempt ${row.original.ordinal}`} onOpen={onOpenMessage} />
      ),
    },
    {
      // Burp: "Comment - any user-applied comment". Browser-only (see the `comments` state's own
      // doc above) — typing here never leaves this tab, and it rides into the CSV export below so
      // an annotation an operator made survives past the session that made it.
      accessorFn: (attempt) => comments.get(attempt.ordinal) ?? "",
      id: "comment",
      header: "Comment",
      cell: ({ row }) => (
        <Input
          aria-label={`Comment on attempt ${row.original.ordinal}`}
          placeholder="Add a comment"
          value={comments.get(row.original.ordinal) ?? ""}
          onChange={(event) => {
            const next = event.target.value;
            setComments((prev) => {
              const copy = new Map(prev);
              if (next === "") copy.delete(row.original.ordinal);
              else copy.set(row.original.ordinal, next);
              return copy;
            });
          }}
        />
      ),
    },
  ];
  const attemptRows = filterTableRows(report.attempts, attemptColumns, attemptFilter);

  const caveats = [
    stopped
      ? `Attack ${paused ? "paused" : "stopped"} after ${formatCount(reached)} of ${formatCount(
          report.planned,
        )} planned requests${report.stop_reason ? ` — ${report.stop_reason}` : ""}. Everything below describes that prefix of the payload sets, not the whole attack.`
      : null,
    report.truncated ? `Capped at ${formatCount(report.max_requests)} requests` : null,
    !report.combinations_exact ? "Combination count is a floor, not an exact total" : null,
    report.buckets_truncated ? "Result buckets were truncated" : null,
    report.unbucketed ? `${formatCount(report.unbucketed)} results outside the shown buckets` : null,
    report.attempts.length < report.sent ? `Per-attempt detail limited to ${formatCount(report.detail_limit)} rows` : null,
    report.auto_throttle_engaged ? `Auto-throttle engaged ${report.auto_throttle_engaged}×` : null,
    // n39: the error-handling count is a caveat, not a footnote — an attack that retried its
    // way to a full result set says so, the way Burp's own results mark retried requests.
    report.retries_used ? `${formatCount(report.retries_used)} retried request${report.retries_used === 1 ? "" : "s"} (network failures sent again per the error-handling settings)` : null,
    report.baseline ? "Item 0 is the unmodified baseline request (no payloads) — every other row is one ordinal higher than the payload set's arithmetic." : null,
  ].filter((value): value is string => value !== null);

  return (
    <>
      <div className="toolbar">
        <Tooltip content="Download the attack's per-attempt rows as a CSV; the caveats ride at the top of the file">
          <Button
            variant="outline"
            onClick={() => {
              const file = intruderExportFilenames(report).csv;
              downloadText(file, intruderReportToCSV(report, report.attempts, payloadsAt, new Date(), comments), "text/csv");
              toast.success(`Exported ${formatCount(report.attempts.length)} attempts to ${file}`);
            }}
          >
            <Download size={14} />
            Export CSV
          </Button>
        </Tooltip>
        <Tooltip content="Download the full report — buckets, attempts, payload sets and bounds — as JSON">
          <Button
            variant="outline"
            onClick={() => {
              const file = intruderExportFilenames(report).json;
              downloadText(file, JSON.stringify(view, null, 2), "application/json");
              toast.success(`Exported the report to ${file}`);
            }}
          >
            <Download size={14} />
            Export report (JSON)
          </Button>
        </Tooltip>
      </div>
      <div className="metric-grid">
        <Badge tone="neutral" className="sr-only">
          report
        </Badge>
        <div className={stopped ? "card metric metric-accent row-flag-bad" : "card metric metric-accent"}>
          <span>Sent</span>
          <strong>{formatCount(report.sent)}</strong>
          <small>
            {stopped
              ? `of ${formatCount(reached)} reached · plan was ${formatCount(report.planned)}`
              : `of ${formatCount(report.planned)} planned`}
          </small>
        </div>
        <div className="card metric">
          <span>Combinations</span>
          <strong>
            {formatCount(report.combinations)}
            {report.combinations_exact ? "" : "+"}
          </strong>
          <small>{report.combinations_exact ? "exact" : "floor — saturated"}</small>
        </div>
        <div className={report.failed ? "card metric metric-bad" : "card metric"}>
          <span>Failed</span>
          <strong>{formatCount(report.failed)}</strong>
          <small>{report.errors.length} distinct errors</small>
        </div>
        <div className="card metric">
          <span>Elapsed</span>
          <strong>{formatDuration(report.elapsed_ms)}</strong>
          <small>{report.grep_matched ? `${formatCount(report.grep_matched)} grep matches` : "mode " + report.kind}</small>
        </div>
        {redirectsFollowed ? (
          <div className="card metric">
            <span>Redirects followed</span>
            <strong>{formatCount(redirectsFollowed)}</strong>
            <small>additional requests this attack sent chasing a 3xx</small>
          </div>
        ) : null}
      </div>

      {caveats.length ? (
        <div className="notice notice-warn">
          <AlertTriangle size={15} />
          <div>
            <strong>Bounds applied to this attack.</strong>
            <ul style={{ margin: "4px 0 0", paddingLeft: 16 }}>
              {caveats.map((caveat) => (
                <li key={caveat}>{caveat}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      <Card>
        <SectionHeading
          title="Result buckets"
          detail="Responses grouped by status, length and reflection. Interesting rows are the ones that differ from the crowd."
        />
        {report.buckets.length ? (
          <>
            <ResultFilter
              label="Filter buckets"
              value={bucketFilter}
              onChange={setBucketFilter}
              shown={bucketRows.length}
              total={report.buckets.length}
            />
            {bucketRows.length ? (
              <SortableTable
                data={bucketRows}
                columns={bucketColumns}
                getRowId={(bucket) => `${bucket.status}-${bucket.response_len}-${bucket.first_ordinal}`}
                ariaLabel="Result buckets"
                menuGroups={bucketMenu}
              />
            ) : (
              <p className="cell-dim">No buckets match the filter — all {report.buckets.length} are hidden.</p>
            )}
          </>
        ) : (
          <Empty title="No buckets" detail="The attack produced no grouped responses." />
        )}
      </Card>

      {report.errors.length ? (
        <Card>
          <SectionHeading title="Errors" detail="Grouped by message, with the first attempt that hit each." />
          <ResultFilter
            label="Filter errors"
            value={errorFilter}
            onChange={setErrorFilter}
            shown={errorRows.length}
            total={report.errors.length}
          />
          {errorRows.length ? (
            <SortableTable
              data={errorRows}
              columns={errorColumns}
              getRowId={(bucket) => bucket.error}
              ariaLabel="Attack errors"
              rowClassName={() => "row-flag-bad"}
            />
          ) : (
            <p className="cell-dim">No errors match the filter — all {report.errors.length} are hidden.</p>
          )}
        </Card>
      ) : null}

      <Card>
        <SectionHeading title="Payload set accounting" detail="What each set produced, and what was bounded away." />
        {sets.length ? (
          <>
            <ResultFilter
              label="Filter payload sets"
              value={setFilter}
              onChange={setSetFilter}
              shown={setRows.length}
              total={sets.length}
            />
            {setRows.length ? (
              <SortableTable
                data={setRows}
                columns={setColumns}
                getRowId={(set) => `${set.kind}-${sets.indexOf(set)}`}
                ariaLabel="Payload set accounting"
              />
            ) : (
              <p className="cell-dim">No payload sets match the filter — all {sets.length} are hidden.</p>
            )}
          </>
        ) : (
          <Empty title="No set accounting" detail="The server reported no per-set breakdown." />
        )}
      </Card>

      {report.attempts.length ? (
        <Card>
          <SectionHeading
            title="Attempts"
            detail={`Per-request detail, capped by the server at ${formatCount(report.detail_limit)} rows.`}
          />
          <ResultFilter
            label="Filter attempts"
            value={attemptFilter}
            onChange={setAttemptFilter}
            shown={attemptRows.length}
            total={report.attempts.length}
          />
          {attemptRows.length ? (
            <SortableTable
              data={attemptRows}
              columns={attemptColumns}
              getRowId={(attempt) => String(attempt.ordinal)}
              ariaLabel="Attempts"
              rowClassName={(attempt) => (attempt.error ? "row-flag-bad" : undefined)}
              menuGroups={attemptMenu}
            />
          ) : (
            <p className="cell-dim">No attempts match the filter — all {report.attempts.length} are hidden.</p>
          )}
        </Card>
      ) : null}
    </>
  );
}

export function IntruderPage(): JSX.Element {
  const seed = useApp((state) => state.intruderSeed);
  const setIntruderSeed = useApp((state) => state.setIntruderSeed);
  // The wordlist inventory (kal): the bundled corpus plus this session's uploads, listed
  // once for every file-source position the operator configures.
  const wordlistsQuery = useWordlists();

  // The whole configuration lives in the store, not in this component: app.tsx mounts one page at
  // a time, so component-local state was destroyed by any nav click, taking the finished report
  // with it (burpsy-react-ui-rby). The field setters below keep the shape the JSX already used.
  const config = useApp((state) => state.intruder);
  const setConfig = useApp((state) => state.setIntruder);
  const storedRun = useApp((state) => state.intruderRun);
  const setStoredRun = useApp((state) => state.setIntruderRun);
  const tab = useApp((state) => state.intruderTab);
  const setTab = useApp((state) => state.setIntruderTab);

  // The menubar's Intruder menu talks to this page rather than launching attacks of its own: a
  // second copy of `onRun` in app.tsx would be a second launcher, and the two would drift. The menu
  // states an intention here; everything below decides whether it can be honoured and says why not.
  const command = useApp((state) => state.intruderCommand);
  const clearCommand = useApp((state) => state.clearIntruderCommand);
  const setStatus = useApp((state) => state.setIntruderStatus);

  /** A setter for one configuration field, accepting a value or an updater like useState's. */
  function field<K extends keyof IntruderConfig>(key: K) {
    return (value: IntruderConfig[K] | ((current: IntruderConfig[K]) => IntruderConfig[K])) =>
      setConfig((current) => {
        const next =
          typeof value === "function" ? (value as (c: IntruderConfig[K]) => IntruderConfig[K])(current[key]) : value;
        // An updater that returns its input means "no change" — the payload-set length sync below
        // relies on that, and a new object every time would re-render the page for nothing.
        if (next === current[key]) return current;
        return { ...current, [key]: next };
      });
  }

  const {
    msgId,
    target,
    label,
    mode,
    allPoints,
    points,
    selected,
    manualSpans,
    payloadTexts,
    payloadTypes,
    payloadNumbers,
    payloadFiles,
    payloadBrute,
    payloadDates,
    payloadCustom,
    payloadNulls,
    rules,
    grepMatch,
    grepMatchMode,
    grepExtract,
    grepMatchList,
    grepMatchCaseSensitive,
    grepMatchExcludeHeaders,
    poolName,
    maxRequests,
    maxInFlight,
    rps,
    delayJitterPct,
    delayIncrementMS,
    retries,
    retryDelayMS,
    baseline,
    setConnectionClose,
    storePayloads,
  } = config;

  const setMsgId = field("msgId");
  const setTarget = field("target");
  const setMode = field("mode");
  const setAllPoints = field("allPoints");
  const setPoints = field("points");
  const setSelected = field("selected");
  const setManualSpans = field("manualSpans");
  const setPayloadTexts = field("payloadTexts");
  const setPayloadTypes = field("payloadTypes");
  const setPayloadNumbers = field("payloadNumbers");
  const setPayloadFiles = field("payloadFiles");
  const setPayloadBrute = field("payloadBrute");
  const setPayloadDates = field("payloadDates");
  const setPayloadCustom = field("payloadCustom");
  const setPayloadNulls = field("payloadNulls");
  const setRules = field("rules");
  // Burp's "URL-encode these characters" (burpsy-react-ui-8cbc): the final-pass encoding
  // set, applied after the rules above regardless of payload type. Default is Burp's own
  // default character list, so the safety net is on unless the operator empties it.
  const [urlEncodeChars, setURLEncodeChars] = useState("=&+%;?/ #:");
  // Burp's "Follow redirections" (tirx). "" is not sent at all — the standing network policy
  // decides, exactly as an attack that never mentions it always has — so this control cannot
  // silently turn following on for an operator who only opened this tab to look at Grep.
  const [redirectMode, setRedirectMode] = useState<FollowRedirectsMode | "">("");
  // Burp's other two attack settings (fmxv), written through the persisted config like every other
  // attack setting: an operator who turns either on expects it still on when the tab is reopened, and
  // a launch that silently loses the setting would send a differently-shaped request than the one on
  // screen.
  const setSetConnectionClose = field("setConnectionClose");
  const setStorePayloads = field("storePayloads");

  /**
   * The 8 generator payload types added for 2g13 (char_substitution, case_modification,
   * illegal_unicode, character_blocks, bit_flipper, username, ecb_shuffler) plus copy_other's
   * one field, keyed by set index rather than one `useState` array per type. The existing
   * payload types above each carry their own typed, persisted array (payloadNumbers,
   * payloadBrute, …) in the IntruderConfig store; these 9 share one generic bucket instead —
   * a deliberately smaller first pass than duplicating that per-type machinery nine more
   * times. Values are read with a fallback (`advField`/`advBool`), so an index that was never
   * touched behaves exactly like one initialised to the type's defaults, and nothing needs a
   * resize effect the way the array-backed types do (an index past what the mode currently
   * renders is simply never read).
   */
  const [advancedFields, setAdvancedFields] = useState<Record<number, Record<string, string>>>({});
  const [advancedFlags, setAdvancedFlags] = useState<Record<number, Record<string, boolean>>>({});
  const advField = (index: number, key: string, fallback = "") => advancedFields[index]?.[key] ?? fallback;
  const setAdvField = (index: number, key: string, value: string) =>
    setAdvancedFields((cur) => ({ ...cur, [index]: { ...cur[index], [key]: value } }));
  const advBool = (index: number, key: string, fallback: boolean) => advancedFlags[index]?.[key] ?? fallback;
  const setAdvBool = (index: number, key: string, value: boolean) =>
    setAdvancedFlags((cur) => ({ ...cur, [index]: { ...cur[index], [key]: value } }));
  const setGrepMatch = field("grepMatch");
  const setGrepMatchMode = field("grepMatchMode");
  const setGrepExtract = field("grepExtract");
  // Grep - Match as a LIST (irt): one expression per line, with Burp's Match type / Case
  // sensitive / Exclude HTTP headers flags. The legacy single-string field is kept and still
  // wins when the list is empty, so an operator's stored config never silently stops matching.
  const setGrepMatchList = field("grepMatchList");
  const setGrepMatchCaseSensitive = field("grepMatchCaseSensitive");
  const setGrepMatchExcludeHeaders = field("grepMatchExcludeHeaders");
  const setPoolName = field("poolName");
  const setMaxRequests = field("maxRequests");
  const setMaxInFlight = field("maxInFlight");
  const setRps = field("rps");
  const setDelayJitterPct = field("delayJitterPct");
  const setDelayIncrementMS = field("delayIncrementMS");
  const setRetries = field("retries");
  const setRetryDelayMS = field("retryDelayMS");
  const setBaseline = field("baseline");

  const result = storedRun?.view ?? null;
  const legacyResult = storedRun?.legacy ?? null;
  const snapshot = storedRun?.snapshot ?? null;

  // Which stored message the Results tab has open. Deliberately not persisted: an operator
  // returning to the page wants the report, not a dialog they left open yesterday.
  const [openMessage, setOpenMessage] = useState<{ id: number; label: string } | null>(null);
  // Starting over now has to be deliberate. The configuration and report survive navigation and
  // reload, so the only thing that can destroy them is this, and it asks first.
  const [confirmReset, setConfirmReset] = useState(false);

  const discover = useIntruderPoints();
  const run = useIntruderRun();
  const pools = usePools();
  const baseMessage = useMessage(msgId ? Number(msgId) : null);

  // Live attack control (pause/resume/stop). /run is synchronous, so this page cannot read its own
  // attack's task_id from the run response — that arrives only when the attack is already over. It
  // finds the id by watching GET /api/intruder/attacks while its run is in flight, and identifying
  // the attack that appeared *after* it launched (target- and kind-matched). priorIds is the set of
  // attacks already running at launch, captured so a second identical attack started elsewhere is
  // not mistaken for this one.
  const priorIds = useRef<Set<number>>(new Set());
  const [myTaskId, setMyTaskId] = useState<number | null>(null);
  const attacks = useIntruderAttacks(run.isPending);
  const attackAction = useIntruderAttackAction();

  // Results handoff (burpsy-react-ui-79u). A bucket's stored exchange is its exemplar's, so both
  // row types are labelled by the ordinal whose bytes they actually carry — a bucket row that said
  // "bucket 200/1024" while resending ordinal 7's request would be naming the wrong thing.
  const resultMenu = useResultMenu(target);
  const bucketMenu = useCallback(
    (bucket: ResultBucket) =>
      resultMenu({
        requestId: bucket.example_request_id,
        responseId: bucket.example_response_id,
        label: `Intruder attempt ${bucket.first_ordinal}`,
      }),
    [resultMenu],
  );
  const attemptMenu = useCallback(
    (attempt: Attempt) =>
      resultMenu({
        requestId: attempt.request_id,
        responseId: attempt.response_id,
        label: `Intruder attempt ${attempt.ordinal}`,
      }),
    [resultMenu],
  );

  // The attacks list reports `target` as bare host:port (the server's targetParts collapses the URL
  // to that; api_types.go), so the page's URL-shaped target has to be reduced the same way before it
  // can match. Mirrors targetParts' scheme-default ports so "https://h" and "h:443" compare equal.
  const targetAuthority = (raw: string): string => {
    let t = raw.trim();
    let tls = false;
    const scheme = t.indexOf("://");
    if (scheme >= 0) {
      tls = t.slice(0, scheme).toLowerCase() === "https";
      t = t.slice(scheme + 3);
    }
    const cut = t.search(/[/?]/);
    if (cut >= 0) t = t.slice(0, cut);
    if (!/:\d+$/.test(t)) t = `${t}:${tls ? 443 : 80}`;
    return t;
  };

  // Lock onto our task id once it appears, and never re-pick within one run: once identified, the id
  // is stable until the run ends, so a later poll that races the attack's own status change cannot
  // move the controls to a different attack.
  useEffect(() => {
    if (!run.isPending || myTaskId !== null) return;
    const authority = targetAuthority(target);
    const candidates = (attacks.data?.attacks ?? []).filter(
      (a) =>
        !priorIds.current.has(a.task_id) &&
        a.target === authority &&
        a.kind === mode &&
        (a.status === "running" || a.status === "paused"),
    );
    if (candidates.length) {
      // The newest matching attack is this page's: it just launched, and older identical attacks (if
      // any) were captured in priorIds already.
      setMyTaskId(candidates.reduce((best, a) => (a.task_id > best.task_id ? a : best)).task_id);
    }
  }, [attacks.data, run.isPending, myTaskId, target, mode]);

  // When the run ends (completed or stopped), drop the id so the controls disappear with it.
  useEffect(() => {
    if (!run.isPending) setMyTaskId(null);
  }, [run.isPending]);

  const myAttack = myTaskId === null ? null : (attacks.data?.attacks ?? []).find((a) => a.task_id === myTaskId) ?? null;

  const controlAttack = (action: "pause" | "resume" | "stop") => {
    if (myTaskId === null) return;
    attackAction.mutate(
      { task_id: myTaskId, action },
      {
        onSuccess: () => {
          if (action === "stop") toast.info("Stopping — the report will show everything that was sent");
          else toast.success(action === "pause" ? "Attack paused" : "Attack resumed");
        },
        onError: (error) =>
          error instanceof AttackActionStale
            ? toast.info("The attack already finished — its report is on the way")
            : toast.error(error instanceof Error ? error.message : String(error)),
      },
    );
  };

  // A send-to handoff from History or Repeater arrives through the store. It replaces only what is
  // tied to the specific request — the base message, the target, the discovered positions — and the
  // report, which belongs to the request that produced it. Payload sets, processing rules, grep and
  // limits are kept: they are the operator's typed work, and a send-to is not consent to discard it.
  // "New attack" in the header is the deliberate full reset, and it asks first.
  useEffect(() => {
    if (!seed) return;
    setConfig((current) => ({
      ...current,
      msgId: seed.msgId !== null ? String(seed.msgId) : current.msgId,
      target: seed.target,
      label: seed.label,
      points: [],
      selected: [],
      manualSpans: [],
    }));
    setStoredRun(null);
    setIntruderSeed(null);
  }, [seed, setConfig, setIntruderSeed, setStoredRun]);

  // Manual markers take a payload slot exactly like a discovered point does — Burp counts every
  // mark on the request, however it was made.
  const pointCount = selected.length + manualSpans.length;
  const setsNeeded = mode === "sniper" || mode === "battering_ram" ? 1 : Math.max(1, pointCount);

  // Keep the payload-set count in step with the mode and the chosen positions.
  useEffect(() => {
    setPayloadTexts((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => "")];
    });
    setPayloadTypes((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => "list" as const)];
    });
    setPayloadNumbers((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => ({ from: "1", to: "100", step: "1" }))];
    });
    setPayloadFiles((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => "")];
    });
    setPayloadBrute((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => ({ charset: "abc", min_len: "1", max_len: "3" }))];
    });
    setPayloadDates((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => ({ from: "2024-01-01", to: "2024-12-31", step: "1", format: "yyyy-MM-dd" }))];
    });
    setPayloadCustom((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => ({ positions: "a,b\nc,d", separator: "" }))];
    });
    setPayloadNulls((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => "10")];
    });
  }, [setsNeeded]);

  /**
   * How many payloads each set will produce, or null when the browser cannot know.
   *
   * `file`, `dates` and `custom_iterator` used to return the constants 1, 10 and 4 here, which the
   * header badge presented as a request count and the over-budget guard used as a bound: a
   * 50,000-line wordlist read "1 request", and an 8,000-combination iterator could not trip the
   * warning that exists to stop an accidental outage (burpsy-react-ui-1ww). Dates and iterators are
   * arithmetic, so they are computed. A server-side file is genuinely unknowable from here, so it
   * says so instead of standing in a number.
   */
  const setSizes = useMemo<SetSize[]>(() => {
    return payloadTypes.map((t, i): SetSize => {
      if (t === "numbers") {
        const n = payloadNumbers[i];
        if (!n) return 0;
        const from = Number(n.from), to = Number(n.to), step = Number(n.step) || 1;
        if (!Number.isFinite(from) || !Number.isFinite(to) || step === 0) return 0;
        return Math.floor(Math.abs(to - from) / Math.abs(step)) + 1;
      }
      if (t === "file") return null;
      if (t === "brute_force") {
        const b = payloadBrute[i];
        if (!b) return 0;
        const charset = b.charset.length || 1;
        const min = Number(b.min_len) || 0, max = Number(b.max_len) || 0;
        if (max < min || min < 1) return 0;
        let total = 0;
        for (let l = min; l <= max; l++) total += Math.pow(charset, l);
        return Math.min(total, 200000);
      }
      if (t === "dates") {
        const d = payloadDates[i];
        if (!d) return 0;
        return dateSetSize(d.from, d.to, Number(d.step) || 1);
      }
      if (t === "custom_iterator") return customIteratorSize(payloadCustom[i]?.positions ?? "");
      if (t === "null") return Number(payloadNulls[i] ?? "0") || 0;
      // The 9 types added for 2g13: the true count depends on server-side generator logic
      // (2^k substitutable positions, a factorial permutation count, …) this page does not
      // reimplement — unknown is the honest answer, the same one `file` already gives, not a
      // guessed number standing in for one (burpsy-react-ui-1ww is exactly the bug that
      // guessing here caused once already).
      if (
        t === "char_substitution" ||
        t === "case_modification" ||
        t === "illegal_unicode" ||
        t === "character_blocks" ||
        t === "bit_flipper" ||
        t === "username" ||
        t === "ecb_shuffler" ||
        t === "copy_other"
      ) {
        return null;
      }
      return countPayloads(payloadTexts[i] ?? "");
    });
  }, [payloadTypes, payloadTexts, payloadNumbers, payloadFiles, payloadBrute, payloadDates, payloadCustom, payloadNulls]);
  const estimate = useMemo(() => estimateRequests(mode, pointCount, setSizes), [mode, pointCount, setSizes]);
  const examples = useMemo(
    () => new Map((result?.examples ?? []).map((example) => [example.first_ordinal, example.payloads])),
    [result],
  );

  // `>= 0` and an integer check: message ids count from zero, so message 0 is a real base request —
  // `> 0` disabled Discover for it, and a decimal typed by accident passed.
  const canDiscover = msgId.trim() !== "" && Number.isInteger(Number(msgId)) && Number(msgId) >= 0;
  // A null size is a file set, whose size only the server knows — unknown must not read as empty
  // and block the launch.
  const canRun =
    canDiscover &&
    target.trim() !== "" &&
    pointCount > 0 &&
    setSizes.every((size) => size === null || size > 0) &&
    !run.isPending;

  const onDiscover = () => {
    setSelected([]);
    setPoints([]);
    discover.mutate(
      { msg_id: Number(msgId), all: allPoints },
      {
        onSuccess: (found) => {
          setPoints(found);
          if (!found.length) toast.error("No insertion points were found in that message");
          else toast.success(`${found.length} insertion ${found.length === 1 ? "point" : "points"} found`);
        },
        onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
      },
    );
  };

  /** A hand-marked position (Burp's Add §): wrap the editor's selection in a marker pair. */
  const onAddManualSpan = useCallback(
    (span: { start: number; end: number; text: string }) => {
      // The editor shows the request with the existing "§" pairs folded in, so its offsets are
      // display offsets; map them back to raw request bytes before storing.
      const current = useApp.getState().intruder.manualSpans;
      const { start, end } = selectionToRawSpan(current, span.start, span.end);
      const result = addManualSpan(current, start, end, span.text);
      if (!result.ok) {
        toast.error(result.reason);
        return;
      }
      setManualSpans(result.spans);
    },
    [setManualSpans],
  );

  // Burp's Auto §: replace the hand marks with the scanner's default set — here, the standard
  // discovery (not "every candidate"), every found point selected.
  const onAutoMark = () => {
    setManualSpans([]);
    setSelected([]);
    discover.mutate(
      { msg_id: Number(msgId), all: false },
      {
        onSuccess: (found) => {
          setPoints(found);
          setSelected(found.map((point) => point.index));
          if (!found.length) toast.error("No insertion points were found in that message");
          else toast.success(`${found.length} insertion ${found.length === 1 ? "point" : "points"} marked`);
        },
        onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
      },
    );
  };

  const onClearMarks = () => setManualSpans([]);

  /**
   * The payload text this browser can name, per set, at the moment of launch.
   *
   * Only sets the browser is itself the source of truth for: a `list` is what the operator typed,
   * and `null` payloads are empty strings by definition. A file lives on the server; the generated
   * kinds are the server's arithmetic. Getting one of those wrong would put a confidently wrong
   * payload next to a result row, so they are left unnamed rather than reconstructed here.
   */
  const payloadSnapshot = (): IntruderPayloadSnapshot => ({
    mode,
    points: pointCount,
    sets: payloadTypes.map((t, i) => {
      if (t === "list") return payloadList(payloadTexts[i] ?? "");
      if (t === "null") return Array.from({ length: Number(payloadNulls[i] ?? "0") || 0 }, () => "");
      return null;
    }),
  });

  const onRun = async () => {
    setStoredRun(null);
    setMyTaskId(null);
    // Snapshot the attacks already running, so the one that appears next is unambiguously ours even
    // if an identical attack is running elsewhere. Best-effort: if the list cannot be read, fall
    // back to an empty prior set and the target/kind/newest match still finds it.
    try {
      const prior = await api<IntruderAttacksResp>("/api/intruder/attacks");
      priorIds.current = new Set(prior.attacks.map((a) => a.task_id));
    } catch {
      priorIds.current = new Set();
    }
    const snapshotAtLaunch = payloadSnapshot();
    const useSources = payloadTypes.some((t) => t !== "list");
    const usePool = poolName.trim() !== "";
    const body: Record<string, unknown> = {
      msg_id: Number(msgId),
      target: target.trim(),
      all: allPoints,
      mode,
      points: selected,
      // Manual markers go as raw byte ranges; the server splices them alongside the discovered
      // points and refuses one that overruns the request or overlaps another position.
      ...(manualSpans.length ? { manual_points: manualSpans.map(({ start, end }) => ({ start, end })) } : {}),
      max_requests: maxRequests,
      ...(rules.length ? { payload_rules: rules } : {}),
      // The final-pass encoding set (burpsy-react-ui-8cbc). Empty means none; the
      // default list is Burp's own.
      ...(urlEncodeChars !== "" ? { url_encode_characters: urlEncodeChars } : {}),
      // Both grep fields are RE2 patterns on the server. A literal typed in simple mode is quoted
      // here so it matches itself; regex mode sends what was typed (burpsy-react-ui-tpy).
      // Grep - Match: the list form when the operator typed expressions, else the legacy single
      // string. The two shapes are the same feature at two sizes and the server refuses both at
      // once, so exactly one of these two branches can ever fire (irt).
      ...(grepMatchList.some((e) => e.trim())
        ? {
            grep_match_list: grepMatchList.map((e) => e.trim()).filter(Boolean),
            grep_match_simple: grepMatchMode === "simple",
            ...(grepMatchMode === "simple" && grepMatchCaseSensitive ? { grep_match_case_sensitive: true } : {}),
            ...(grepMatchExcludeHeaders ? { grep_match_exclude_headers: true } : {}),
          }
        : grepMatch.trim()
        ? { grep_match: grepMatchMode === "simple" ? quoteRegex(grepMatch.trim()) : grepMatch.trim() }
        : {}),
      ...(grepExtract.trim() ? { grep_extract: grepExtract.trim() } : {}),
      // A named pool states rps, concurrency and throttling itself; the server refuses a request
      // that carries both, so the inline pair is omitted rather than sent and dropped.
      ...(usePool
        ? { pool: poolName.trim() }
        : {
            max_in_flight: maxInFlight,
            ...(rps.trim() ? { rps: Number(rps) } : {}),
            // Burp's resource-pool variations (nn0n). Omitted entirely when the operator left both
            // blank or zeroed, so an attack that does not vary its delay posts the wire shape it
            // always did — and the engine takes the flat token-bucket path it always took.
            ...delayVariationFields(delayJitterPct, delayIncrementMS),
          }),
      // Error handling (n39): empty means the server's default — Burp's own 3 retries with a
      // 2000ms pause. A field that names a number sends it; 0 disables retries.
      ...(retries.trim() !== "" ? { retries: Number(retries) } : {}),
      ...(retryDelayMS.trim() !== "" ? { retry_delay_ms: Number(retryDelayMS) } : {}),
      // Burp's "Make unmodified baseline request" (v34): sent only when asked, so the wire
      // shape for "off" stays what every existing client already posts.
      ...(baseline ? { baseline: true } : {}),
      // Burp's "Follow redirections" (tirx). Omitted, not sent as "", when the operator left it on
      // the standing policy — an absent field and an empty string must not become two different
      // wire shapes for "I did not choose", the same discipline url_encode_characters above holds.
      ...(redirectMode !== "" ? { follow_redirects: redirectMode } : {}),
      // Set Connection header and Store full payloads (fmxv). Sent only when asked, for the same
      // reason baseline above: the wire shape for "off" stays what every existing client posts, so
      // a saved attack resumes byte-for-byte as it did.
      ...(setConnectionClose ? { set_connection_close: true } : {}),
      ...(storePayloads ? { store_full_payloads: true } : {}),
    };
    if (useSources) {
      body.payload_sources = payloadTypes.map((t, i) => {
        if (t === "numbers") {
          const n = payloadNumbers[i] ?? { from: "1", to: "100", step: "1" };
          return { type: "numbers", from: Number(n.from), to: Number(n.to), step: Number(n.step) || 1 };
        }
        if (t === "file") {
          return { type: "file", filename: (payloadFiles[i] ?? "").trim() };
        }
        if (t === "brute_force") {
          const b = payloadBrute[i] ?? { charset: "abc", min_len: "1", max_len: "3" };
          return { type: "brute_force", charset: b.charset, min_len: Number(b.min_len) || 1, max_len: Number(b.max_len) || 1 };
        }
        if (t === "dates") {
          const d = payloadDates[i] ?? { from: "2024-01-01", to: "2024-12-31", step: "1", format: "yyyy-MM-dd" };
          return { type: "dates", from: d.from, to: d.to, step: Number(d.step) || 1, format: d.format };
        }
        if (t === "custom_iterator") {
          const c = payloadCustom[i] ?? { positions: "a,b\nc,d", separator: "" };
          return { type: "custom_iterator", positions: customIteratorSlots(c.positions), separator: c.separator };
        }
        if (t === "null") {
          return { type: "null", count: Number(payloadNulls[i] ?? "0") || 0 };
        }
        if (t === "char_substitution") {
          return {
            type: "char_substitution",
            words: payloadList(advField(i, "words")),
            subs: parseCharSubstitutions(advField(i, "subs")),
            max_per_word: Number(advField(i, "max_per_word")) || 0,
          };
        }
        if (t === "case_modification") {
          return {
            type: "case_modification",
            words: payloadList(advField(i, "words")),
            lower: advBool(i, "lower", true),
            upper: advBool(i, "upper", true),
            capitalize: advBool(i, "capitalize", true),
          };
        }
        if (t === "illegal_unicode") {
          const forms: ("overlong2" | "overlong3" | "overlong4")[] = [];
          if (advBool(i, "overlong2", true)) forms.push("overlong2");
          if (advBool(i, "overlong3", false)) forms.push("overlong3");
          if (advBool(i, "overlong4", false)) forms.push("overlong4");
          return {
            type: "illegal_unicode",
            chars: advField(i, "chars", "/"),
            forms,
            percent_encode: advBool(i, "percent_encode", true),
          };
        }
        if (t === "character_blocks") {
          return {
            type: "character_blocks",
            chars: advField(i, "chars", "A"),
            min_len: Number(advField(i, "min_len", "1")) || 1,
            max_len: Number(advField(i, "max_len", "100")) || 1,
            step: Number(advField(i, "step", "1")) || 1,
          };
        }
        if (t === "bit_flipper") {
          return { type: "bit_flipper", base: advField(i, "base") };
        }
        if (t === "username") {
          return { type: "username", names: payloadList(advField(i, "names")) };
        }
        if (t === "ecb_shuffler") {
          return {
            type: "ecb_shuffler",
            sample: advField(i, "sample"),
            encoding: advField(i, "encoding", "base64") as "base64" | "hex",
            block_size: Number(advField(i, "block_size", "16")) || 16,
          };
        }
        if (t === "copy_other") {
          return { type: "copy_other", position: Number(advField(i, "position", "0")) || 0 };
        }
        if (t === "recursive_grep") {
          return {
            type: "recursive_grep",
            initial: advField(i, "initial"),
            extract_re: advField(i, "extract_re"),
            stop_duplicate: advBool(i, "stop_duplicate", true),
          };
        }
        if (t === "collaborator") {
          return {
            type: "collaborator",
            count: Number(advField(i, "collab_count", "10")) || 10,
            include_location: advBool(i, "collab_include_location", true),
          };
        }
        return { type: "list", items: payloadList(payloadTexts[i] ?? "") };
      });
    } else {
      body.payload_sets = payloadTexts.map(payloadList);
    }
    run.mutate(body as unknown as IntruderRunRequest, {
      onSuccess: (payload) => {
        // Naming a mode always selects the full report shape, but stay defensive:
        // an older server could still answer with the flat legacy array.
        if (payload && typeof payload === "object" && "report" in payload) {
          const view = payload as RunView;
          setStoredRun({ view, legacy: null, snapshot: snapshotAtLaunch });
          setTab("results");
          toast.success(`${formatCount(view.report.sent)} requests sent in ${formatDuration(view.report.elapsed_ms)}`);
        } else {
          setStoredRun({ view: null, legacy: payload, snapshot: snapshotAtLaunch });
          setTab("results");
          toast.success("Attack finished");
        }
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
    });
  };

  // The payload upload (016): the operator's wordlist goes up as the request body, and the
  // response's stored path drops into this set's file-path field — the ordinary file source
  // resolves it, so an uploaded list and a server-side one are the same thing to the engine.
  const [uploading, setUploading] = useState(false);
  const uploadPayloadFile = async (index: number, file: File) => {
    setUploading(true);
    try {
      const res = await fetch("/api/intruder/payload-files", {
        method: "POST",
        headers: { "X-Payload-Filename": file.name },
        body: file,
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const out = (await res.json()) as { filename: string; lines: number };
      setPayloadFiles((cur) => cur.map((v, i) => (i === index ? out.filename : v)));
      toast.success(`Uploaded ${file.name} — ${formatCount(out.lines)} payloads; the server stored it as ${out.filename}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };
  /**
   * Why this attack will not launch, in the page's own terms.
   *
   * `canRun` is a boolean, and a menu item that refuses without a reason is the thing this bead
   * exists to avoid. The order matches the order an operator fills the form in, so the message names
   * the first thing still missing rather than the last.
   */
  const launchRefusal = (): string => {
    if (msgId.trim() === "") return "Choose a stored message id first.";
    if (!canDiscover) return `"${msgId}" is not a stored message id.`;
    if (target.trim() === "") return "The attack has no target authority.";
    if (selected.length === 0) return "No insertion points are selected — discover and choose some first.";
    const empty = setSizes.findIndex((size) => size !== null && size <= 0);
    if (empty >= 0) return `Payload set ${empty + 1} is empty, so there is nothing to send.`;
    return "This attack is not ready to launch.";
  };

  // Publish what this page permits so the menubar can grey its items truthfully, and say WHY when it
  // greys one. Only the mounted page knows an attack is in flight, so the menu reads it from here
  // rather than guessing.
  const launchRefusalNow = run.isPending ? "An attack is already running." : canRun ? null : launchRefusal();
  useEffect(() => {
    setStatus({ refusal: launchRefusalNow, running: run.isPending, controllable: myTaskId !== null });
  }, [launchRefusalNow, run.isPending, myTaskId, setStatus]);
  // Leaving the page takes the knowledge with it: a status left behind would tell the menubar an
  // attack is running long after the mutation that was running it was unmounted.
  useEffect(() => () => setStatus(null), [setStatus]);

  /**
   * Perform a menubar instruction.
   *
   * Depends on `command` alone on purpose: `onRun` and `controlAttack` are rebuilt every render, so
   * listing them would re-fire the effect — and re-firing this one launches an attack. The command
   * is cleared first, so a refusal consumes the instruction exactly like a launch does and a second
   * click is a second command (that is what the nonce is for).
   */
  useEffect(() => {
    if (!command) return;
    clearCommand();
    if (command.kind === "start") {
      if (run.isPending) {
        toast.info("An attack is already running — stop it before starting another");
        return;
      }
      if (!canRun) {
        toast.error(launchRefusal());
        return;
      }
      void onRun();
      return;
    }
    if (!run.isPending) {
      toast.info("No attack is running, so there is nothing to stop");
      return;
    }
    if (myTaskId === null) {
      toast.info("Still locating the attack — its controls appear in the header once it is named");
      return;
    }
    controlAttack("stop");
  }, [command]);

  // Only a known count can be over budget. When the estimate is a floor the guard may still fire —
  // a floor above the cap is certainly above it — but its silence proves nothing, which is why the
  // header says the number is a floor rather than presenting it as a count.
  const overBudget = estimate.count > maxRequests;
  const selectedPool = pools.data?.pools.find((pool) => pool.name === poolName) ?? null;

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Intruder"
          description={label || "Payload-driven attacks with explicit bounds and honest result accounting."}
          actions={
            <>
              <Tooltip
                content={
                  estimate.exact
                    ? "Requests this configuration implies"
                    : "A floor, not a count: a payload set reads a file on the server and its size is not knowable in the browser"
                }
              >
                <Badge tone={overBudget ? "warn" : estimate.exact ? "neutral" : "info"}>
                  {estimate.exact ? "" : "≥ "}
                  {formatCount(estimate.count)} request{estimate.count === 1 && estimate.exact ? "" : "s"}
                </Badge>
              </Tooltip>
              {msgId !== "" || result || legacyResult ? (
                <Button variant="outline" onClick={() => setConfirmReset(true)}>
                  <RotateCcw size={14} />
                  New attack
                </Button>
              ) : null}
              {/* Live controls for the attack in flight. They appear only once this page's task id
                  has been located in the attacks list — a control that cannot yet name its target is
                  worse than no control, so until then the badge says it is still locating. */}
              {run.isPending ? (
                myAttack ? (
                  <>
                    <Badge tone={myAttack.status === "paused" ? "warn" : "accent"}>
                      {myAttack.status === "paused" ? "paused" : "running"}
                    </Badge>
                    {myAttack.status === "paused" ? (
                      <Tooltip content="Resume the paused attack">
                        <Button variant="outline" onClick={() => controlAttack("resume")} disabled={attackAction.isPending}>
                          <Play size={14} />
                          Resume
                        </Button>
                      </Tooltip>
                    ) : (
                      <Tooltip content="Pause the attack; it holds its place and can be resumed">
                        <Button variant="outline" onClick={() => controlAttack("pause")} disabled={attackAction.isPending}>
                          <Pause size={14} />
                          Pause
                        </Button>
                      </Tooltip>
                    )}
                    <Tooltip content="Stop the attack; the report will show everything sent so far">
                      <Button variant="outline" onClick={() => controlAttack("stop")} disabled={attackAction.isPending}>
                        <Square size={14} />
                        Stop
                      </Button>
                    </Tooltip>
                  </>
                ) : (
                  <Badge tone="info">locating attack…</Badge>
                )
              ) : null}
              <Tooltip content={canRun ? "Run the attack" : "Choose a message, target, positions and payloads first"}>
                <button type="button" className="button button-primary" onClick={() => void onRun()} disabled={!canRun}>
                  <Zap size={14} />
                  {run.isPending ? "Attacking…" : "Launch attack"}
                </button>
              </Tooltip>
            </>
          }
        />

        {overBudget ? (
          <div className="notice notice-warn" style={{ marginTop: "var(--s2)" }}>
            <AlertTriangle size={15} />
            <div>
              This configuration implies {estimate.exact ? "" : "at least "}
              {formatCount(estimate.count)} requests but the cap is {formatCount(maxRequests)}. The server will stop at
              the cap and mark the report truncated. Raise the cap or narrow the payload sets.
            </div>
          </div>
        ) : !estimate.exact ? (
          <div className="notice" style={{ marginTop: "var(--s2)" }}>
            <AlertTriangle size={15} />
            <div>
              A payload set reads a file on the server, so the browser cannot size this attack: the count above is a
              floor and the cap of {formatCount(maxRequests)} has not been checked against the file's real length. The
              server enforces the cap and marks the report truncated if it is reached.
            </div>
          </div>
        ) : null}
      </div>

      {/* Burp splits Intruder across Positions / Payloads / Resource pool / Settings.
          Same split here, so the muscle memory carries over. */}
      <Tabs value={tab} onValueChange={setTab} className="tool-panel">
        <TabsList aria-label="Intruder configuration">
          <TabsTrigger value="positions">Positions</TabsTrigger>
          <TabsTrigger value="payloads">Payloads</TabsTrigger>
          <TabsTrigger value="pool">Resource pool</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="results">
            Results{result ? ` (${formatCount(result.report.sent)})` : ""}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="positions" className="tool-pane">
          <Card>
            <SectionHeading
              title="Base request"
              detail="A stored message id supplies the request that payloads are spliced into."
            />
            <div className="form-grid">
              <Field label="Stored message id">
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={1}
                    value={msgId}
                    onChange={(event) => {
                      setMsgId(event.target.value);
                      setPoints([]);
                      setSelected([]);
                      setManualSpans([]);
                    }}
                    placeholder="e.g. 42"
                  />
                )}
              </Field>
              <Field label="Target authority">
                {(id) => <Input id={id} value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://host:443" />}
              </Field>
              <Field label="Attack type">
                {(id) => (
                  <Select id={id} value={mode} onChange={(event) => setMode(event.target.value as AttackMode)}>
                    {ATTACK_MODES.map((entry) => (
                      <option key={entry.value} value={entry.value}>
                        {entry.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
            <p className="field-hint">{ATTACK_MODES.find((entry) => entry.value === mode)?.detail}</p>

            <div className="toolbar">
              <label className="check-row">
                <Switch
                  checked={allPoints}
                  onCheckedChange={(next) => {
                    setAllPoints(next);
                    setPoints([]);
                    setSelected([]);
                    setManualSpans([]);
                  }}
                  label="Include every candidate position"
                />
                <span>Every candidate position</span>
              </label>
              <Button variant="outline" onClick={onDiscover} disabled={!canDiscover || discover.isPending}>
                <Search size={14} />
                {discover.isPending ? "Scanning…" : "Find positions"}
              </Button>
              {/* Burp's Auto § and Clear §. Add § lives in the editor's selection menu below,
                  because it needs a selection and the editor is the only thing that has one. */}
              <Button variant="outline" onClick={onAutoMark} disabled={!canDiscover || discover.isPending}>
                <Crosshair size={14} />
                Auto §
              </Button>
              <Button variant="outline" onClick={onClearMarks} disabled={!manualSpans.length}>
                <Trash2 size={14} />
                Clear §
              </Button>
            </div>

            {discover.error ? <ErrorNotice error={discover.error} onRetry={onDiscover} /> : null}

            {manualSpans.length ? (
              <div className="row-list point-list">
                {manualSpans.map((span, i) => (
                  <div className="point-row" key={`${span.start}-${span.end}`}>
                    <span>
                      <strong>manual {i + 1}</strong>
                      <small>
                        bytes {span.start}–{span.end} · {span.text || "(empty)"}
                      </small>
                    </span>
                    {/* Manual markers are always used — there is no deselect, only removal. */}
                    <Badge tone="accent">used</Badge>
                    <Button
                      variant="ghost"
                      aria-label={`Remove manual marker ${i + 1}`}
                      onClick={() => setManualSpans((current) => current.filter((s) => s !== span))}
                    >
                      <Trash2 size={14} />
                    </Button>
                  </div>
                ))}
              </div>
            ) : null}

            {points.length ? (
              <div className="row-list point-list">
                {points.map((point) => {
                  const on = selected.includes(point.index);
                  const order = selected.indexOf(point.index);
                  return (
                    <label className="point-row" key={point.index}>
                      <input
                        type="checkbox"
                        checked={on}
                        aria-label={`Use position ${point.label}`}
                        onChange={(event) =>
                          setSelected((current) =>
                            event.target.checked
                              ? [...current, point.index]
                              : current.filter((index) => index !== point.index),
                          )
                        }
                      />
                      <span>
                        <strong>{point.label}</strong>
                        <small>
                          {point.kind} · offset {point.offset} · {point.current || "(empty)"}
                        </small>
                      </span>
                      {on && (mode === "pitchfork" || mode === "cluster_bomb") ? (
                        <Badge tone="accent">set {order + 1}</Badge>
                      ) : null}
                    </label>
                  );
                })}
              </div>
            ) : manualSpans.length ? null
            : canDiscover ? (
              <Empty title="No positions loaded" detail="Find positions before launching an attack." />
            ) : (
              <Empty
                title="No base request"
                detail="Enter a stored message id, or right-click a row in HTTP history and choose “Send to Intruder”."
              />
            )}
          </Card>

          {/* Rendered as soon as a message id exists, not once the fetch resolves, so
              the form never jumps out from under the pointer mid-click. */}
          {msgId ? (
            <Card className="card-flush tool-pane-fill">
              <HttpEditor
                label={`Base request · message ${msgId}`}
                readOnly
                // Shown with the markers folded in — the editor displays the same "§"-wrapped
                // request Burp's Positions tab does. The editor is read-only here, so the display
                // text cannot drift from the request the stored raw offsets were measured against.
                value={
                  baseMessage.data?.text
                    ? displayText(baseMessage.data.text, manualSpans)
                    : (baseMessage.isFetching
                      ? "Loading the base request…"
                      : baseMessage.error
                        ? `Could not load message ${msgId}.`
                        : "No bytes stored for this message.")
                }
                payloadMarks={{ onAdd: onAddManualSpan }}
                filename={`intruder-base-${msgId}.txt`}
              />
            </Card>
          ) : null}
        </TabsContent>

        <TabsContent value="payloads" className="tool-pane">
          <Card className="card-flush">
            <div className="card-pad">
              <SectionHeading
                title="Payload sets"
                detail={
                  setsNeeded === 1
                    ? "One payload per line."
                    : `${setsNeeded} sets — one per selected position, in selection order.`
                }
              />
            </div>
            <div className="card-pad stack">
              {Array.from({ length: setsNeeded }, (_, index) => {
                const t = payloadTypes[index] ?? "list";
                return (
                  <Card key={index} className="card-pad" style={{ border: "1px solid var(--line)" }}>
                    <div className="toolbar" style={{ marginBottom: 8 }}>
                      {/* "unknown" rather than a number for a server-side file: the count in this
                          label is the same number the header badge and the over-budget guard use. */}
                      <Field
                        label={`${setsNeeded === 1 ? "Set" : `Set ${index + 1}`} (${
                          setSizes[index] === null ? "unknown" : formatCount(setSizes[index] ?? 0)
                        })`}
                      >
                        {(id) => (
                          <Select
                            id={id}
                            value={t}
                            onChange={(e) =>
                              setPayloadTypes((cur) => cur.map((v, i) => (i === index ? (e.target.value as typeof t) : v)))
                            }
                          >
                            <option value="list">Simple list</option>
                            <option value="numbers">Numbers</option>
                            <option value="file">File (server path)</option>
                            <option value="brute_force">Brute force</option>
                            <option value="dates">Dates</option>
                            <option value="custom_iterator">Custom iterator</option>
                            <option value="null">Null payloads</option>
                            <option value="char_substitution">Character substitution</option>
                            <option value="case_modification">Case modification</option>
                            <option value="illegal_unicode">Illegal Unicode</option>
                            <option value="character_blocks">Character blocks (frobber)</option>
                            <option value="bit_flipper">Bit flipper</option>
                            <option value="username">Username generator</option>
                            <option value="ecb_shuffler">ECB block shuffler</option>
                            <option value="copy_other">Copy other payload</option>
                            <option value="recursive_grep">Recursive grep</option>
                            <option value="collaborator">Collaborator payloads</option>
                          </Select>
                        )}
                      </Field>
                      <Badge tone={t === "list" ? "neutral" : "accent"}>{t}</Badge>
                    </div>
                    {t === "list" ? (
                      <Field label="One payload per line">
                        {(id) => (
                          <Textarea
                            id={id}
                            value={payloadTexts[index] ?? ""}
                            onChange={(event) =>
                              setPayloadTexts((current) =>
                                current.map((value, position) => (position === index ? event.target.value : value)),
                              )
                            }
                            placeholder={index === 0 ? DEFAULT_PAYLOADS : "one payload per line"}
                          />
                        )}
                      </Field>
                    ) : t === "numbers" ? (
                      <div className="form-grid">
                        <Field label="From">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadNumbers[index]?.from ?? "1"}
                              onChange={(e) =>
                                setPayloadNumbers((cur) => cur.map((v, i) => (i === index ? { ...v, from: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="To">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadNumbers[index]?.to ?? "100"}
                              onChange={(e) =>
                                setPayloadNumbers((cur) => cur.map((v, i) => (i === index ? { ...v, to: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="Step">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadNumbers[index]?.step ?? "1"}
                              onChange={(e) =>
                                setPayloadNumbers((cur) => cur.map((v, i) => (i === index ? { ...v, step: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                      </div>
                    ) : t === "file" ? (
                      <div className="stack">
                        {/* The wordlist manager (kal): the inventory of bundled and uploaded
                            lists, one select instead of a path the operator must invent. The
                            builtin entries fill the path as "builtin:<name>" (resolved from
                            the binary), uploads as their stored path — both read by the same
                            file source, so nothing downstream changes. */}
                        <Field label="Available wordlists" hint="Bundled lists resolve from the binary; uploads from this session">
                          {(id) => (
                            <Select
                              id={id}
                              value=""
                              onChange={(e) => {
                                const ref = e.target.value;
                                if (!ref) return;
                                setPayloadFiles((cur) => cur.map((v, i) => (i === index ? ref : v)));
                              }}
                            >
                              <option value="">Choose a wordlist…</option>
                              {(wordlistsQuery.data?.wordlists ?? []).map((wl) => (
                                <option key={wl.ref} value={wl.ref}>
                                  {wl.name} ({wl.kind === "builtin" ? "bundled" : "upload"}, {wl.lines} lines)
                                </option>
                              ))}
                            </Select>
                          )}
                        </Field>
                        <Field label="Server file path" hint="File must exist on server; blank lines skipped. Bundled lists use builtin:<name>">
                          {(id) => (
                            <Input
                              id={id}
                              value={payloadFiles[index] ?? ""}
                              onChange={(e) =>
                                setPayloadFiles((cur) => cur.map((v, i) => (i === index ? e.target.value : v)))
                              }
                              placeholder="builtin:sqli-basic or /tmp/payloads.txt"
                            />
                          )}
                        </Field>
                        {/* Upload (016): the operator's own wordlist from their machine. The response's
                            stored path fills the field above, so the attack reads it through the ordinary
                            file source — the engine cannot tell an uploaded list from a server-side one,
                            which is the whole point. */}
                        <label className="field-label" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>
                          <input
                            type="file"
                            disabled={uploading}
                            style={{ maxWidth: 260 }}
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) void uploadPayloadFile(index, file);
                            }}
                          />
                          {uploading ? "uploading…" : "or upload from this machine"}
                        </label>
                      </div>
                    ) : t === "brute_force" ? (
                      <div className="form-grid">
                        <Field label="Charset">
                          {(id) => (
                            <Input
                              id={id}
                              value={payloadBrute[index]?.charset ?? "abc"}
                              onChange={(e) =>
                                setPayloadBrute((cur) => cur.map((v, i) => (i === index ? { ...v, charset: e.target.value } : v)))
                              }
                              placeholder="abc"
                            />
                          )}
                        </Field>
                        <Field label="Min length">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadBrute[index]?.min_len ?? "1"}
                              onChange={(e) =>
                                setPayloadBrute((cur) => cur.map((v, i) => (i === index ? { ...v, min_len: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="Max length">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadBrute[index]?.max_len ?? "3"}
                              onChange={(e) =>
                                setPayloadBrute((cur) => cur.map((v, i) => (i === index ? { ...v, max_len: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                      </div>
                    ) : t === "dates" ? (
                      <div className="form-grid">
                        <Field label="From (YYYY-MM-DD)">
                          {(id) => (
                            <Input
                              id={id}
                              value={payloadDates[index]?.from ?? "2024-01-01"}
                              onChange={(e) =>
                                setPayloadDates((cur) => cur.map((v, i) => (i === index ? { ...v, from: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="To">
                          {(id) => (
                            <Input
                              id={id}
                              value={payloadDates[index]?.to ?? "2024-12-31"}
                              onChange={(e) =>
                                setPayloadDates((cur) => cur.map((v, i) => (i === index ? { ...v, to: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="Step (days)">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadDates[index]?.step ?? "1"}
                              onChange={(e) =>
                                setPayloadDates((cur) => cur.map((v, i) => (i === index ? { ...v, step: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="Format">
                          {(id) => (
                            <Input
                              id={id}
                              value={payloadDates[index]?.format ?? "yyyy-MM-dd"}
                              onChange={(e) =>
                                setPayloadDates((cur) => cur.map((v, i) => (i === index ? { ...v, format: e.target.value } : v)))
                              }
                              placeholder="yyyy-MM-dd"
                            />
                          )}
                        </Field>
                      </div>
                    ) : t === "custom_iterator" ? (
                      <div className="stack">
                        <Field label="Positions (one set per line, comma-separated)" hint="Two or more lines, each line is a slot: a,b,c">
                          {(id) => (
                            <Textarea
                              id={id}
                              value={payloadCustom[index]?.positions ?? "a,b\nc,d"}
                              onChange={(e) =>
                                setPayloadCustom((cur) => cur.map((v, i) => (i === index ? { ...v, positions: e.target.value } : v)))
                              }
                              placeholder="a,b,c&#10;1,2,3"
                            />
                          )}
                        </Field>
                        <Field label="Separator">
                          {(id) => (
                            <Input
                              id={id}
                              value={payloadCustom[index]?.separator ?? ""}
                              onChange={(e) =>
                                setPayloadCustom((cur) => cur.map((v, i) => (i === index ? { ...v, separator: e.target.value } : v)))
                              }
                              placeholder="e.g. / or empty"
                            />
                          )}
                        </Field>
                      </div>
                    ) : t === "null" ? (
                      <Field label="Count (number of empty payloads)">
                        {(id) => (
                          <Input
                            id={id}
                            type="number"
                            value={payloadNulls[index] ?? "10"}
                            onChange={(e) =>
                              setPayloadNulls((cur) => cur.map((v, i) => (i === index ? e.target.value : v)))
                            }
                          />
                        )}
                      </Field>
                    ) : t === "char_substitution" ? (
                      <div className="stack">
                        <Field label="Words (one per line)">
                          {(id) => (
                            <Textarea id={id} value={advField(index, "words")} onChange={(e) => setAdvField(index, "words", e.target.value)} placeholder="password&#10;admin" />
                          )}
                        </Field>
                        <Field label="Substitutions (one per line, char=replacement)" hint="e.g. e=3 to substitute every 'e' with '3' in some combinations">
                          {(id) => (
                            <Textarea id={id} value={advField(index, "subs")} onChange={(e) => setAdvField(index, "subs", e.target.value)} placeholder="e=3&#10;a=4&#10;o=0" />
                          )}
                        </Field>
                        <Field label="Max combinations per word" hint="0 = unbounded (still capped by max payloads overall)">
                          {(id) => <Input id={id} type="number" min={0} value={advField(index, "max_per_word")} onChange={(e) => setAdvField(index, "max_per_word", e.target.value)} placeholder="0" />}
                        </Field>
                      </div>
                    ) : t === "case_modification" ? (
                      <div className="stack">
                        <Field label="Words (one per line)">
                          {(id) => <Textarea id={id} value={advField(index, "words")} onChange={(e) => setAdvField(index, "words", e.target.value)} placeholder="admin&#10;root" />}
                        </Field>
                        <div className="row-list">
                          <Checkbox checked={advBool(index, "lower", true)} onCheckedChange={(v) => setAdvBool(index, "lower", v)} label="lower case" />
                          <Checkbox checked={advBool(index, "upper", true)} onCheckedChange={(v) => setAdvBool(index, "upper", v)} label="UPPER CASE" />
                          <Checkbox checked={advBool(index, "capitalize", true)} onCheckedChange={(v) => setAdvBool(index, "capitalize", v)} label="Capitalize" />
                        </div>
                      </div>
                    ) : t === "illegal_unicode" ? (
                      <div className="stack">
                        <Field label="Characters (each must be ASCII)">
                          {(id) => <Input id={id} value={advField(index, "chars", "/")} onChange={(e) => setAdvField(index, "chars", e.target.value)} placeholder="/" />}
                        </Field>
                        <div className="row-list">
                          <Checkbox checked={advBool(index, "overlong2", true)} onCheckedChange={(v) => setAdvBool(index, "overlong2", v)} label="overlong 2-byte" />
                          <Checkbox checked={advBool(index, "overlong3", false)} onCheckedChange={(v) => setAdvBool(index, "overlong3", v)} label="overlong 3-byte" />
                          <Checkbox checked={advBool(index, "overlong4", false)} onCheckedChange={(v) => setAdvBool(index, "overlong4", v)} label="overlong 4-byte" />
                          <Checkbox checked={advBool(index, "percent_encode", true)} onCheckedChange={(v) => setAdvBool(index, "percent_encode", v)} label="%-encode (for a URL/query context)" />
                        </div>
                      </div>
                    ) : t === "character_blocks" ? (
                      <div className="form-grid">
                        <Field label="Characters (cycled to fill each block)">
                          {(id) => <Input id={id} value={advField(index, "chars", "A")} onChange={(e) => setAdvField(index, "chars", e.target.value)} placeholder="A" />}
                        </Field>
                        <Field label="Min length">
                          {(id) => <Input id={id} type="number" min={0} value={advField(index, "min_len", "1")} onChange={(e) => setAdvField(index, "min_len", e.target.value)} />}
                        </Field>
                        <Field label="Max length">
                          {(id) => <Input id={id} type="number" min={0} value={advField(index, "max_len", "100")} onChange={(e) => setAdvField(index, "max_len", e.target.value)} />}
                        </Field>
                        <Field label="Step">
                          {(id) => <Input id={id} type="number" value={advField(index, "step", "1")} onChange={(e) => setAdvField(index, "step", e.target.value)} />}
                        </Field>
                      </div>
                    ) : t === "bit_flipper" ? (
                      <Field label="Base value" hint="One payload per bit of this value, with that bit inverted.">
                        {(id) => <Input id={id} value={advField(index, "base")} onChange={(e) => setAdvField(index, "base", e.target.value)} placeholder="e.g. a sample cookie or token value" />}
                      </Field>
                    ) : t === "username" ? (
                      <Field label="Full names (one per line, e.g. 'John Smith')" hint="Generates first, last, first.last, firstlast, flast and firstl for each name.">
                        {(id) => <Textarea id={id} value={advField(index, "names")} onChange={(e) => setAdvField(index, "names", e.target.value)} placeholder="John Smith&#10;Ada Lovelace" />}
                      </Field>
                    ) : t === "ecb_shuffler" ? (
                      <div className="form-grid">
                        <Field label="Sample value (already encoded)" hint="A captured encrypted value, e.g. a session cookie">
                          {(id) => <Input id={id} value={advField(index, "sample")} onChange={(e) => setAdvField(index, "sample", e.target.value)} placeholder="base64 or hex" />}
                        </Field>
                        <Field label="Encoding">
                          {(id) => (
                            <Select id={id} value={advField(index, "encoding", "base64")} onChange={(e) => setAdvField(index, "encoding", e.target.value)}>
                              <option value="base64">Base64</option>
                              <option value="hex">Hex</option>
                            </Select>
                          )}
                        </Field>
                        <Field label="Block size (bytes)" hint="16 for AES, 8 for DES/3DES/Blowfish">
                          {(id) => <Input id={id} type="number" min={1} value={advField(index, "block_size", "16")} onChange={(e) => setAdvField(index, "block_size", e.target.value)} />}
                        </Field>
                      </div>
                    ) : t === "copy_other" ? (
                      <Field
                        label="Position to copy (0-based)"
                        hint="Pitchfork only — every position advances in lockstep there, which is what makes this position's payload match the named one on every request. Refused in cluster bomb, where that guarantee does not hold (see the server's own error)."
                      >
                        {(id) => <Input id={id} type="number" min={0} value={advField(index, "position", "0")} onChange={(e) => setAdvField(index, "position", e.target.value)} />}
                      </Field>
                    ) : t === "collaborator" ? (
                      <div className="stack">
                        <Field
                          label="Number of payloads to generate"
                          hint="One fresh out-of-band address per payload, minted when the attack launches and listed on the Collaborator page. Bounded at 100 by the server, like the Collaborator page's own batch."
                        >
                          {(id) => <Input id={id} type="number" min={1} max={100} value={advField(index, "collab_count", "10")} onChange={(e) => setAdvField(index, "collab_count", e.target.value)} />}
                        </Field>
                        <Checkbox
                          checked={advBool(index, "collab_include_location", true)}
                          onCheckedChange={(v) => setAdvBool(index, "collab_include_location", v)}
                          label="Include Collaborator server location"
                        />
                        <p className="cell-dim">
                          Each payload is a unique address on the interaction channel. Unchecking the server location yields the bare interaction id — it cannot receive a callback by itself. The attack refuses to launch when no interaction server is configured, rather than inserting a placeholder.
                        </p>
                      </div>
                    ) : t === "recursive_grep" ? (
                      <div className="stack">
                        <Field
                          label="Initial payload for first request"
                          hint="The chain starts here — the first extraction needs a response to read."
                        >
                          {(id) => <Input id={id} value={advField(index, "initial")} onChange={(e) => setAdvField(index, "initial", e.target.value)} placeholder="e.g. a — the first row key to enumerate" />}
                        </Field>
                        <Field
                          label="Extract grep item (regex)"
                          hint="First capture group of its match in the previous response becomes the next payload; the whole match when the pattern has no group. Capture capped at 256 bytes."
                        >
                          {(id) => <Input id={id} value={advField(index, "extract_re")} onChange={(e) => setAdvField(index, "extract_re", e.target.value)} placeholder="e.g. next: ([a-z]+)" />}
                        </Field>
                        <Checkbox
                          checked={advBool(index, "stop_duplicate", true)}
                          onCheckedChange={(v) => setAdvBool(index, "stop_duplicate", v)}
                          label="Stop if duplicate payload found"
                        />
                        <p className="cell-dim">
                          Runs one request at a time (each payload derives from the previous response — the server forces max_in_flight to 1, as Burp forces its resource pool for these attacks). The chain ends when the extract matches nothing, or on a duplicate if checked; the report lists every derived payload per request.
                        </p>
                      </div>
                    ) : null}
                  </Card>
                );
              })}
            </div>
          </Card>

          <Card>
            <SectionHeading
              title="Payload processing"
              detail="Rules run in order on every payload before it is sent."
              actions={
                <Button
                  variant="outline"
                  size="small"
                  onClick={() => setRules((current) => [...current, emptyRule("add_prefix")])}
                >
                  <Plus size={13} />
                  Add rule
                </Button>
              }
            />
            {rules.length ? (
              rules.map((rule, index) => (
                <RuleRow
                  key={index}
                  rule={rule}
                  index={index}
                  onChange={(next) =>
                    setRules((current) => current.map((value, position) => (position === index ? next : value)))
                  }
                  onRemove={() => setRules((current) => current.filter((_, position) => position !== index))}
                />
              ))
            ) : (
              <p className="field-hint">No processing rules. Payloads are sent exactly as written.</p>
            )}
            {/* Burp's "URL-encode these characters" (burpsy-react-ui-8cbc): a final pass over
                every generated payload, after the rules regardless of payload type — the
                safety net that keeps a payload from breaking the request it travels in.
                Spaces and control characters are always encoded additionally server-side,
                because a request containing them cannot be delivered. */}
            <div className="card-pad" style={{ borderTop: "1px solid var(--line)" }}>
              <Field
                label="URL-encode these characters"
                hint="Percent-encoded in every payload as the final step before sending. Clear the box to disable."
              >
                {(id) => (
                  <Input
                    id={id}
                    value={urlEncodeChars}
                    onChange={(event) => setURLEncodeChars(event.target.value)}
                    placeholder="=&+%;?/ #:"
                  />
                )}
              </Field>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="pool" className="tool-pane">
          <Card>
            <SectionHeading
              title="Saved resource pool"
              detail="Bind this attack to a pool created in Settings → Resource pools, so several tools share one authorised rate."
            />
            {pools.error ? (
              <ErrorNotice error={pools.error} onRetry={() => pools.refetch()} />
            ) : (
              <>
                <div className="form-grid">
                  <Field
                    label="Resource pool"
                    hint="A pool states the rate and concurrency; selecting one replaces the inline limits below."
                  >
                    {(id) => (
                      <Select
                        id={id}
                        value={poolName}
                        disabled={pools.isLoading || !pools.data?.pools.length}
                        onChange={(event) => setPoolName(event.target.value)}
                      >
                        <option value="">Inline limits (no saved pool)</option>
                        {(pools.data?.pools ?? []).map((pool) => (
                          <option key={pool.name} value={pool.name}>
                            {pool.name}
                          </option>
                        ))}
                      </Select>
                    )}
                  </Field>
                </div>
                {pools.isLoading ? (
                  <p className="field-hint">Loading saved pools…</p>
                ) : !pools.data?.pools.length ? (
                  <p className="field-hint">
                    No pools are saved. Create one under Settings → Resource pools; until then this attack runs on the
                    inline limits below.
                  </p>
                ) : null}
                {/* A pool the report will name but whose bounds are gone is the failure this guards:
                    the server refuses an unknown name outright, so say so before the launch does. */}
                {poolName && !pools.isLoading && !selectedPool ? (
                  <div className="notice notice-warn">
                    <AlertTriangle size={15} />
                    <div>
                      The pool <strong>{poolName}</strong> is no longer saved. The server refuses an attack naming a pool
                      it cannot resolve, so pick another pool or go back to inline limits.
                    </div>
                  </div>
                ) : null}
                {selectedPool ? (
                  <p className="field-hint">
                    <strong>{selectedPool.name}</strong> enforces {formatCount(selectedPool.max_concurrent)} concurrent
                    request{selectedPool.max_concurrent === 1 ? "" : "s"}
                    {selectedPool.delay_ms ? ` and a ${formatDuration(selectedPool.delay_ms)} delay between them` : " with no delay between them"}
                    {selectedPool.throttle ? ", plus automatic throttling" : ""}. Max requests below still applies — it
                    bounds the attack's size, not its rate.
                  </p>
                ) : null}
              </>
            )}
          </Card>

          <Card>
            <SectionHeading
              title="Inline limits"
              detail="An attack is always bounded. Max requests always applies; concurrency and rate apply only when no pool is selected."
            />
            <div className="form-grid">
              <Field label="Max requests">
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={1}
                    value={maxRequests}
                    onChange={(event) => setMaxRequests(Number(event.target.value) || 1)}
                  />
                )}
              </Field>
              <Field
                label="Max concurrent requests"
                hint={poolName ? "Set by the selected pool." : undefined}
              >
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={1}
                    disabled={poolName !== ""}
                    value={poolName ? (selectedPool ? selectedPool.max_concurrent : "") : maxInFlight}
                    onChange={(event) => setMaxInFlight(Number(event.target.value) || 1)}
                  />
                )}
              </Field>
              <Field
                label="Requests per second"
                hint={poolName ? "Set by the selected pool." : "Blank leaves it unthrottled."}
              >
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={0}
                    step="0.5"
                    disabled={poolName !== ""}
                    value={poolName ? "" : rps}
                    onChange={(event) => setRps(event.target.value)}
                    placeholder={poolName ? "from the pool" : "unlimited"}
                  />
                )}
              </Field>
              {/* Burp's two resource-pool variations (nn0n). A flat rate is a signature: a lockout
                  counter that a constant rate trips at request N trips at request N every run. The
                  engine schedules each gap itself when either of these is set — seeded, so the
                  delays a run took can be replayed — and refuses a variation it cannot honour
                  rather than quietly moving it to one it can. */}
              <Field
                label="With random variations (± %)"
                hint={
                  poolName
                    ? "Set by the selected pool."
                    : "Burp's resource-pool option. Each gap between requests lands within this percentage of the interval the rate above states. Blank or 0 is a flat delay; 100 or more is refused."
                }
              >
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={0}
                    max={99}
                    step="5"
                    disabled={poolName !== ""}
                    value={poolName ? "" : delayJitterPct}
                    onChange={(event) => setDelayJitterPct(event.target.value)}
                    placeholder={poolName ? "from the pool" : "no variation"}
                  />
                )}
              </Field>
              <Field
                label="Increase delay between requests (ms)"
                hint={
                  poolName
                    ? "Set by the selected pool."
                    : "Burp's delay increment: every gap is this many milliseconds longer than the one before it, so an attack that starts inside a rate-limit window stays inside it as the window fills. Blank or 0 does not ramp."
                }
              >
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={0}
                    max={600000}
                    disabled={poolName !== ""}
                    value={poolName ? "" : delayIncrementMS}
                    onChange={(event) => setDelayIncrementMS(event.target.value)}
                    placeholder={poolName ? "from the pool" : "no increase"}
                  />
                )}
              </Field>
            </div>
          </Card>

          <Card>
            <SectionHeading
              title="Error handling"
              detail="What happens when the target hiccups. Burp's defaults apply when these are blank."
            />
            <div className="form-grid">
              <Field
                label="Retries on network failure"
                hint="How many times a failed request is sent again before its error counts. Blank = 3 (Burp's default); 0 disables. A retried request is still one attempt — the report counts retries separately."
              >
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={0}
                    value={retries}
                    onChange={(event) => setRetries(event.target.value)}
                    placeholder="3"
                  />
                )}
              </Field>
              <Field
                label="Pause before retry (ms)"
                hint="How long to wait between retries. Blank = 2000ms (Burp's default). Bounded at 600000, Burp's own validation."
              >
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={0}
                    max={600000}
                    value={retryDelayMS}
                    onChange={(event) => setRetryDelayMS(event.target.value)}
                    placeholder="2000"
                  />
                )}
              </Field>
              <Checkbox
                checked={baseline}
                onCheckedChange={(v) => setBaseline(v)}
                label="Make unmodified baseline request"
              />
              <p className="cell-dim">
                Issues the template with every position at its base value as item 0 — "Baseline request (no payloads)" — so the attack responses hang against a base response to compare with. Every result ordinal shifts by one.
              </p>
              {/* Burp's remaining two attack settings (fmxv). The engine has implemented both
                  since 29a7ee3; this is the first path a request has to reach them, and the first
                  time an operator can see either one at all. */}
              <Checkbox
                checked={setConnectionClose}
                onCheckedChange={(v) => setSetConnectionClose(v)}
                label="Set Connection header"
              />
              <p className="cell-dim">
                Adds or updates <code>Connection: close</code> on every request this attack sends. Applied after the
                payloads are spliced in, so an existing header keeps its spelling and spacing and only its value changes.
              </p>
              <Checkbox
                checked={storePayloads}
                onCheckedChange={(v) => setStorePayloads(v)}
                label="Store full payloads"
              />
              <p className="cell-dim">
                Keeps each result&apos;s full payload values, so the report can name the payloads behind a row instead of
                an ordinal. Costs a small per-row slice header over the payload strings the attack already holds — the
                bytes are shared, not copied.
              </p>
              {/* Burp's third attack setting, and the one this build does not implement. Said here
                  rather than left to be discovered at the target: "Use denial-of-service mode" sends
                  the request and deliberately does not read the response, which needs a fire-and-forget
                  send AND every attempt-recording path to learn "no response was read" instead of
                  counting a zero-length one. A checkbox that quietly reported an empty response as a
                  zero-length 0 would be the exact lie this project treats as worse than the gap. */}
              <p className="field-hint">
                <strong>Use denial-of-service mode is not implemented.</strong> Burp sends each request and
                deliberately does not read the response. Doing that honestly here needs a send that can
                leave without reading, plus every place an attempt records its status, length and
                reflection to carry &ldquo;no response was read&rdquo; rather than a zero — otherwise the
                report would count a request it never saw an answer to.
              </p>
            </div>
            {poolName ? (
              <p className="field-hint">
                Concurrency and rate are disabled because a pool is selected. The server refuses a request that carries
                both — a pool already answers “how fast may this attack run”, and accepting a second answer would mean
                dropping one while the report still named the pool.
              </p>
            ) : null}
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="tool-pane">
          {/* Both fields are compiled by RE2 on the server (buildGrep in api_tools.go). They used to
              be labelled and placeheld as literal strings, so following the placeholder produced a
              control that silently did nothing useful (burpsy-react-ui-tpy). Match type is Burp's
              own answer to that: a simple string is quoted here before it is sent. */}
          <Card>
            <SectionHeading
              title="Grep — match and extract"
              detail="Count the responses that match, or capture a value out of each response."
            />
            <div className="form-grid">
              <Field label="Match type" hint="Whether Grep match is a literal string or a regular expression.">
                {(id) => (
                  <Select
                    id={id}
                    value={grepMatchMode}
                    onChange={(event) => setGrepMatchMode(event.target.value as "simple" | "regex")}
                  >
                    <option value="simple">Simple string</option>
                    <option value="regex">Regular expression</option>
                  </Select>
                )}
              </Field>
              <Field
                label="Grep match — expressions (one per line)"
                hint="One results column per expression, counting every occurrence in each response (irt). Leave empty to use the single expression below. Empty lines are skipped."
              >
                {(id) => (
                  <Textarea
                    id={id}
                    value={grepMatchList.join("\n")}
                    onChange={(event) => setGrepMatchList(event.target.value.split("\n"))}
                    placeholder={"error\nexception\ninvalid\nSQL syntax"}
                  />
                )}
              </Field>
              <div className="row-list">
                <Checkbox
                  checked={grepMatchCaseSensitive}
                  onCheckedChange={(v) => setGrepMatchCaseSensitive(v)}
                  label="Case sensitive match (simple-string mode only)"
                />
                <Checkbox
                  checked={grepMatchExcludeHeaders}
                  onCheckedChange={(v) => setGrepMatchExcludeHeaders(v)}
                  label="Exclude HTTP headers"
                />
              </div>
              <Field
                label="Grep match (single expression)"
                hint={
                  grepMatchList.some((e) => e.trim())
                    ? "Ignored while the expression list above has entries — the list is the same feature at a larger size, and the server refuses both at once."
                    : grepMatchMode === "simple"
                    ? "Counts responses containing this exact text. Regex characters in it are escaped for you."
                    : "Counts responses matching this regular expression (RE2). Alternate with |."
                }
              >
                {(id) => (
                  <Input
                    id={id}
                    value={grepMatch}
                    onChange={(event) => setGrepMatch(event.target.value)}
                    placeholder={grepMatchMode === "simple" ? "root:" : "error|root:|welcome"}
                  />
                )}
              </Field>
              <Field
                label="Grep extract (regular expression)"
                hint="Captures the first capture group of the first match, or the whole match when the pattern has no group. A pattern with no group returns the marker itself."
              >
                {(id) => (
                  <Input
                    id={id}
                    value={grepExtract}
                    onChange={(event) => setGrepExtract(event.target.value)}
                    placeholder="token=([^&\s;]+)"
                  />
                )}
              </Field>
            </div>
          </Card>

          <Card>
            <SectionHeading
              title="Redirections"
              detail="Burp's tools/intruder/configure-attack/settings.html: whether an attack chases a 3xx to the page that actually carries the result."
            />
            <div className="form-grid">
              <Field
                label="Follow redirections"
                hint="Every hop is re-authorised against scope on its own rendered bytes, the same gate the request itself went through — a payload can steer a hop somewhere nobody named."
              >
                {(id) => (
                  <Select id={id} value={redirectMode} onChange={(event) => setRedirectMode(event.target.value as FollowRedirectsMode | "")}>
                    <option value="">Standing network policy (Never, unless changed in Network settings)</option>
                    {FOLLOW_REDIRECTS_MODES.map((m) => (
                      <option key={m.value} value={m.value}>
                        {m.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="results" className="tool-pane">
          {run.error ? <ErrorNotice error={run.error} onRetry={onRun} /> : null}

          {/* The live attack window. While /run holds its response open there is no report to render,
              but the attack is not silent: the settled-send counts move every second (the attacks
              poll), and the controls are the same ones the header carries — Burp's results window is
              where an operator goes to watch, so the watching view carries the controls too. The
              per-row report still arrives only when the attack completes; pretending otherwise would
              render rows the collector has not folded yet. */}
          {run.isPending ? (
            <Card>
              <SectionHeading
                title="Attack in progress"
                detail={
                  myAttack
                    ? "Counts are live; the full report arrives when the attack ends."
                    : "Finding this attack in the running list…"
                }
              />
              {myAttack ? (
                <div className="stack">
                  <div className="toolbar">
                    <Badge tone={myAttack.status === "paused" ? "warn" : "accent"}>
                      {myAttack.status === "paused" ? "paused" : "running"}
                    </Badge>
                    <span className="cell-dim">
                      {formatCount(myAttack.sent)} got responses, {formatCount(myAttack.failed)} failed — of{" "}
                      {formatCount(myAttack.planned)} planned
                    </span>
                    <span style={{ flex: 1 }} />
                    {myAttack.status === "paused" ? (
                      <Tooltip content="Resume the paused attack">
                        <Button variant="outline" onClick={() => controlAttack("resume")} disabled={attackAction.isPending}>
                          <Play size={14} />
                          Resume
                        </Button>
                      </Tooltip>
                    ) : (
                      <Tooltip content="Pause the attack; it holds its place and can be resumed">
                        <Button variant="outline" onClick={() => controlAttack("pause")} disabled={attackAction.isPending}>
                          <Pause size={14} />
                          Pause
                        </Button>
                      </Tooltip>
                    )}
                    <Tooltip content="Stop the attack; the report will show everything sent so far">
                      <Button variant="outline" onClick={() => controlAttack("stop")} disabled={attackAction.isPending}>
                        <Square size={14} />
                        Stop
                      </Button>
                    </Tooltip>
                  </div>
                  <div className="progress-track" aria-hidden="true">
                    <div
                      className="progress-fill"
                      style={{
                        width:
                          myAttack.planned > 0
                            ? `${Math.min(100, ((myAttack.sent + myAttack.failed) / myAttack.planned) * 100)}%`
                            : "0%",
                      }}
                    />
                  </div>
                </div>
              ) : (
                <Badge tone="info">locating attack…</Badge>
              )}
            </Card>
          ) : null}

          {result ? (
            <AttackResult
              view={result}
              examples={examples}
              snapshot={snapshot}
              onOpenMessage={(id, messageLabel) => setOpenMessage({ id, label: messageLabel })}
              bucketMenu={bucketMenu}
              attemptMenu={attemptMenu}
            />
          ) : null}

          {legacyResult ? (
            <Card>
              <SectionHeading title="Attack result" detail="This server answered with the legacy per-attempt form." />
              <JsonView value={legacyResult} label="attempts" />
            </Card>
          ) : null}

          {!result && !legacyResult && !run.isPending && !run.error ? (
            <Empty
              title="No attack run yet"
              detail="Pick a base request, choose positions and payloads, then launch. The report shows what was sent and what was bounded away."
              action={
                <Badge tone="info">
                  <Crosshair size={11} />
                  {estimate.exact ? "" : "at least "}
                  {formatCount(estimate.count)} requests planned
                </Badge>
              }
            />
          ) : null}
        </TabsContent>
      </Tabs>

      {openMessage ? (
        <StoredMessage id={openMessage.id} label={openMessage.label} onClose={() => setOpenMessage(null)} />
      ) : null}

      <Modal
        open={confirmReset}
        onOpenChange={setConfirmReset}
        title="Start a new attack?"
        description="This discards the current configuration and the report it produced. Neither can be recovered."
      >
        <div className="toolbar">
          <Button variant="outline" onClick={() => setConfirmReset(false)}>
            Keep this attack
          </Button>
          <button
            type="button"
            className="button button-primary"
            onClick={() => {
              setConfig(emptyIntruderConfig());
              setStoredRun(null);
              setTab("positions");
              setConfirmReset(false);
            }}
          >
            Discard and start over
          </button>
        </div>
      </Modal>
    </div>
  );
}
