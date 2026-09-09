import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Crosshair, Download, FileSearch, Pause, Play, Plus, RotateCcw, Search, Square, Trash2, X, Zap } from "lucide-react";
import { toast } from "sonner";
import { api, downloadText, formatBytes, formatCount, formatDuration, statusTone } from "../lib/api";
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
} from "../lib/data.tools";
import { usePools } from "../lib/data.pools";
import { useMessage } from "../lib/data";
import { addManualSpan, displayText, selectionToRawSpan } from "../lib/intruder-marks";
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
  type Attempt,
  type AttackMode,
  type ErrorBucket,
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
 * The attack report, presented as accounting rather than a payload dump: every
 * bound the engine applied (capped, truncated, skipped, unbucketed) is shown, so
 * a small result set is never mistaken for a complete one.
 */
function AttackResult({
  view,
  examples,
  snapshot,
  onOpenMessage,
}: {
  view: RunView;
  examples: Map<number, string[]>;
  snapshot: IntruderPayloadSnapshot | null;
  onOpenMessage: (id: number, label: string) => void;
}): JSX.Element {
  const { report, payload_sets: sets } = view;

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
    {
      accessorFn: (attempt) => attempt.error ?? undefined,
      id: "error",
      header: "Error",
      sortUndefined: "last",
      cell: ({ row }) => (row.original.error ? <span title={row.original.error}>{row.original.error}</span> : <span className="cell-dim">—</span>),
    },
    {
      id: "response",
      header: "Response",
      enableSorting: false,
      cell: ({ row }) => (
        <ResponseCell id={row.original.response_id} label={`Response to attempt ${row.original.ordinal}`} onOpen={onOpenMessage} />
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
  ].filter((value): value is string => value !== null);

  return (
    <>
      <div className="toolbar">
        <Tooltip content="Download the attack's per-attempt rows as a CSV; the caveats ride at the top of the file">
          <Button
            variant="outline"
            onClick={() => {
              const file = intruderExportFilenames(report).csv;
              downloadText(file, intruderReportToCSV(report, report.attempts, payloadsAt), "text/csv");
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

  // The whole configuration lives in the store, not in this component: app.tsx mounts one page at
  // a time, so component-local state was destroyed by any nav click, taking the finished report
  // with it (burpsy-react-ui-rby). The field setters below keep the shape the JSX already used.
  const config = useApp((state) => state.intruder);
  const setConfig = useApp((state) => state.setIntruder);
  const storedRun = useApp((state) => state.intruderRun);
  const setStoredRun = useApp((state) => state.setIntruderRun);
  const tab = useApp((state) => state.intruderTab);
  const setTab = useApp((state) => state.setIntruderTab);

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
    poolName,
    maxRequests,
    maxInFlight,
    rps,
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
  const setGrepMatch = field("grepMatch");
  const setGrepMatchMode = field("grepMatchMode");
  const setGrepExtract = field("grepExtract");
  const setPoolName = field("poolName");
  const setMaxRequests = field("maxRequests");
  const setMaxInFlight = field("maxInFlight");
  const setRps = field("rps");

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
      ...(grepMatch.trim()
        ? { grep_match: grepMatchMode === "simple" ? quoteRegex(grepMatch.trim()) : grepMatch.trim() }
        : {}),
      ...(grepExtract.trim() ? { grep_extract: grepExtract.trim() } : {}),
      // A named pool states rps, concurrency and throttling itself; the server refuses a request
      // that carries both, so the inline pair is omitted rather than sent and dropped.
      ...(usePool
        ? { pool: poolName.trim() }
        : { max_in_flight: maxInFlight, ...(rps.trim() ? { rps: Number(rps) } : {}) }),
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
                      <Field label="Server file path" hint="File must exist on server; blank lines skipped">
                        {(id) => (
                          <Input
                            id={id}
                            value={payloadFiles[index] ?? ""}
                            onChange={(e) =>
                              setPayloadFiles((cur) => cur.map((v, i) => (i === index ? e.target.value : v)))
                            }
                            placeholder="/tmp/payloads.txt or ./wordlists/sqli.txt"
                          />
                        )}
                      </Field>
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
                label="Grep match"
                hint={
                  grepMatchMode === "simple"
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
