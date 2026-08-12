import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { Columns3, Combine, Crosshair, HelpCircle, Repeat2, Search, X } from "lucide-react";
import { toast } from "sonner";
import { useExchangeActions, exchangeUrl } from "../lib/actions";
import { formatBytes, formatDuration, relativeTime, statusTone } from "../lib/api";
import { cn } from "../lib/cn";
import { useAnnotateExchange, useDebounced, useHistory, useMessage } from "../lib/data";
import { useScopeView } from "../lib/data.policy";
import { useApp } from "../lib/store";
import { HIGHLIGHTS, type Exchange } from "../lib/types";
import type { ScopeRuleView, ScopeView } from "../lib/types.policy";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Button, Empty, ErrorNotice, IconButton, Input, Modal, Select, Toolbar, Tooltip } from "../ui/primitives";
import { VirtualTable, type Column } from "../ui/table";

const STATUS_BUCKETS = [
  { value: "all", label: "All statuses" },
  { value: "2", label: "2xx success" },
  { value: "3", label: "3xx redirect" },
  { value: "4", label: "4xx client" },
  { value: "5", label: "5xx server" },
  { value: "none", label: "No response" },
];

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/**
 * Escape a value for a double-quoted DSL string literal (query.go's lexer takes \", \\, \n, \t, \r).
 * Only \\ and \" can occur in a host pattern in practice, but escaping is complete rather than
 * assuming that.
 */
function escapeQueryString(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t").replace(/\r/g, "\\r");
}

/**
 * Translates the scope an operator has configured into the history filter grammar, so "In scope
 * only" can compose with the DSL box instead of being a second, invisible filtering mechanism.
 *
 * Returns null when the scope cannot be expressed exactly:
 * - `allow_all` or an empty rule set both mean "everything is in scope" — there is nothing to add.
 * - A pattern containing `*` has no exact equivalent in the DSL's `=`/`~` string operators (the
 *   query grammar has no glob operator), so it is not translated rather than approximated — an
 *   approximate query shown in the box would misdescribe what is actually being filtered, which is
 *   exactly the kind of dishonesty DESIGN.md's "the numbers must be honest" section rules out.
 *
 * When it returns null, the toggle still filters correctly — `isHostInScope` below does the same
 * check client-side — it just does not show up in the query text.
 *
 * The translation mirrors `core.Scope.Contains` in burpsy-go/internal/core/scope.go: excludes always
 * win, and with no include rules everything not excluded is in scope.
 */
function scopeToQueryFragment(scope: ScopeView | undefined): string | null {
  if (!scope || scope.allow_all) return null;
  const named = scope.rules.filter((rule): rule is ScopeRuleView & { host: string } => Boolean(rule.host));
  if (named.length === 0) return null;
  if (named.some((rule) => rule.host.includes("*"))) return null;
  const includes = named.filter((rule) => rule.kind === "Include");
  const excludes = named.filter((rule) => rule.kind === "Exclude");
  const clause = (rules: typeof named) => rules.map((rule) => `host = "${escapeQueryString(rule.host)}"`).join(" OR ");
  const parts: string[] = [];
  if (includes.length > 0) parts.push(includes.length > 1 ? `(${clause(includes)})` : clause(includes));
  if (excludes.length > 0) parts.push(`NOT ${excludes.length > 1 ? `(${clause(excludes)})` : clause(excludes)}`);
  return parts.length > 0 ? parts.join(" AND ") : null;
}

/** Append a fragment as a new AND'd clause, or start the query with it if the box is empty. */
function combineQuery(base: string, fragment: string): string {
  const trimmed = base.trim();
  return trimmed ? `${trimmed} AND ${fragment}` : fragment;
}

/**
 * Best-effort removal of a fragment this component injected. If the operator has since hand-edited
 * the box (the design's own intent — "the operator can see what it did and learn the language"), the
 * exact injected substring may no longer be there; this leaves their edit alone rather than mangling
 * unrelated text.
 */
function stripFragment(current: string, fragment: string): string {
  const suffix = ` AND ${fragment}`;
  if (current.endsWith(suffix)) return current.slice(0, -suffix.length);
  if (current === fragment) return "";
  const prefix = `${fragment} AND `;
  if (current.startsWith(prefix)) return current.slice(prefix.length);
  return current;
}

/**
 * Wildcard-pattern host match, ported from `core.NewScopeRule`'s regex construction (the
 * `*.example.com` case matches zero-or-more subdomain labels; a bare `*` matches anything). Used
 * only when `scopeToQueryFragment` returned null, i.e. a wildcard pattern makes the scope
 * inexpressible in the DSL, so the toggle still filters correctly without touching the query text.
 */
function hostPatternRegex(pattern: string): RegExp {
  let out = "^";
  for (let i = 0; i < pattern.length; i += 1) {
    const c = pattern[i] ?? "";
    if (c === "*") {
      if (i === 0 && pattern.length > 1 && pattern[1] === ".") {
        out += "([a-zA-Z0-9-]+\\.)*";
        i += 1; // the dot is consumed into the label group above, same as the Go loop
      } else {
        out += ".*";
      }
    } else if (c === ".") {
      out += "\\.";
    } else {
      out += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  out += "$";
  return new RegExp(out, "i");
}

/** Client-side mirror of `core.Scope.Contains`, ignoring port/path — the UI's own scope API exposes
 *  neither (see settings.tsx), so there is nothing for either page to filter on. */
function isHostInScope(host: string, scope: ScopeView | undefined): boolean {
  if (!scope || scope.allow_all) return true;
  const named = scope.rules.filter((rule): rule is ScopeRuleView & { host: string } => Boolean(rule.host));
  if (named.some((rule) => rule.kind === "Exclude" && hostPatternRegex(rule.host).test(host))) return false;
  const includes = named.filter((rule) => rule.kind === "Include");
  if (includes.length === 0) return true;
  return includes.some((rule) => hostPatternRegex(rule.host).test(host));
}

/** design/jsx/filter-toggle-{off,on}.jsx. A real toggle button, not a checkbox styled as a pill —
 *  `aria-pressed` is the correct role for "this button's own state flips", per the task brief. */
function FilterToggle({
  pressed,
  onPressedChange,
  children,
}: {
  pressed: boolean;
  onPressedChange: (next: boolean) => void;
  children: string;
}): JSX.Element {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      className={cn("filter-toggle", pressed && "filter-toggle-on")}
      onClick={() => onPressedChange(!pressed)}
    >
      <span className="filter-toggle-dot" aria-hidden="true" />
      <span>{children}</span>
    </button>
  );
}

/**
 * design/jsx/highlight-picker-default.jsx: ten 10px swatches including "none" (an outlined
 * transparent circle, per DESIGN.md's Row highlights section — the exported JSX's solid black fill
 * is a Penpot preview artifact, not the documented intent). Each swatch is a real button with its
 * own accessible name, reachable by Tab, so the picker needs no pointer to operate.
 */
function HighlightPicker({ value, onChange }: { value: string; onChange: (next: string) => void }): JSX.Element {
  return (
    <div className="highlight-picker" role="group" aria-label="Row highlight">
      {HIGHLIGHTS.map((name) => {
        const wireValue = name === "none" ? "" : name;
        const isSelected = value === wireValue;
        return (
          <button
            key={name}
            type="button"
            className={cn("highlight-swatch", name === "none" && "highlight-swatch-none", isSelected && "highlight-swatch-selected")}
            style={name === "none" ? undefined : ({ "--swatch-color": `var(--highlight-${name})` } as CSSProperties)}
            aria-label={name === "none" ? "Clear highlight" : `Highlight row ${name}`}
            aria-pressed={isSelected}
            onClick={() => onChange(wireValue)}
          />
        );
      })}
    </div>
  );
}

/** design/jsx/comment-indicator-default.jsx. Decorative glyph plus a screen-reader-only label —
 *  "a row has a note" is information, not decoration, so it cannot be aria-hidden outright. */
function CommentIndicator(): JSX.Element {
  return (
    <span className="comment-indicator" title="Has a note">
      <span aria-hidden="true">...</span>
      <span className="sr-only">Has a note</span>
    </span>
  );
}

function QueryHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Filter syntax" description="The filter box is sent to the server as a query expression.">
      <div className="prose">
        {[
          "host = api.example.com",
          "host ~ example          (substring match)",
          "status = 500",
          "status >= 400",
          "method = POST",
          "path ~ /admin",
          "body ~ password",
          'host = api.example.com AND status >= 400',
          "method = POST OR method = PUT",
        ].join("\n")}
      </div>
      <p className="field-hint">
        The fields are host, status, method, path, mime and body — every term needs an operator and a value. host and
        mime ignore case; method and path do not. Clear the box to return to the full capture.
      </p>
    </Modal>
  );
}

export function HistoryPage(): JSX.Element {
  const historyQuery = useApp((state) => state.historyQuery);
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);
  const historyFocus = useApp((state) => state.historyFocus);
  const focusExchange = useApp((state) => state.focusExchange);

  const [term, setTerm] = useState(historyQuery);
  const [status, setStatus] = useState("all");
  const [method, setMethod] = useState("all");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [limit, setLimit] = useState(500);
  const [inspector, setInspector] = useState(true);
  const [scopeOnly, setScopeOnly] = useState(false);
  const [hideNoResponse, setHideNoResponse] = useState(false);
  const [note, setNote] = useState("");

  const debouncedTerm = useDebounced(term, 260);
  const { data, error, isFetching, refetch } = useHistory(debouncedTerm, limit);
  const actions = useExchangeActions();
  const scope = useScopeView();
  const annotate = useAnnotateExchange();

  // Another page asked to filter here (for example "filter by this host").
  useEffect(() => {
    if (!historyQuery) return;
    setTerm(historyQuery);
    setHistoryQuery("");
  }, [historyQuery, setHistoryQuery]);

  // Another page asked to reveal one exchange.
  useEffect(() => {
    if (historyFocus === null) return;
    setSelectedId(historyFocus);
    focusExchange(null);
  }, [historyFocus, focusExchange]);

  // "In scope only" composes with the DSL box rather than filtering invisibly beside it: when the
  // configured scope can be written as a query (scopeToQueryFragment), that text is spliced into the
  // box itself, so the operator sees exactly what the toggle did and the server does the filtering.
  // The ref tracks what this effect last injected, so turning the toggle off — or the scope changing
  // while it is on — removes exactly that substring rather than guessing at one.
  const injectedFragment = useRef<string | null>(null);
  const scopeFragment = useMemo(() => scopeToQueryFragment(scope.data), [scope.data]);
  useEffect(() => {
    const wanted = scopeOnly ? scopeFragment : null;
    if (injectedFragment.current === wanted) return;
    setTerm((current) => {
      const withoutOld = injectedFragment.current ? stripFragment(current, injectedFragment.current) : current;
      return wanted ? combineQuery(withoutOld, wanted) : withoutOld;
    });
    injectedFragment.current = wanted;
  }, [scopeOnly, scopeFragment]);

  const rows = useMemo(() => {
    const all = data ?? [];
    return all.filter((row) => {
      if (method !== "all" && row.method !== method) return false;
      if (status === "none" && row.status !== null) return false;
      if (status !== "all" && status !== "none" && (row.status === null || !String(row.status).startsWith(status))) return false;
      if (hideNoResponse && row.response === null) return false;
      // Only needed when the scope could not be written into the query above (a wildcard pattern) —
      // when it could, the server already returned only in-scope rows and this is a no-op re-check.
      if (scopeOnly && !scopeFragment && !isHostInScope(row.host, scope.data)) return false;
      return true;
    });
  }, [data, method, status, hideNoResponse, scopeOnly, scopeFragment, scope.data]);

  // Selection is held by id, not by object identity, so a background refresh
  // cannot silently drop the operator's selection.
  const selected = useMemo(() => rows.find((row) => row.id === selectedId) ?? null, [rows, selectedId]);

  // Burp's signature bindings, on the selected row. ctrl+R overrides the browser's
  // reload: for a Burp user that combination means "send to Repeater" and nothing else.
  useHotkeys(
    "mod+r",
    (event) => {
      if (!selected) return;
      event.preventDefault();
      void actions.sendToRepeater(selected);
    },
    { enableOnFormTags: false },
    [selected, actions],
  );
  useHotkeys(
    "mod+i",
    (event) => {
      if (!selected) return;
      event.preventDefault();
      actions.sendToIntruder(selected);
    },
    { enableOnFormTags: false },
    [selected, actions],
  );

  const request = useMessage(selected?.request);
  const response = useMessage(selected?.response ?? null);

  // The note field mirrors the selected row's own copy — see organizer.tsx's identical comment on
  // its own draft state — but reset only on a selection change, not on every background refetch, so
  // a background refetch cannot wipe out a note the operator is mid-typing.
  useEffect(() => {
    setNote(selected?.notes ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  const saveNote = () => {
    if (!selected) return;
    const trimmed = note.trim();
    if (trimmed === (selected.notes ?? "")) return;
    annotate.mutate({ id: selected.id, notes: trimmed === "" ? null : trimmed });
  };

  const columns = useMemo<Column<Exchange>[]>(
    () => [
      {
        accessorKey: "id",
        header: "#",
        size: 62,
        cell: (info) => (
          <span className="cell-id">
            <span className="cell-num">{info.getValue<number>()}</span>
            {info.row.original.notes ? <CommentIndicator /> : null}
          </span>
        ),
      },
      {
        accessorKey: "method",
        header: "Method",
        size: 74,
        cell: (info) => <Badge tone="info">{info.getValue<string>()}</Badge>,
      },
      {
        id: "authority",
        header: "Host",
        size: 190,
        accessorFn: (row) => `${row.host}:${row.port}`,
        cell: (info) => <span title={info.getValue<string>()}>{info.getValue<string>()}</span>,
      },
      {
        accessorKey: "path",
        header: "Path",
        size: 330,
        cell: (info) => <code title={info.getValue<string>()}>{info.getValue<string>()}</code>,
      },
      {
        accessorKey: "status",
        header: "Status",
        size: 78,
        cell: (info) => {
          const value = info.getValue<number | null>();
          return value === null ? <Badge>pending</Badge> : <Badge tone={statusTone(value)}>{value}</Badge>;
        },
      },
      {
        accessorKey: "mime",
        header: "Type",
        size: 92,
        cell: (info) => <span className="cell-dim">{info.getValue<string | undefined>() || "—"}</span>,
      },
      {
        accessorKey: "response_len",
        header: "Length",
        size: 84,
        cell: (info) => <span className="cell-num">{formatBytes(info.getValue<number>())}</span>,
      },
      {
        accessorKey: "duration_ms",
        header: "Time",
        size: 78,
        cell: (info) => <span className="cell-num">{formatDuration(info.getValue<number>())}</span>,
      },
      {
        accessorKey: "started_ms",
        header: "Age",
        size: 84,
        cell: (info) => <span className="cell-dim">{relativeTime(info.getValue<number>())}</span>,
      },
    ],
    [],
  );

  const detail = selected ? (
    <div className="tabs-fill">
      <div className="detail-head">
        <div className="detail-head-title">
          <span className="eyebrow">#{selected.id}</span>
          <strong title={exchangeUrl(selected)}>
            {selected.method} {exchangeUrl(selected)}
          </strong>
        </div>
        <div className="detail-actions">
          <Badge tone={statusTone(selected.status)}>{selected.status ?? "pending"}</Badge>
          <Badge>{formatDuration(selected.duration_ms)}</Badge>
          <Badge>{selected.protocol}</Badge>
          <Button variant="outline" size="small" onClick={() => void actions.sendToRepeater(selected)}>
            <Repeat2 size={13} />
            Repeater
          </Button>
          <Button variant="outline" size="small" onClick={() => actions.sendToIntruder(selected)}>
            <Crosshair size={13} />
            Intruder
          </Button>
          <Button variant="outline" size="small" onClick={() => void actions.sendToComparer(selected, "a")}>
            <Combine size={13} />
            Compare
          </Button>
          <IconButton
            label={inspector ? "Hide Inspector" : "Show Inspector"}
            size="small"
            aria-pressed={inspector}
            onClick={() => setInspector((current) => !current)}
          >
            <Columns3 size={13} />
          </IconButton>
          <IconButton label="Clear selection" size="small" onClick={() => setSelectedId(null)}>
            <X size={13} />
          </IconButton>
        </div>
      </div>
      {/* Annotation bar (UX-15): the highlight vocabulary and notes exist for Organizer items today —
          this is what lets an operator mark a row up in place instead of filing it in a different
          tool just to comment on it. */}
      <div className="annotate-bar">
        <HighlightPicker
          value={selected.highlight}
          onChange={(next) => annotate.mutate({ id: selected.id, highlight: next })}
        />
        <Input
          aria-label="Row note"
          title="Row note"
          placeholder="Add a note…"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          onBlur={saveNote}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              (event.target as HTMLInputElement).blur();
            }
          }}
        />
      </div>
      <div className={inspector ? "editor-grid-inspected" : "editor-grid"}>
        <HttpEditor
          label="Request"
          readOnly
          value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
          filename={`exchange-${selected.id}-request.txt`}
        />
        <HttpEditor
          label="Response"
          readOnly
          value={
            selected.response === null
              ? "No response was captured for this exchange."
              : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."))
          }
          filename={`exchange-${selected.id}-response.txt`}
        />
        {inspector ? <Inspector raw={request.data?.text ?? ""} label="Inspector · request" /> : null}
      </div>
    </div>
  ) : (
    <Empty
      title="No exchange selected"
      detail="Choose a row to read its exact request and response bytes. Arrow keys move through the table; right-click a row for send-to actions."
    />
  );

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="HTTP history"
          actions={
            <>
              <Badge tone={rows.length === data?.length ? "neutral" : "info"}>
                {rows.length.toLocaleString()}
                {data && rows.length !== data.length ? ` / ${data.length.toLocaleString()}` : ""} rows
              </Badge>
              <RefreshButton onClick={() => void refetch()} loading={isFetching} />
            </>
          }
        />
        <Toolbar style={{ marginTop: 10 }}>
          <div className="search-field">
            <Search size={15} />
            <Input
              aria-label="Filter history"
              title="Filter history"
              value={term}
              onChange={(event) => setTerm(event.target.value)}
              placeholder="host = api.example AND status >= 400"
            />
            {term ? (
              <IconButton label="Clear filter" size="small" onClick={() => setTerm("")}>
                <X size={13} />
              </IconButton>
            ) : null}
            <Tooltip content="Filter syntax">
              <button type="button" className="icon-button icon-button-sm" aria-label="Filter syntax" onClick={() => setHelpOpen(true)}>
                <HelpCircle size={13} />
              </button>
            </Tooltip>
          </div>
          <FilterToggle pressed={scopeOnly} onPressedChange={setScopeOnly}>
            In scope only
          </FilterToggle>
          <FilterToggle pressed={hideNoResponse} onPressedChange={setHideNoResponse}>
            Hide items without responses
          </FilterToggle>
          <Select aria-label="Status filter" title="Status filter" value={status} onChange={(event) => setStatus(event.target.value)} style={{ maxWidth: "var(--w-sm)" }}>
            {STATUS_BUCKETS.map((bucket) => (
              <option key={bucket.value} value={bucket.value}>
                {bucket.label}
              </option>
            ))}
          </Select>
          <Select aria-label="Method filter" title="Method filter" value={method} onChange={(event) => setMethod(event.target.value)} style={{ maxWidth: "var(--w-xs)" }}>
            <option value="all">All methods</option>
            {METHODS.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </Select>
          <Select
            aria-label="Row limit"
            title="Row limit"
            value={String(limit)}
            onChange={(event) => setLimit(Number(event.target.value))}
            style={{ maxWidth: "var(--w-xs)" }}
          >
            {[200, 500, 1000, 5000].map((value) => (
              <option key={value} value={value}>
                last {value}
              </option>
            ))}
          </Select>
        </Toolbar>
        {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
      </div>

      <SplitPane
        storageId="history"
        orientation="vertical"
        defaultMasterSize="46"
        master={
          <VirtualTable
            ariaLabel="Captured HTTP exchanges"
            data={rows}
            columns={columns}
            getRowId={(row) => String(row.id)}
            selectedId={selectedId === null ? null : String(selectedId)}
            onSelect={(row) => setSelectedId(row.id)}
            onActivate={(row) => void actions.sendToRepeater(row)}
            menuGroups={(row) =>
              actions.menu(row, [
                {
                  id: "inspect",
                  actions: [
                    {
                      id: "copy-response",
                      label: "Copy response bytes",
                      onSelect: () => {
                        if (row.response === null) {
                          toast.error("This exchange has no response");
                          return;
                        }
                        setSelectedId(row.id);
                      },
                    },
                  ],
                },
              ])
            }
            rowClassName={(row) =>
              cn(
                row.status !== null && row.status >= 500 ? "row-flag-bad" : row.status !== null && row.status >= 400 ? "row-flag-warn" : undefined,
                // `rowClassName` is a CSS-class hook only — see the survey — so an arbitrary per-row
                // highlight colour is one class per colour (`row-highlight-<name>`), each of which
                // just binds the `--row-tint` custom property a single generic rule reads. That
                // keeps this to 9 one-line classes plus 3 shared rules instead of 9 colours x 3
                // states of duplicated color-mix() — see styles.css's Task 5 section and the report.
                row.highlight ? cn("row-highlight", `row-highlight-${row.highlight}`) : undefined,
              ) || undefined
            }
            loading={isFetching && !data}
            empty={
              <Empty
                title={term ? "No exchange matches this filter" : "No traffic captured yet"}
                detail={
                  term
                    ? "Relax the filter, or clear it to see the whole capture."
                    : "Point a client at the proxy and install the CA certificate to start capturing HTTPS."
                }
              />
            }
          />
        }
        detail={detail}
      />
      <QueryHelp open={helpOpen} onOpenChange={setHelpOpen} />
    </div>
  );
}
