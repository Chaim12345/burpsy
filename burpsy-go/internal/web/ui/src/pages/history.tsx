import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { BookOpen, Columns3, Combine, Crosshair, Download, HelpCircle, Repeat2, Search, X } from "lucide-react";
import { toast } from "sonner";
import { useExchangeActions, exchangeUrl } from "../lib/actions";
import { downloadText, formatBytes, formatCount, formatDuration, historyToCSV, relativeTime, statusTone } from "../lib/api";
import { cn } from "../lib/cn";
import { useAnnotateExchange, useDebounced, useHistory, useMessage, useStats } from "../lib/data";
import { useScopeView } from "../lib/data.policy";
import { QUERY_PANEL } from "../lib/reference";
import { useApp } from "../lib/store";
import { HIGHLIGHTS, type Exchange } from "../lib/types";
import type { ScopeRuleView, ScopeView } from "../lib/types.policy";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Button, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Toolbar, Tooltip } from "../ui/primitives";
import { ReferencePanelView } from "../ui/reference";
import { VirtualTable, type Column } from "../ui/table";

const STATUS_BUCKETS = [
  { value: "all", label: "All statuses" },
  { value: "2", label: "2xx success" },
  { value: "3", label: "3xx redirect" },
  { value: "4", label: "4xx client" },
  { value: "5", label: "5xx server" },
  { value: "none", label: "No response" },
];

const MIME_TYPES = [
  { value: "all", label: "All types" },
  { value: "html", label: "HTML" },
  { value: "json", label: "JSON" },
  { value: "xml", label: "XML" },
  { value: "javascript", label: "JavaScript" },
  { value: "css", label: "CSS" },
  { value: "image", label: "Images" },
  { value: "binary", label: "Binary" },
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
/**
 * Extension and query-parameter count, derived from the row's own path.
 *
 * Both come from `path`, which carries the query string (verified against a live capture:
 * `/search?q=test&page=2` arrives whole). Deriving here rather than widening the wire is the
 * point: `internal/web/AGENTS.md` states that /api/history returns index rows and never touches
 * a body, so anything a row can compute for itself must not become a server round trip.
 *
 * `params` counts QUERY parameters only. Burp's Params column also counts body parameters, and
 * that is deliberately not matched: the body is not on the index row, and reading one per row to
 * fill a column is exactly the regression the index/payload split exists to prevent. The column
 * is labelled "Query" for that reason — a column called "Params" that silently ignored body
 * parameters would be a wrong number rather than a narrower one.
 */
export function pathParts(path: string): { extension: string; queryCount: number } {
  const cut = path.indexOf("?");
  const route = cut === -1 ? path : path.slice(0, cut);
  const query = cut === -1 ? "" : path.slice(cut + 1);

  // Extension is read from the last segment only, so a dot in a directory name does not become
  // one. A trailing dot, a dotfile, and a segment that is all dots have no extension.
  const segment = route.slice(route.lastIndexOf("/") + 1);
  const dot = segment.lastIndexOf(".");
  const extension = dot > 0 && dot < segment.length - 1 ? segment.slice(dot + 1).toLowerCase() : "";

  // A bare `?` is zero parameters, not one empty one.
  const queryCount = query === "" ? 0 : query.split("&").filter((pair) => pair !== "").length;
  return { extension, queryCount };
}

function CommentIndicator(): JSX.Element {
  return (
    <span className="comment-indicator" title="Has a note">
      <span aria-hidden="true">...</span>
      <span className="sr-only">Has a note</span>
    </span>
  );
}

/**
 * The filter box's syntax help.
 *
 * This modal used to hold its own nine-line cheat sheet and a paragraph naming the
 * fields. Both were already drifting: the examples spelled the connectives AND and
 * OR while every other example in the tree uses lowercase, and neither mentioned
 * `in low..high`, nor that a comparison against an absent field is false rather
 * than an error — the single most misread behaviour in the grammar, because it is
 * why `status != 304` quietly excludes rows that have no response yet.
 *
 * So it renders the same panel Discover renders, from `lib/reference.ts`. One list,
 * two renderers. The link is there because the modal is the wrong place to read a
 * grammar at length, and the page is the right one.
 */
function QueryHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
  const setRoute = useApp((state) => state.setRoute);
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      wide
      title="Filter syntax"
      description="The filter box is sent to the server as a query expression. Clear the box to return to the full capture."
    >
      <ReferencePanelView panel={QUERY_PANEL} showHeading={false} />
      <Button
        variant="outline"
        onClick={() => {
          onOpenChange(false);
          setRoute("discover");
        }}
      >
        <BookOpen size={14} />
        Open the full reference in Discover
      </Button>
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
  const [mime, setMime] = useState("all");
  const [method, setMethod] = useState("all");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [limit, setLimit] = useState(500);
  const [inspector, setInspector] = useState(true);
  const [scopeOnly, setScopeOnly] = useState(false);
  const [hideNoResponse, setHideNoResponse] = useState(false);
  // Burp's remaining row-type filters (proxyHttpShowOnly*Checkbox). Each is "show only", so all
  // off means no restriction -- the same polarity Burp uses, so a fresh page hides nothing.
  const [onlyParameterized, setOnlyParameterized] = useState(false);
  const [onlyCommented, setOnlyCommented] = useState(false);
  const [onlyHighlighted, setOnlyHighlighted] = useState(false);
  // Extension include/exclude, comma-separated, matched against the derived extension.
  const [showExtensions, setShowExtensions] = useState("");
  const [hideExtensions, setHideExtensions] = useState("");
  // Search modifiers over the existing term (proxyHttpSearch*Checkbox). An invalid regex is
  // reported in place rather than silently matching nothing.
  const [searchCase, setSearchCase] = useState(false);
  const [searchRegex, setSearchRegex] = useState(false);
  const [searchNegate, setSearchNegate] = useState(false);
  const [filterOpen, setFilterOpen] = useState(false);
  const [note, setNote] = useState("");

  const debouncedTerm = useDebounced(term, 260);
  const { data, error, isFetching, refetch } = useHistory(debouncedTerm, limit);
  // The captured total, so a limit-truncated view cannot read as the whole capture. DESIGN.md is
  // explicit that a count the data does not support is a defect, and "500 rows" on a 12,000-row
  // capture is exactly that -- the operator concludes they have seen everything.
  const stats = useStats();
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
  //
  // The toggle handler is async: when turning ON, it awaits scope.refetch() BEFORE flipping
  // scopeOnly. This matters because the scope may have been mutated externally (another client, or
  // a test harness POSTing to /api/scope directly) since the page mounted — React Query's cache
  // would be stale, and scopeFragment would be computed from the wrong data. By awaiting the
  // refetch, the effect that injects the fragment always sees the server's actual state.
  const injectedFragment = useRef<string | null>(null);
  const scopeFragment = useMemo(() => scopeToQueryFragment(scope.data), [scope.data]);
  const handleScopeToggle = useCallback(async (pressed: boolean) => {
    if (pressed) await scope.refetch();
    setScopeOnly(pressed);
  }, [scope]);
  useEffect(() => {
    const wanted = scopeOnly ? scopeFragment : null;
    if (injectedFragment.current === wanted) return;
    // Capture the previously injected fragment BEFORE queueing the setTerm update: React may run
    // the functional updater after this effect returns, by which point the ref below already holds
    // wanted — reading the ref inside the updater would strip the new fragment instead of the old.
    const previous = injectedFragment.current;
    setTerm((current) => {
      const withoutOld = previous ? stripFragment(current, previous) : current;
      return wanted ? combineQuery(withoutOld, wanted) : withoutOld;
    });
    injectedFragment.current = wanted;
  }, [scopeOnly, scopeFragment]);

  // Extension lists, normalised once: lower-cased, dot-stripped, blanks dropped, so "PNG", ".png"
  // and " png " are one entry.
  const parseExtList = (raw: string) =>
    raw.split(",").map((e) => e.trim().toLowerCase().replace(/^\./, "")).filter((e) => e !== "");
  const showList = useMemo(() => parseExtList(showExtensions), [showExtensions]);
  const hideList = useMemo(() => parseExtList(hideExtensions), [hideExtensions]);

  // The search term compiled into a predicate, plus the reason it could not be. An invalid regex
  // is the case that matters: silently matching nothing would read as "no such traffic", which is
  // the difference between an empty result and a broken filter.
  const { searchMatcher, searchError } = useMemo(() => {
    const needle = debouncedTerm.trim();
    if (needle === "" || !searchRegex && !searchCase && !searchNegate) {
      // No modifiers in play: the DSL box already handles plain terms server-side.
      if (needle === "" || !searchRegex) return { searchMatcher: null, searchError: null };
    }
    if (searchRegex) {
      try {
        const re = new RegExp(needle, searchCase ? "" : "i");
        return { searchMatcher: (hay: string) => re.test(hay), searchError: null };
      } catch (failure) {
        return {
          searchMatcher: null,
          searchError: failure instanceof Error ? failure.message : "invalid regular expression",
        };
      }
    }
    const cmp = searchCase ? needle : needle.toLowerCase();
    return {
      searchMatcher: (hay: string) => (searchCase ? hay : hay.toLowerCase()).includes(cmp),
      searchError: null,
    };
  }, [debouncedTerm, searchRegex, searchCase, searchNegate]);

  const filtersActive =
    (onlyParameterized ? 1 : 0) + (onlyCommented ? 1 : 0) + (onlyHighlighted ? 1 : 0) +
    (showList.length > 0 ? 1 : 0) + (hideList.length > 0 ? 1 : 0) +
    (searchMatcher ? 1 : 0);

  const rows = useMemo(() => {
    const all = data ?? [];
    return all.filter((row) => {
      if (method !== "all" && row.method !== method) return false;
      if (mime !== "all") {
        const exMime = (row.mime ?? "").toLowerCase();
        if (mime === "binary") {
          // Binary = everything that is not a text-ish content type.
          if (
            exMime.includes("text") || exMime.includes("json") || exMime.includes("xml") ||
            exMime.includes("javascript") || exMime.includes("css") || exMime.includes("html")
          ) {
            return false;
          }
        } else if (!exMime.includes(mime)) {
          return false;
        }
      }
      if (status === "none" && row.status !== null) return false;
      if (status !== "all" && status !== "none" && (row.status === null || !String(row.status).startsWith(status))) return false;
      if (hideNoResponse && row.response === null) return false;
      // Only needed when the scope could not be written into the query above (a wildcard pattern) —
      // when it could, the server already returned only in-scope rows and this is a no-op re-check.
      if (scopeOnly && !scopeFragment && !isHostInScope(row.host, scope.data)) return false;

      const { extension, queryCount } = pathParts(row.path);
      if (onlyParameterized && queryCount === 0) return false;
      if (onlyCommented && (row.notes ?? "").trim() === "") return false;
      if (onlyHighlighted && (row.highlight ?? "") === "") return false;
      if (showList.length > 0 && !showList.includes(extension)) return false;
      if (hideList.length > 0 && hideList.includes(extension)) return false;

      if (searchMatcher) {
        // Search runs over the fields a row actually carries. It deliberately does NOT reach into
        // request or response bodies: those are not on the index row, and fetching 500 of them to
        // colour a filter would undo the split that makes a 100k-row history cheap. The label on
        // the control says so.
        const haystack = `${row.method} ${row.host} ${row.path} ${row.mime ?? ""} ${row.notes ?? ""}`;
        const hit = searchMatcher(haystack);
        if (hit === searchNegate) return false;
      }
      return true;
    });
  }, [
    data, method, status, mime, hideNoResponse, scopeOnly, scopeFragment, scope.data,
    onlyParameterized, onlyCommented, onlyHighlighted, showList, hideList, searchMatcher, searchNegate,
  ]);

  // CSV export — client-side from the loaded rows; no server endpoint needed
  // because the page already holds the index rows in memory. The CSV shape is
  // historyToCSV in lib/api: the desktop shell's File > Export History renders
  // through the same helper, so the two doors cannot drift apart. This button
  // exports the loaded (filtered) view; the menu item exports the full capture.
  const exportCSV = () => {
    if (!data || data.length === 0) {
      toast.error("No history rows to export");
      return;
    }
    downloadText("history.csv", historyToCSV(data), "text/csv");
    toast.success(`Exported ${data.length} exchanges to CSV`);
  };

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
        // 'basic' matches JS native .sort() (UTF-16 code unit order); the default
        // 'alphanumeric' treats '?' inside query strings differently, which makes
        // the descending sort disagree with [...ascending].reverse().
        sortingFn: "basic",
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
        id: "extension",
        header: "Ext",
        size: 66,
        accessorFn: (row: Exchange) => pathParts(row.path).extension,
        cell: (info) => <span className="cell-dim">{info.getValue<string>() || "—"}</span>,
      },
      {
        // "Query", not Burp's "Params": this counts query parameters only, because body
        // parameters are not on the index row. See pathParts.
        id: "query",
        header: "Query",
        size: 68,
        accessorFn: (row: Exchange) => pathParts(row.path).queryCount,
        cell: (info) => {
          const n = info.getValue<number>();
          return <span className="cell-num">{n === 0 ? "—" : formatCount(n)}</span>;
        },
      },
      {
        accessorKey: "tls",
        header: "TLS",
        size: 60,
        cell: (info) => (info.getValue<boolean>() ? <Badge tone="good">TLS</Badge> : <span className="cell-dim">—</span>),
      },
      {
        id: "comment",
        header: "Comment",
        size: 180,
        accessorFn: (row: Exchange) => row.notes ?? "",
        cell: (info) => {
          const text = info.getValue<string>();
          return text === "" ? <span className="cell-dim">—</span> : <span title={text}>{text}</span>;
        },
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
    <div className="tabs-fill history-detail">
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
        {inspector ? (
          <Inspector
            raw={request.data?.text ?? ""}
            label="Inspector · request"
            readOnlyNote="This request has already been sent, so it is read-only here. Send it to Repeater to change it and try again."
          />
        ) : null}
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
              <Button variant="outline" size="small" onClick={exportCSV} disabled={!data || data.length === 0}>
                <Download size={14} />
                Export CSV
              </Button>
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
          <FilterToggle pressed={scopeOnly} onPressedChange={handleScopeToggle}>
            In scope only
          </FilterToggle>
          <FilterToggle pressed={hideNoResponse} onPressedChange={setHideNoResponse}>
            Hide items without responses
          </FilterToggle>
          <Button
            variant={filtersActive > 0 ? "outline" : "quiet"}
            size="small"
            aria-expanded={filterOpen}
            onClick={() => setFilterOpen(true)}
          >
            More filters{filtersActive > 0 ? ` (${filtersActive})` : ""}
          </Button>
          <Select aria-label="Status filter" title="Status filter" value={status} onChange={(event) => setStatus(event.target.value)} style={{ maxWidth: "var(--w-sm)" }}>
            {STATUS_BUCKETS.map((bucket) => (
              <option key={bucket.value} value={bucket.value}>
                {bucket.label}
              </option>
            ))}
          </Select>
          <Select aria-label="MIME type filter" title="MIME type filter" value={mime} onChange={(event) => setMime(event.target.value)} style={{ maxWidth: "var(--w-sm)" }}>
            {MIME_TYPES.map((mt) => (
              <option key={mt.value} value={mt.value}>
                {mt.label}
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

      {/* Status bar at bottom — Burp-style capture counts at a glance. Counts are
          honest: visible (post-filter) rows over the server-loaded total, response
          bytes summed from what is actually shown, and the pending count is the
          exchanges with no response yet, not a cached number. */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: "6px 12px",
          borderTop: "1px solid var(--border)",
          fontSize: "var(--fs-sm)",
          color: "var(--fg-dim)",
        }}
      >
        <div title="Rows visible after the current filters, of those loaded, of everything captured">
          <strong style={{ color: "var(--fg)" }}>{formatCount(rows.length)}</strong>
          {data && rows.length !== data.length ? ` of ${formatCount(data.length)} loaded` : ""}
          {/* Three numbers, not one: filtered, loaded, captured. They differ for different reasons -
              a filter narrowed the view, the row limit truncated the fetch, or neither - and
              collapsing them hides which. The captured figure is omitted rather than guessed when
              /api/stats has not answered. */}
          {stats.data && data && stats.data.exchanges > data.length
            ? `, ${formatCount(stats.data.exchanges)} captured`
            : ""}
          {" "}
          {rows.length === 1 ? "row" : "rows"}
        </div>
        <div title="Sum of response bytes for the visible rows">
          {formatBytes(rows.reduce((sum, row) => sum + (row.response_len ?? 0), 0))} in responses
        </div>
        <div title="Exchanges with no response yet">
          {rows.filter((row) => row.status === null).length} pending
        </div>
        {selected ? (
          <div style={{ color: "var(--fg)", marginLeft: "auto", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={exchangeUrl(selected)}>
            <strong>#{selected.id}</strong> {selected.method} {selected.path}
          </div>
        ) : null}
      </div>

      <QueryHelp open={helpOpen} onOpenChange={setHelpOpen} />
      <Modal
        open={filterOpen}
        onOpenChange={setFilterOpen}
        title="More filters"
        description="Applied over the rows already loaded. These narrow what is shown; they do not change what was captured."
      >
        <div className="stack">
          <div>
            <div className="shortcut-group">Show only</div>
            <Checkbox checked={onlyParameterized} onCheckedChange={setOnlyParameterized} label="Parameterized requests" />
            <Checkbox checked={onlyCommented} onCheckedChange={setOnlyCommented} label="Commented items" />
            <Checkbox checked={onlyHighlighted} onCheckedChange={setOnlyHighlighted} label="Highlighted items" />
            <p className="field-hint">
              Parameterized counts query parameters only — the body is not on a history row, so a body-only
              POST does not match.
            </p>
          </div>

          <div className="form-grid">
            <Field label="Show only extensions" hint="Comma-separated, e.g. php,asp. Empty shows every extension.">
              {(id) => (
                <Input id={id} value={showExtensions} onChange={(event) => setShowExtensions(event.target.value)} placeholder="php,asp,jsp" />
              )}
            </Field>
            <Field label="Hide extensions" hint="Comma-separated, e.g. css,png,js. Applied after the show list.">
              {(id) => (
                <Input id={id} value={hideExtensions} onChange={(event) => setHideExtensions(event.target.value)} placeholder="css,png,gif,js" />
              )}
            </Field>
          </div>

          <div>
            <div className="shortcut-group">Search modifiers</div>
            <Checkbox checked={searchCase} onCheckedChange={setSearchCase} label="Case sensitive" />
            <Checkbox checked={searchRegex} onCheckedChange={setSearchRegex} label="Regular expression" />
            <Checkbox
              checked={searchNegate}
              onCheckedChange={setSearchNegate}
              label="Negative match — show rows that do NOT match"
            />
            {searchError ? (
              <ErrorNotice error={new Error(`Search regex rejected: ${searchError}`)} />
            ) : null}
            <p className="field-hint">
              Searches method, host, path, MIME and comment. Not request or response bodies: those are not
              carried on a history row, and fetching them per row to colour a filter would undo what makes a
              large capture cheap to list.
            </p>
          </div>

          <Toolbar>
            <Button
              variant="quiet"
              size="small"
              onClick={() => {
                setOnlyParameterized(false);
                setOnlyCommented(false);
                setOnlyHighlighted(false);
                setShowExtensions("");
                setHideExtensions("");
                setSearchCase(false);
                setSearchRegex(false);
                setSearchNegate(false);
              }}
            >
              Show all
            </Button>
            <Button variant="primary" size="small" onClick={() => setFilterOpen(false)}>
              Done
            </Button>
          </Toolbar>
        </div>
      </Modal>
    </div>
  );
}
