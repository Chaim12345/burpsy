import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { BookOpen, Columns3, Combine, Crosshair, Download, HelpCircle, Repeat2, Search, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { useExchangeActions, useSendShortcuts, exchangeUrl } from "../lib/actions";
import { downloadText, formatBytes, formatCount, formatDuration, historyToCSV, mimeLabel, relativeTime, statusTone } from "../lib/api";
import { cn } from "../lib/cn";
import { useAnnotateExchange, useDebounced, useDeleteHistory, useHistory, useMessage, useStats } from "../lib/data";
import { useAuditSelected } from "../lib/data.observe";
import { useScopeView } from "../lib/data.policy";
import { compileHistorySearch } from "../lib/history-search";
import { QUERY_PANEL } from "../lib/reference";
import { useApp } from "../lib/store";
import { HIGHLIGHTS, type Exchange } from "../lib/types";
import type { ScopeRuleView, ScopeView } from "../lib/types.policy";
import { HttpEditor } from "../ui/editor";
import { availableVariants, VariantPicker, variantMessageId, type MessageVariant } from "../ui/variant-picker";
import { Inspector } from "../ui/inspector";
import { MessageLayoutSwitch, PageHeader, RefreshButton, SplitPane, useMessageLayout } from "../ui/layout";
import { Badge, Button, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Tabs, TabsContent, TabsList, TabsTrigger, Toolbar, Tooltip } from "../ui/primitives";
import { BucketMenu } from "../ui/column-visibility-menu";
import { ReferencePanelView } from "../ui/reference";
import { VirtualTable, type Column, type VisibilityState } from "../ui/table";

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
 * Whether one MIME bucket matches a row (burpsy-react-ui-9my). The single-select memo below
 * used to inline this per the selected value; the multi-select calls it per checked bucket and
 * passes on the first hit. Untyped rows match nothing - see isTyped.
 */
function mimeMatches(row: Exchange, value: string): boolean {
 if (!isTyped(row)) return false;
 const exMime = row.mime.toLowerCase();
 if (value === "binary") {
  return !(
   exMime.includes("text") || exMime.includes("json") || exMime.includes("xml") ||
   exMime.includes("javascript") || exMime.includes("css") || exMime.includes("html")
  );
 }
 return exMime.includes(value);
}

/**
 * Whether a row can be classified by content type at all.
 *
 * A row with no type is not "binary" and is not any other bucket — it is unclassified, and the type
 * filter must exclude it from every specific value rather than let the `binary` branch sweep it up.
 * That branch is written as "not text-ish", so before `mime` was populated it matched literally every
 * row; now that empty is a real answer it would still swallow every untyped and every response-less
 * row and present them to the operator as a confident claim that the body is binary.
 */
function isTyped(row: Exchange): boolean {
 return row.mime !== "";
}

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

/* --- per-column filters (burpsy-react-ui-8sa) ------------------------------
 *
 * Burp puts a filter input under each column header. burpsy did not have one, and the naive fix —
 * a row of inputs each holding its own state and filtering client-side — would have made this the
 * page's *third* filtering mechanism, after the toolbar selects and the DSL box, with no single
 * place showing what is actually being filtered.
 *
 * So these compose into the DSL instead, the same way the "In scope only" toggle already does
 * (see scopeToQueryFragment and combineQuery). Typing in a column filter appends a clause to the
 * query box, where the operator can see it, edit it, and learn the language. One mechanism, one
 * visible statement of the current filter, and the server still does the filtering.
 *
 * # Why only some columns get one
 *
 * The DSL knows six fields: host, method, path, mime, status, body (internal/query/query.go:444).
 * Columns outside that set — extension, query-parameter count, length, time, comment — cannot be
 * expressed as a clause, and an input that silently did nothing, or that filtered client-side while
 * the box said otherwise, is worse than no input. Those columns get no filter and the panel says
 * why rather than leaving the operator to wonder which ones work.
 *
 * status, mime and method already have toolbar selects, so offering a second control for the same
 * field would put two widgets on one clause. The text fields are the gap, and they are what this
 * adds.
 */

/** The DSL-expressible text columns, with the operator each one should use. */
export const COLUMN_FILTERS = [
 {
  field: "host",
  label: "Host",
  // `~` rather than `=`: a column filter is a substring search in every tool that has one, and
  // `host = api.example.com` would match nothing until the operator typed the authority in full.
  operator: "~",
  placeholder: "api.example",
 },
 { field: "path", label: "Path", operator: "~", placeholder: "/admin" },
 {
  field: "body",
  label: "Response body",
  operator: "~",
  // Worth stating: this is the one clause the server cannot answer from the index — it reads
  // response bodies — so it is slower than the others by a lot on a large capture.
  placeholder: "searches response bytes",
 },
] as const;

type ColumnFilterField = (typeof COLUMN_FILTERS)[number]["field"];

/** The clause a column filter contributes, or "" when the input is empty. */
export function columnClause(field: string, operator: string, value: string): string {
 const trimmed = value.trim();
 return trimmed === "" ? "" : `${field} ${operator} "${escapeQueryString(trimmed)}"`;
}

/**
 * Replace one column filter's clause in the query text.
 *
 * Pure, and exported, because the property that matters is a sequence property and cannot be seen
 * from one call: typing "api" one character at a time must leave ONE clause in the box, not
 * `host ~ "a" AND host ~ "ap" AND host ~ "api"`. That is what stripping the previous clause before
 * appending the next one buys, and it is worth a test rather than a comment.
 */
export function rewriteClause(term: string, previous: string, next: string): string {
 const without = previous ? stripFragment(term, previous) : term;
 return next ? combineQuery(without, next) : without;
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
/**
 * Reads and writes one table's hidden-column set under `burpsy.<key>` (burpsy-react-ui-3daa).
 * Copied from logger.tsx's local of the same name: storage is a page decision, not table API
 * (see the note there), so each page carries its own fifteen lines rather than sharing one
 * keyed wrong.
 */
function useStoredColumnVisibility(key: string): [VisibilityState, (next: VisibilityState) => void] {
 const [visibility, setVisibility] = useState<VisibilityState>(() => {
  try {
   const raw = localStorage.getItem(`burpsy.${key}`);
   return raw ? (JSON.parse(raw) as VisibilityState) : {};
  } catch {
   return {};
  }
 });
 const store = (next: VisibilityState) => {
  setVisibility(next);
  try {
   localStorage.setItem(`burpsy.${key}`, JSON.stringify(next));
  } catch {
   // A private window or cleared site data: the table still filters this session.
  }
 };
 return [visibility, store];
}

function FilterToggle({
 pressed,
 onPressedChange,
 children,
 title,
}: {
 pressed: boolean;
 onPressedChange: (next: boolean) => void;
 children: string;
 title?: string;
}): JSX.Element {
 return (
  <button
   type="button"
   aria-pressed={pressed}
   title={title}
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
 // burpsy-react-ui-9my: independent bucket sets, not single values - Burp's status/MIME
 // filters are checkboxes, so "2xx and 5xx" is expressible. Empty means all.
 const [statusSet, setStatusSet] = useState<string[]>([]);
 const [mimeSet, setMimeSet] = useState<string[]>([]);
 // burpsy-react-ui-ovow: Burp's master Filter on/off - suspends every control below while
 // preserving its value, so the operator can compare filtered against unfiltered without
 // clearing anything. On by default: off would show the whole capture behind a filter bar
 // that claims to filter.
 const [filterOn, setFilterOn] = useState(true);
 const [method, setMethod] = useState("all");
 const [selectedId, setSelectedId] = useState<number | null>(null);
 const [helpOpen, setHelpOpen] = useState(false);
 const [limit, setLimit] = useState(500);
 const [inspector, setInspector] = useState(true);
 // The editor-area layout (burpsy-react-ui-446): Burp's horizontal / vertical / combined,
 // persisted per surface. History's pre-switcher arrangement was stacked, so that is the
 // fallback a first visitor gets.
 const [messageLayout, setMessageLayout] = useMessageLayout("history", "vertical");
 const [scopeOnly, setScopeOnly] = useState(false);
 const [hideNoResponse, setHideNoResponse] = useState(false);
 // Burp's remaining row-type filters (proxyHttpShowOnly*Checkbox). Each is "show only", so all
 // off means no restriction -- the same polarity Burp uses, so a fresh page hides nothing.
 const [onlyParameterized, setOnlyParameterized] = useState(false);
 const [onlyCommented, setOnlyCommented] = useState(false);
 const [onlyHighlighted, setOnlyHighlighted] = useState(false);
 // burpsy-react-ui-c13: Burp pins history to the newest rows as traffic arrives.
 const [followNew, setFollowNew] = useState(false);
 // Extension include/exclude, comma-separated, matched against the derived extension.
 const [showExtensions, setShowExtensions] = useState("");
 const [hideExtensions, setHideExtensions] = useState("");
 // Search modifiers (proxyHttpSearch*Checkbox) modify the dedicated search field below, not the
 // DSL box: the box is a statement the server evaluates, and compiling it as a RegExp was how
 // "Regular expression" emptied the table on a query the operator never typed as a pattern
 // (burpsy-react-ui-vlf). An invalid regex is reported in place rather than matching nothing.
 const [searchCase, setSearchCase] = useState(false);
 const [searchRegex, setSearchRegex] = useState(false);
 const [searchNegate, setSearchNegate] = useState(false);
 const [searchText, setSearchText] = useState("");
 const [filterOpen, setFilterOpen] = useState(false);
 /**
  * Per-column filter inputs (8sa). Their own state, but not their own filtering: each edit rewrites
  * the DSL box, so `term` stays the single statement of what is filtered and the server still does
  * the work. Kept keyed by field so a column can be cleared without disturbing the others.
  */
 const [columnFilters, setColumnFilters] = useState<Record<ColumnFilterField, string>>({
  host: "",
  path: "",
  body: "",
 });
 const [columnFiltersOpen, setColumnFiltersOpen] = useState(false);
 // burpsy-react-ui-3daa: Logger's capability, same fifteen lines (see the note on
 // useStoredColumnVisibility): the operator's hidden-column set persists per table.
 const [columnVisibility, setColumnVisibility] = useStoredColumnVisibility("history-columns");

 /**
  * Change one column filter and rewrite its clause in the query box.
  *
  * The old clause is stripped before the new one is appended, so editing an input does not stack
  * `host ~ "a" AND host ~ "ap" AND host ~ "api"` as the operator types. stripFragment is
  * best-effort by design — if they have hand-edited the box, their text is left alone and the new
  * clause is simply appended, which is visible in the box rather than silently discarded.
  */
 const setColumnFilter = (field: ColumnFilterField, value: string) => {
  const spec = COLUMN_FILTERS.find((entry) => entry.field === field);
  if (!spec) return;
  const previous = columnClause(field, spec.operator, columnFilters[field]);
  const next = columnClause(field, spec.operator, value);
  setColumnFilters((current) => ({ ...current, [field]: value }));
  setTerm((current) => rewriteClause(current, previous, next));
 };

 const columnFiltersActive = Object.values(columnFilters).filter((value) => value.trim() !== "").length;
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
 const removeRows = useDeleteHistory();
 // Burp's "Delete items"/"Clear (tool)" (r6li) go through one confirm modal, the way Logger's
 // clear does: rows is null for "the selected rows", or "all" for Clear. undefined means the
 // modal is closed; the value decides what the confirm button says and sends.
 const [confirmDelete, setConfirmDelete] = useState<undefined | { scope: "selected" | "all" }>(undefined);
 // The ticked rows live in the store, not here, because a second surface acts on them: the New scan
 // dialog's "Audit selected items" audits the current selection from the dashboard. Keeping a local
 // copy would give the two surfaces two answers to "what is selected" — the drift the store exists
 // to prevent. The Set is a view of the store's array, memoised so the tick column's memo holds.
 const checkedExchanges = useApp((state) => state.checkedExchanges);
 const setCheckedExchanges = useApp((state) => state.setCheckedExchanges);
 const checkedRows = useMemo(() => new Set(checkedExchanges), [checkedExchanges]);
 const auditSelected = useAuditSelected();

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

 // The search field compiled into a predicate, plus the reason it could not be. It is debounced
 // on its own clock, exactly like the DSL box, so typing does not recompile per keystroke. An
 // invalid regex is the case that matters: silently matching nothing would read as "no such
 // traffic", which is the difference between an empty result and a broken filter.
 const debouncedSearchText = useDebounced(searchText, 260);
 const { matcher: searchMatcher, error: searchError } = useMemo(
  () => compileHistorySearch(debouncedSearchText, { caseSensitive: searchCase, regex: searchRegex }),
  [debouncedSearchText, searchCase, searchRegex],
 );

 const filtersActive =
  (onlyParameterized ? 1 : 0) + (onlyCommented ? 1 : 0) + (onlyHighlighted ? 1 : 0) +
  (showList.length > 0 ? 1 : 0) + (hideList.length > 0 ? 1 : 0) +
  (searchMatcher ? 1 : 0);

 /**
  * Every narrowing currently in force, named as an operator would name it.
  *
  * This exists because a filter that empties the table must say which filter did it. The MIME filter
  * was the case that proved it: selecting any type cleared the table for every row in the capture
  * (the field it matched on was never populated), and the page reported that as "No traffic captured
  * yet — point a client at the proxy", which is a statement about the proxy and was false. The count
  * line and the empty state both read this list, so neither can drift from what is actually applied.
  *
  * `filtersActive` deliberately stays as it is: it counts only the "More filters" popover's contents,
  * because it is the badge on that button. This is the whole set, top-bar controls included.
  */
 const activeFilterNames = useMemo(() => {
  const names: string[] = [];
  // The typed query is a filter whether or not a checkbox produced it: it runs server-side
  // (useHistory sends debouncedTerm) and narrows `data` exactly like the controls do. Leaving
  // it out of this list meant a hand-typed query that matched nothing answered with "No traffic
  // captured yet" — a false claim about the proxy, verified live against a seeded capture —
  // instead of naming the filter that emptied the view.
  if (debouncedTerm.trim() !== "") names.push(`query ${debouncedTerm.trim()}`);
  if (method !== "all") names.push(`method ${method}`);
  if (mimeSet.length > 0) {
   const labelFor = (value: string) => MIME_TYPES.find((mt) => mt.value === value)?.label ?? value;
   names.push(`type ${mimeSet.map(labelFor).join(" + ")}`);
  }
  if (statusSet.length > 0) {
   const labelFor = (value: string) => STATUS_BUCKETS.find((sb) => sb.value === value)?.label ?? value;
   names.push(`status ${statusSet.map(labelFor).join(" + ")}`);
  }
  if (hideNoResponse) names.push("hiding rows with no response");
  if (scopeOnly) names.push("in-scope only");
  if (searchMatcher) names.push(`search "${debouncedSearchText}"${searchNegate ? " (inverted)" : ""}`);
  if (onlyParameterized) names.push("with query parameters");
  if (onlyCommented) names.push("commented");
  if (onlyHighlighted) names.push("highlighted");
  if (showList.length > 0) names.push(`showing ${showList.join(", ")}`);
  if (hideList.length > 0) names.push(`hiding ${hideList.join(", ")}`);
  return names;
 }, [
  debouncedTerm, method, mimeSet, statusSet, hideNoResponse, scopeOnly, searchMatcher, searchNegate, debouncedSearchText,
  onlyParameterized, onlyCommented, onlyHighlighted, showList, hideList,
 ]);
 // ovow: names describe the *applied* filters; suspended, there are none to name no matter
 // what the controls hold. Computed above, filtered here, so the empty states and the status
 // bar read unfiltered while the values wait underneath.
 const appliedFilterNames = filterOn ? activeFilterNames : [];

 const rows = useMemo(() => {
  const all = data ?? [];
  return all.filter((row) => {
   // burpsy-react-ui-ovow: suspended means the whole capture, values preserved.
   if (!filterOn) return true;
   if (method !== "all" && row.method !== method) return false;
   if (mimeSet.length > 0 && !mimeSet.some((value) => mimeMatches(row, value))) return false;
   if (statusSet.length > 0) {
    const bucket = row.status === null ? "none" : String(row.status).slice(0, 1);
    if (!statusSet.includes(bucket)) return false;
   }
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
  data, method, statusSet, mimeSet, filterOn, hideNoResponse, scopeOnly, scopeFragment, scope.data,
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

 // Burp's signature bindings, on the selected row. ctrl+R overrides the browser's reload: for a
 // Burp user that combination means "send to Repeater" and nothing else. They used to be two
 // hardcoded literals here, which made the Settings hotkey table a lie and left every other row
 // table without them — see useSendShortcuts in lib/actions.ts.
 useSendShortcuts(selected);

 // Burp's three readings of each message (burpsy-react-ui-c05). Two pieces of state because the
 // request and the response are independent: an operator can edit a held request and leave the
 // response alone, so forcing one choice on both panes would make one of them show bytes under a
 // label that does not describe them.
 const [requestVariant, setRequestVariant] = useState<MessageVariant>("edited");
 const [responseVariant, setResponseVariant] = useState<MessageVariant>("edited");

 // Every selection starts on the bytes that travelled, which is the reading an operator wants by
 // default and the only one every row has. Reset on selection change so a comparison made on one
 // row does not silently carry to the next, where that reading may not even exist.
 useEffect(() => {
  setRequestVariant("edited");
  setResponseVariant("edited");
 }, [selectedId]);

 const requestVariants = availableVariants(selected?.variants?.request_original, selected?.variants?.request_auto_modified);
 const responseVariants = availableVariants(selected?.variants?.response_original, selected?.variants?.response_auto_modified);

 // A reading the server did not resolve falls back to the bytes that travelled rather than
 // fetching nothing, so a pane is never empty while the picker claims a reading exists.
 const requestId = variantMessageId(selected?.request ?? null, selected?.variants?.request_original, selected?.variants?.request_auto_modified, requestVariant);
 const responseId = variantMessageId(selected?.response ?? null, selected?.variants?.response_original, selected?.variants?.response_auto_modified, responseVariant);

 const request = useMessage(requestId);
 const response = useMessage(responseId);

 // The two panes, built once and placed by whichever layout is active, so the readings and the
 // file names cannot drift between the combined and split arrangements.
 //
 // The picker is wrapped *only* when there is something to compare. That keeps the common case's
 // DOM exactly what it was — no extra element in the editor grid, no new chance of a layout
 // regression on the rows that have nothing to show — and it is also what makes the wrapper's
 // presence meaningful rather than decorative.
 const renderPane = (
  label: string,
  options: MessageVariant[],
  value: MessageVariant,
  onChange: (next: MessageVariant) => void,
  editor: JSX.Element,
 ): JSX.Element =>
  options.length < 2 ? (
   editor
  ) : (
   <div className="reading-pane">
    <VariantPicker label={label} options={options} value={value} onChange={onChange} />
    {editor}
   </div>
  );

 // Gated on a selection because the panes are built on every render while the detail block renders
 // only when something is selected, and actions.menu wants a row.
 const requestPane = selected ? (
  renderPane(
   "Request",
   requestVariants,
   requestVariant,
   setRequestVariant,
   <HttpEditor
    label="Request"
    readOnly
    value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
    filename={`exchange-${selected.id}-request-${requestVariant}.txt`}
    menuGroups={actions.menu(selected)}
   />,
  )
 ) : null;
 const responsePane = selected ? (
  renderPane(
   "Response",
   responseVariants,
   responseVariant,
   setResponseVariant,
   <HttpEditor
    label="Response"
    readOnly
    value={
     selected.response === null
      ? "No response was captured for this exchange."
      : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."))
    }
    bodyBase64={response.data?.body_base64}
    filename={`exchange-${selected.id}-response-${responseVariant}.txt`}
    menuGroups={actions.menu(selected)}
   />,
  )
 ) : null;

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

 const runDelete = () => {
  const ids = confirmDelete?.scope === "selected" ? [...checkedRows] : null;
  removeRows.mutate(ids, {
   onSuccess: ({ removed, requested }) => {
    setConfirmDelete(undefined);
    setCheckedExchanges([]);
    if (selectedId !== null && ids !== null && ids.includes(selectedId)) setSelectedId(null);
    // Honest count, not a bare success: requested > removed means the operator named rows
    // already gone (another view deleted them, or the limit hid them). Say what actually
    // happened rather than "Deleted".
    toast.success(requested > removed ? `Deleted ${removed} of ${requested} rows (rest were already gone)` : `Deleted ${removed} rows`);
   },
   onError: (cause) => toast.error(`Could not delete: ${cause.message}`),
  });
 };

 /** Burp's "Audit selected items" (Zhw0): one scan over exactly the ticked rows.
  *
  *  The toast reports the reply's own count rather than the number of ticks, because the two can
  *  differ — the server drops repeated ids — and a message quoting the selection would claim work the
  *  scan did not take on. The selection is deliberately left in place: Burp keeps it too, and an
  *  operator auditing a set and then sending the same set to Intruder should not have to tick it
  *  twice. */
 const launchSelectedAudit = () => {
  auditSelected.mutate(
   { exchange_ids: [...checkedRows] },
   {
    onSuccess: (reply) =>
     toast.success(
      reply.duplicates_dropped > 0
       ? `Audit started over ${reply.count} item${reply.count === 1 ? "" : "s"} (${reply.duplicates_dropped} repeated id${reply.duplicates_dropped === 1 ? "" : "s"} dropped)`
       : `Audit started over ${reply.count} item${reply.count === 1 ? "" : "s"}`,
     ),
    onError: (cause: unknown) =>
     toast.error(`Could not start the audit: ${cause instanceof Error ? cause.message : "the server refused it"}`),
   },
  );
 };

 const columns = useMemo<Column<Exchange>[]>(
  () => [
   {
    // The tick column Delete items works on (r6li). Not sortable and not a data accessor —
    // its state is the page's checkedRows set, so the memo's [] deps hold and a row object
    // never carries view state.
    id: "tick",
    header: "",
    size: 34,
    enableSorting: false,
    enableHiding: false,
    cell: (info) => {
     const id = info.row.original.id;
     return (
      <Checkbox
       label={<span className="sr-only">{`Select row ${id}`}</span>}
       checked={checkedRows.has(id)}
       onCheckedChange={(on) => {
        const next = new Set(checkedRows);
        if (on) next.add(id);
        else next.delete(id);
        setCheckedExchanges([...next]);
       }}
      />
     );
    },
   },
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
    // accessorKey (not accessorFn) so sorting still orders by the raw media type rather than by
    // the rendered word — "untyped" must not sort in among the u's as though it were a type. The
    // row is reached through info.row.original because the label needs `response` too.
    cell: (info) => {
     const row = info.row.original;
     return (
      <span className="cell-dim" title={row.mime || (row.response === null ? "No response was captured" : "The response declared no Content-Type")}>
       {mimeLabel(row)}
      </span>
     );
    },
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
    // Burp's Cookies column (burpsy-react-ui-f4hc): names, not values - values are
    // secrets more often than not, and a column is the wrong place for them.
    id: "cookies",
    header: "Cookies",
    size: 110,
    accessorFn: (row: Exchange) => row.cookies ?? [],
    cell: (info) => {
     const names = info.getValue<string[]>();
     return names.length ? (
      <span className="cell-num" title={names.join(", ")}>
       {names.length}
      </span>
     ) : (
      <span className="cell-dim">—</span>
     );
    },
   },
   {
    // Burp's IP column (burpsy-react-ui-mr4p): the destination server's address as the socket
    // actually reached it. Dimmed rather than blank when absent, because "" is a real answer —
    // this row came from a producer with no socket, or from a server that did not record it.
    id: "server_ip",
    header: "IP",
    size: 130,
    accessorFn: (row: Exchange) => row.server_ip ?? "",
    cell: (info) => {
     const ip = info.getValue<string>();
     return ip === "" ? <span className="cell-dim">—</span> : <span>{ip}</span>;
    },
   },
   {
    // Burp's Listener port column (burpsy-react-ui-he81): which listener captured this row.
    // Zero is not a port — it means this exchange did not come from a listener at all (Repeater,
    // Intruder, a crawl) — so it renders as absent rather than as "0".
    id: "listener_port",
    header: "Listener port",
    size: 110,
    accessorFn: (row: Exchange) => row.listener_port ?? 0,
    cell: (info) => {
     const port = info.getValue<number>();
     return port === 0 ? <span className="cell-dim">—</span> : <span className="cell-num">{port}</span>;
    },
   },
   {
    // Burp's Title column (burpsy-react-ui-tk6z): the page title for HTML responses.
    id: "title",
    header: "Title",
    size: 200,
    accessorFn: (row: Exchange) => row.title ?? "",
    cell: (info) => {
     const text = info.getValue<string>();
     return text === "" ? <span className="cell-dim">—</span> : <span title={text}>{text}</span>;
    },
   },
   {
    // Burp's "Edited" column (burpsy-react-ui-c05, corrected by sd0d): a row the *operator* modified by
    // hand in Intercept. Not "a row whose bytes differ from the peer's" — burpsy rewrites traffic of
    // its own accord after the hold, so that reading put this badge on traffic nobody had touched.
    // Automatic rewrites are still visible per row, one click away, in the reading picker: this column
    // answers who changed the message, the picker answers what it became.
    //
    // The empty state is the table's own `—` rather than a blank cell, because every other column
    // reads that way and a column that was silently empty would look like a field this build had
    // forgotten to populate. What stands out on the rows that carry something is the badge, which
    // is the point: the unedited majority is the background this column is read against.
    id: "edited",
    header: "Edited",
    size: 76,
    accessorFn: (row: Exchange) => row.variants?.edited ?? false,
    cell: (info) =>
     info.getValue<boolean>() ? <Badge tone="warn">edited</Badge> : <span className="cell-dim">—</span>,
   },
   {
    accessorKey: "response_len",
    header: "Length",
    size: 84,
    cell: (info) => <span className="cell-num">{formatBytes(info.getValue<number>())}</span>,
   },
   {
    // Burp splits the response timer in two (burpsy-react-ui-jcdm). TTFB is the wait for the
    // origin to start answering; Total is the whole transfer. An em dash rather than 0 where the
    // producer never timed the first byte — claiming an instant first byte would be worse than
    // admitting the row does not know.
    accessorKey: "ttfb_ms",
    header: "TTFB",
    size: 78,
    cell: (info) => {
     const ms = info.getValue<number | null>();
     return ms === null || ms === undefined ? (
      <span className="cell-dim">—</span>
     ) : (
      <span className="cell-num">{formatDuration(ms)}</span>
     );
    },
   },
   {
    accessorKey: "duration_ms",
    header: "Total",
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
  // checkedRows is read inside the tick cell, so the memo tracks it (the Checkbox is fully
  // controlled; without this a re-tick would not re-render the header count on the button). The
  // setter is stable, but it is named here too because the cell is the only writer.
  [checkedRows, setCheckedExchanges],
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
    <MessageLayoutSwitch value={messageLayout} onChange={setMessageLayout} />
   </div>
   <div
    className={[
     inspector ? "editor-grid-inspected" : "editor-grid",
     messageLayout === "horizontal" ? "editor-grid-horizontal" : "",
     messageLayout === "combined" ? "editor-grid-combined" : "",
    ]
     .filter(Boolean)
     .join(" ")}
   >
    {/* The row menu, on the message itself. Burp carries the same actions in both places, and
            reading a response then sending it straight to Repeater is the gesture this pane exists
            for — reaching back up to the table row to do it is the divergence. */}
    {messageLayout === "combined" ? (
     <Tabs defaultValue="request" className="editor-combined">
      <TabsList>
       <TabsTrigger value="request">Request</TabsTrigger>
       <TabsTrigger value="response">Response</TabsTrigger>
      </TabsList>
      <TabsContent value="request" className="tabs-fill">
       {requestPane}
      </TabsContent>
      <TabsContent value="response" className="tabs-fill">
       {responsePane}
      </TabsContent>
     </Tabs>
    ) : (
     <>
      {requestPane}
      {responsePane}
     </>
    )}
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
       {/* Burp's third scan kind, launched from the selection the way Burp launches it: right-click
           or toolbar, on the items you ticked, as one task. It sits next to Delete items because that
           is the other action on the tick column, and both are disabled with the same reason. */}
       <Button
        variant="outline"
        size="small"
        onClick={launchSelectedAudit}
        disabled={checkedRows.size === 0 || auditSelected.isPending}
        title={
         checkedRows.size === 0
          ? "Tick rows to audit"
          : `Audit ${checkedRows.size} ticked item${checkedRows.size === 1 ? "" : "s"} as one scan`
        }
       >
        <Crosshair size={14} />
        Audit selected items
       </Button>
       <Button
        variant="danger"
        size="small"
        onClick={() => setConfirmDelete({ scope: "selected" })}
        disabled={checkedRows.size === 0}
        title={checkedRows.size === 0 ? "Tick rows to delete" : `Delete ${checkedRows.size} ticked rows`}
       >
        <Trash2 size={14} />
        Delete items
       </Button>
       <Button variant="danger" size="small" onClick={() => setConfirmDelete({ scope: "all" })} disabled={!data || data.length === 0}>
        <Trash2 size={14} />
        Clear
       </Button>
      </>
     }
    />
    <Toolbar style={{ marginTop: 10 }}>

     <FilterToggle pressed={filterOn} onPressedChange={setFilterOn} title="Suspend every filter below without clearing it">
      Filter
     </FilterToggle>
     <FilterToggle pressed={scopeOnly} onPressedChange={handleScopeToggle}>
      In scope only
     </FilterToggle>
     <FilterToggle pressed={hideNoResponse} onPressedChange={setHideNoResponse}>
      Hide items without responses
     </FilterToggle>
     <FilterToggle
      pressed={followNew}
      onPressedChange={setFollowNew}
      title="Keep the bottom of the table in view as new rows arrive"
     >
      Auto-scroll
     </FilterToggle>
     {/* FilterToggle takes a single string child, so the count is composed rather than
              interpolated as a second child. */}
     <FilterToggle pressed={columnFiltersOpen} onPressedChange={setColumnFiltersOpen}>
      {columnFiltersActive > 0 ? `Column filters (${columnFiltersActive})` : "Column filters"}
     </FilterToggle>
     <Button
      variant={filtersActive > 0 ? "outline" : "quiet"}
      size="small"
      aria-expanded={filterOpen}
      onClick={() => setFilterOpen(true)}
     >
      More filters{filtersActive > 0 ? ` (${filtersActive})` : ""}
     </Button>
     <BucketMenu
      label="Status"
      buckets={STATUS_BUCKETS.filter((bucket) => bucket.value !== "all")}
      selected={statusSet}
      onToggle={(value) =>
       setStatusSet((current) => (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]))
      }
      onReset={() => setStatusSet([])}
     />
     <BucketMenu
      label="Type"
      buckets={MIME_TYPES.filter((mt) => mt.value !== "all")}
      selected={mimeSet}
      onToggle={(value) =>
       setMimeSet((current) => (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]))
      }
      onReset={() => setMimeSet([])}
     />
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
    </Toolbar>

    {columnFiltersOpen ? (
     <Toolbar style={{ marginTop: 6 }} aria-label="Per-column filters">
      {COLUMN_FILTERS.map((spec) => (
       <Field key={spec.field} label={spec.label} className="field-inline">
        {(id) => (
         <Input
          id={id}
          value={columnFilters[spec.field]}
          placeholder={spec.placeholder}
          onChange={(event) => setColumnFilter(spec.field, event.target.value)}
         />
        )}
       </Field>
      ))}
      {columnFiltersActive > 0 ? (
       <Button
        variant="outline"
        size="small"
        onClick={() => {
         for (const spec of COLUMN_FILTERS) setColumnFilter(spec.field, "");
        }}
       >
        <X size={13} />
        Clear column filters
       </Button>
      ) : null}
      {/* Said once, here, rather than left to be discovered: these write clauses into the
                filter box above, and the columns the query grammar cannot express get no input. */}
      <span className="cell-dim">
       These append clauses to the filter box, so it always shows what is filtered. Status,
       type and method have their own controls above; extension, params, length, time and
       comment cannot be expressed in the query grammar and so have no filter here.
      </span>
     </Toolbar>
    ) : null}
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
      followNewRows={followNew}
      enableColumnVisibility
      columnVisibility={columnVisibility}
      onColumnVisibilityChange={setColumnVisibility}
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
       // The condition is "did any filter narrow this", not "is there a search term". Keying it
       // on `term` alone meant every other filter — the MIME one above all — emptied the table
       // and was answered with "No traffic captured yet. Point a client at the proxy", which is
       // a claim about the proxy, was false whenever a filter was responsible, and sent the
       // operator to check their client setup over a dropdown they had set themselves.
       appliedFilterNames.length > 0 ? (
        <Empty
         title="No exchange matches these filters"
         detail={`Nothing in the ${formatCount(data?.length ?? 0)} loaded rows matches ${appliedFilterNames.join(" + ")}. Relax or clear a filter to see more of the capture.`}
        />
       ) : (
        <Empty
         title="No traffic captured yet"
         detail="Point a client at the proxy and install the CA certificate to start capturing HTTPS."
        />
       )
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
    {/* The fourth clause, and the same reasoning as the three numbers above: zero is the count
            that most needs a cause attached. "0 of 300 loaded rows" is true and still reads as an
            empty capture, so when a filter is what produced the zero, the filter is named here.
            Kept to the zero case on purpose - naming the active filters on every render would be
            noise beside a count that already explains itself.

            --fg, not --warn: this is a neutral statement of cause, and the yellow token is a
            14px-on-paper contrast risk in a status bar the axe suite currently passes clean. */}
    {rows.length === 0 && (data?.length ?? 0) > 0 && appliedFilterNames.length > 0 ? (
     <div style={{ color: "var(--fg)" }} title="Which filters are responsible for the empty table">
      no match for {appliedFilterNames.join(" + ")}
     </div>
    ) : null}
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
      {/* Burp's dedicated search field (proxyHttpSearch*Checkbox modify it). Deliberately its
                own input, not the top-bar box: that box is a DSL statement the server evaluates,
                and a regex tick over it turned `host ~ "api" AND status = 200` into a pattern that
                matches nothing — the defect this field exists to remove (burpsy-react-ui-vlf). */}
      <Field label="Search for" hint="Text or pattern over method, host, path, MIME and comment. Separate from the filter box above — the modifiers apply only here.">
       {(id) => (
        <Input
         id={id}
         value={searchText}
         onChange={(event) => setSearchText(event.target.value)}
         placeholder="text or pattern"
        />
       )}
      </Field>
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
        setSearchText("");
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
   <Modal
    open={confirmDelete !== undefined}
    onOpenChange={(open) => {
     if (!open) setConfirmDelete(undefined);
    }}
    title={confirmDelete?.scope === "selected" ? "Delete the ticked items?" : "Clear the capture?"}
    description={
     confirmDelete?.scope === "selected"
      ? "The ticked rows leave the history view. The underlying capture is not renumbered, and this cannot be undone."
      : "Every history row leaves the view. Message bytes stay on disk in a persisted store, and this cannot be undone."
    }
   >
    <div className="detail-actions">
     <Button variant="danger" disabled={removeRows.isPending} onClick={runDelete}>
      <Trash2 size={14} />
      {removeRows.isPending
       ? "Deleting…"
       : confirmDelete?.scope === "selected"
        ? `Delete ${checkedRows.size.toLocaleString()} ${checkedRows.size === 1 ? "row" : "rows"}`
        : `Clear ${formatCount(data?.length ?? 0)} rows`}
     </Button>
     <Button variant="outline" onClick={() => setConfirmDelete(undefined)}>
      Keep them
     </Button>
    </div>
   </Modal>
  </div>
 );
}
