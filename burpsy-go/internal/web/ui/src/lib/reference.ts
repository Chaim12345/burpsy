/**
 * The in-app reference: what an operator of *this* tool currently has to read
 * source or docs to find out.
 *
 * Burp's tool registry has a DISCOVER constant — the tab formerly called "Learn"
 * — and in Burp it is a farm of links to the Web Security Academy, the manual and
 * the community forum. Reproducing that here would be worthless: burpsy has no
 * academy to link to, and a page of outbound links is not an answer to "why did
 * this scan find nothing".
 *
 * So this is the honest analogue. Everything below already exists somewhere in
 * this tree — `internal/query`'s package doc, `internal/bcheck`'s parser,
 * ROADMAP.md's out-of-scope table, `ui-gaps.md` — and the point of the module is
 * that it is *reachable from the console* rather than from a checkout.
 *
 * Content is data here rather than JSX for the same reason `lib/shortcuts.ts`
 * holds the hotkeys as data: the query panel is rendered twice, once on the
 * Discover page and once in History's filter-syntax modal, and two renderers of
 * one list stay in step where two hand-maintained lists do not.
 *
 * Verified against the implementation, not transcribed from memory:
 *   - Every QUERY_EXAMPLES entry is fed to internal/query.Parse, and every
 *     QUERY_REFUSALS entry is required to fail it, by
 *     internal/web/reference_examples_test.go. A grammar this page documents and
 *     the parser rejects is a test failure, not a support ticket.
 *   - BCHECK_SKELETON was parsed by internal/bcheck.Parse while this page was
 *     written; it classifies as an M2-runnable active check.
 *   - Each LIMITS row was checked against the code it describes. Where ui-gaps.md
 *     had gone stale — it still lists "no protocol arm on scope rules", which
 *     core.ScopeRule.Protocol and the Scope page's protocol select have since
 *     closed — the code won and the row is absent.
 */

import { chordKeys, shortcutGroups, type Keymap } from "./shortcuts";

/** One term and what it means. `keys` renders as <Kbd> chips instead of monospace text. */
export interface ReferenceRow {
 /** A stable React key when `term` is not unique in its panel (two unbound hotkeys both read "unbound"). */
 key?: string;
 term: string;
 detail: string;
 keys?: string[];
 /** A secondary line: a caveat, a deviation from Burp, the reason a gap exists. */
 note?: string;
}

/** A monospace block: a grammar, a file skeleton, a worked example. */
export interface ReferenceBlock {
 label: string;
 body: string;
}

export interface ReferencePanel {
 id: string;
 title: string;
 summary: string;
 /** Where in the tree this material is maintained, so a reader can check it. */
 source: string;
 blocks?: ReferenceBlock[];
 rows: ReferenceRow[];
}

/* --- the query DSL --------------------------------------------------------- */

const QUERY_GRAMMAR = `query      := or-expr
or-expr    := and-expr ( "or" and-expr )*
and-expr   := unary-expr ( "and" unary-expr )*
unary-expr := "not" unary-expr | primary
primary    := "(" or-expr ")" | comparison
comparison := field op value
field      := "host" | "status" | "method" | "path" | "mime" | "body"\n            | "length" | "duration" | "extension" | "params"\n            | "highlight" | "comment" | "task" | "header" "[" string "]"`;

/**
 * Filter examples, one complete query per entry.
 *
 * internal/web/reference_examples_test.go reads this array out of this file and
 * feeds every `query` to internal/query.Parse, so an example that the shipped
 * parser would reject fails `go test` rather than misleading an operator.
 * Keep each `query` on one line — that is what the test's extractor reads.
 */
export const QUERY_EXAMPLES: { query: string; means: string }[] = [
 { query: "host = api.example.com", means: "Exact host. host folds case, so API.Example.com matches too." },
 { query: "host ~ example", means: "Substring. ~ is contains, never a regular expression." },
 { query: "status = 500", means: "Exact status." },
 { query: "status != 304", means: "Every 304 excluded — and every row with no response yet, which has no status to differ from." },
 { query: "status >= 400", means: "Ordered comparison. status, length and duration are the numeric fields." },
 { query: "status in 500..599", means: "Range, inclusive at both ends." },
 { query: "method = POST", means: "Case-sensitive: method = post matches nothing." },
 { query: "path ~ /admin", means: "Also case-sensitive, per RFC 3986." },
 { query: "task = 3", means: "Only the traffic dashboard task 3 produced — a crawl, audit or attack run." },
 { query: "task != 0", means: "Only traffic some run owns. task = 0 is everything you proxied yourself, which no run tracked." },
 { query: "mime ~ json", means: "Matched against the response Content-Type, case-insensitively." },
 { query: "length > 1mb", means: "Response size. b, kb, mb and gb are accepted; a bare number means bytes." },
 { query: "length in 1kb..1mb", means: "Size range, inclusive at both ends." },
 { query: "length = 0", means: "A genuinely empty response, such as a 204 — not a request still waiting, which has no length at all." },
 {
  query: "duration > 500ms",
  means: "Slow exchanges. us, ms and s are accepted; a bare number means milliseconds, matching the History column.",
 },
 { query: "duration in 100ms..2s", means: "Timing range. Exchanges nobody timed match no duration comparison, including this one." },
 { query: 'header["server"] ~ "nginx"', means: "A response header. The name is quoted and case-insensitive; the value folds case too." },
 {
  query: 'header["set-cookie"] ~ "HttpOnly"',
  means: "Any-of over a repeated header: Set-Cookie appears many times and this matches if any value does.",
 },
 {
  query: 'not header["strict-transport-security"] ~ "max-age"',
  means: "Responses missing HSTS. An absent header fails every comparison, so `not` is how you ask for its absence.",
 },
 { query: 'extension = "js"', means: "The path's last-segment extension, lower-cased. A path with none matches no extension comparison." },
 {
  query: "params > 3",
  means: "How many QUERY parameters the path carries — the same count the Query column shows, body parameters excluded.",
 },
 { query: 'highlight = "red"', means: "Your own highlight colour. These two fields describe burpsy's state, not the target's." },
 { query: 'highlight = ""', means: 'Rows you have not highlighted. "" is a real answer here, unlike every other field.' },
 { query: 'comment ~ "injectable"', means: "Your own note on the row, searched case-insensitively." },
 { query: "body ~ password", means: "The only operator body accepts, matched against the raw bytes." },
 { query: "host = api.example.com and status >= 400", means: "and binds tighter than or." },
 { query: "method = POST or method = PUT", means: "Keywords are case-insensitive; AND and OR also parse." },
 { query: "not path ~ /static and status = 200", means: "not binds tightest, and takes a bare comparison." },
 { query: "(host ~ api or host ~ auth) and status >= 500", means: "Parentheses override both precedences." },
 { query: 'host = "8080"', means: "Quote a value that is all digits to mean the text." },
];

/**
 * Queries the grammar refuses, and why that is the feature.
 *
 * The same Go test requires every one of these to fail Parse. A query that is
 * ill-typed must be an error before a single row is compared — in a filter box a
 * runtime failure is indistinguishable from "no matches", which is the one
 * mistake a closed typed grammar exists to prevent.
 */
export const QUERY_REFUSALS: { query: string; why: string }[] = [
 { query: 'status > "abc"', why: "A string where status wants an integer. Rejected at parse time, not silently false." },
 { query: "body = anything", why: "body supports ~ only. Byte-for-byte equality on a whole body is never what is meant." },
 { query: "host = 8080", why: 'A bare all-digit word where a string belongs. Quote it: host = "8080".' },
];

export const QUERY_PANEL: ReferencePanel = {
 id: "query",
 title: "Query language",
 summary:
  "The filter grammar over captured traffic. One small closed typed language, shared by the History filter box and the CLI's history --query.",
 source: "internal/query — grammar and rationale in query.go's package doc",
 blocks: [
  { label: "Grammar", body: QUERY_GRAMMAR },
  { label: "Examples", body: QUERY_EXAMPLES.map((entry) => entry.query).join("\n") },
  { label: "Refused at parse time", body: QUERY_REFUSALS.map((entry) => entry.query).join("\n") },
 ],
 rows: [
  {
   term: "host, method, path, mime",
   detail: "= (or ==), != and ~ (contains), each against a string value.",
   note:
    "host and mime fold case — DNS names and MIME types both are case-insensitive. method and path do not, because the method token is case-sensitive per RFC 7230 and the path per RFC 3986; folding either would accept a query describing a different wire request than the one sent.",
  },
  {
   term: "status",
   detail: "= (or ==), !=, <, <=, >, >= with an integer, or in low..high for a range inclusive of both ends.",
   note:
    "A literal outside 0-65535 is refused at parse time. An inverted range (status in 299..200) parses and matches nothing — the bounds are compared, not reordered.",
  },
  {
   term: "body",
   detail: "~ only, matched case-sensitively against the raw response bytes.",
  },
  {
   term: "length",
   detail: "Response size in bytes: = (or ==), !=, <, <=, >, >= and in low..high. Accepts b, kb, mb and gb; a bare number means bytes.",
   note:
    "length = 0 is a real answer — a 204 is zero-length — so it does not match a request still waiting, which has no length at all. An inverted range (length in 1mb..1kb) is refused at parse time rather than matching nothing.",
  },
  {
   term: "highlight, comment",
   detail: "Your own annotations on a row: =, != and ~ (contains), all case-insensitive.",
   note:
    'The only fields here describing burpsy\'s state rather than the target\'s, and the only ones where "" is a real answer — highlight = "" asks for rows you have not triaged. Everywhere else an empty value means the target gave us nothing and fails every comparison. A consumer that cannot answer at all (the crawler\'s frontier gate, a match/replace candidate) still fails every comparison including the empty one, so a queued URL is never reported as an untriaged exchange.',
  },
  {
   term: "extension, params",
   detail: "Derived from the path: extension takes =, != and ~ case-insensitively; params is a count and takes the numeric operators.",
   note:
    "Both are computed from the path rather than sent, so they cannot disagree between rows — and they use the same rules as the History table's Extension and Query columns (pathParts), so the filter and the column beside it always agree. params counts QUERY parameters only; Burp's Params column also counts body parameters, which are not on an index row. A path with no extension matches NO extension comparison, negations included.",
  },
  {
   term: 'header["name"]',
   detail: "A response header: = (or ==), != and ~ (contains). The name is quoted and matched case-insensitively; so is the value.",
   note:
    'Indexed rather than a flat text match over the whole head, which would let a match straddle a header boundary. Any-of over repeated values, because Set-Cookie repeats and "does any cookie contain HttpOnly" is the question. An absent header fails EVERY comparison including !=, so ask for absence with not header["x"] ~ "y". A header present with an empty value is not absent.',
  },
  {
   term: "duration",
   detail:
    "How long the exchange took: the same operators as length. Accepts us, ms and s; a bare number means milliseconds, matching the History column.",
   note:
    "An exchange nobody timed matches NO duration comparison, negations included. burpsy records whether a duration was measured rather than defaulting to zero, so an untimed exchange is never reported as instantaneous.",
  },
  {
   term: "Absent fields are absent, not zero",
   detail:
    'A request with no response yet has status 0, mime "", no length and no duration, and every comparison on an absent field is false — never true, never an error.',
   note:
    "This is why status != 304 does not include pending rows: they have no status to differ from. Before it was explicit, status < 400 matched every request still waiting, because 0 < 400. length and duration carry the same rule through an explicit presence flag rather than a sentinel value, because 0 bytes and 0 microseconds are both real answers.",
  },
  {
   term: "Precedence",
   detail: "not binds tightest, then and, then or — so a or b and c parses as a or (b and c). Parentheses override both.",
  },
  {
   term: "Strings",
   detail:
    'Quoted values support exactly five escapes: \\", \\\\, \\n, \\t and \\r. An unrecognised escape is a parse error rather than a silently dropped backslash.',
   note:
    "An unquoted bare word is accepted as a string (host = example.com). The Rust reference requires quotes; this is a named divergence, not an accident.",
  },
  {
   term: "Where it runs",
   detail:
    "The History filter box sends the expression to the server; the CLI takes the same text as history --query. The crawler frontier gate refuses a query naming a field it cannot honestly evaluate before a response exists.",
  },
 ],
};

/* --- BCheck --------------------------------------------------------------- */

const BCHECK_SKELETON = `metadata:
    language: v2-beta
    name: "Readable .git directory"
    description: "Requests .git/HEAD and reports a readable Git repository"
    author: "burpsy"
    tags: "exposure", "misconfiguration"

define:
    probe = "/.git/HEAD"

given host then
    send request called head:
        method: "GET"
        replacing path: {probe}
        appending headers:
            "Accept": "*/*"

    if {head.response.status_code} is "200"
       and {head.response.body} contains "ref:" then
        report issue:
            severity: medium
            confidence: firm
            detail: "The Git repository is served at {probe}."
            remediation: "Deny requests for /.git from the web root."
    end if`;

export const BCHECK_PANEL: ReferencePanel = {
 id: "bcheck",
 title: "BCheck syntax",
 summary:
  "PortSwigger's check DSL, parsed and evaluated in full. Burp's scan checks are largely data rather than code, so one interpreter inherits the published corpus instead of porting hundreds of Java checks.",
 source: "internal/bcheck (parser.go, bcheck.go, active.go); docs/BCHECK-COVERAGE.md",
 blocks: [{ label: "A complete check", body: BCHECK_SKELETON }],
 rows: [
  {
   term: "Loading a corpus",
   detail:
    "Start burpsy with -bchecks DIR. The corpus is deliberately not vendored into this repository — you supply the directory, and the loader reports what it read.",
  },
  {
   term: "metadata:",
   detail:
    "language, name, description, author, severity, confidence, and tags / reference (comma-separated). Unknown keys are tolerated as v2-beta extensions rather than refused.",
  },
  {
   term: "define:",
   detail: "name = value pairs, comma-separated. Referenced elsewhere as {name}. define: and run for each: may appear in either order.",
  },
  {
   term: "run for each:",
   detail: "name = v1, v2, … — the check body runs once per combination.",
   note:
    "Bounded at 10,000 entries per list and 100,000 across the cartesian product, so a hostile check cannot turn the evaluator into a denial of service.",
  },
  {
   term: "given … then",
   detail:
    "One of: response, host, request, path, or insertion point. An insertion-point check may name the kinds it wants — any, query, header, body or cookie, joined by or — as in given query or header insertion point then.",
   note:
    "given response with no send and no run tool is what makes a check passive; everything else is active. The published corpus splits 104 response, 98 host, 40 request, 11 path.",
  },
  {
   term: "send request:",
   detail:
    "Either a raw literal or template string, or clauses of replacing / appending plus a target — method, path, query_string, queries, headers or body. send request called NAME: binds the result as {NAME.response…}.",
   note:
    "Replacing path leaves the query string intact, because the grammar exposes path and query_string as separate targets. That is an inference from the grammar, not an observation of Burp's runtime, and it is marked as such in the code.",
  },
  {
   term: "if … then / else if / else / end if",
   detail: "end if is the only block terminator. Whitespace and newlines are insignificant, and # starts a comment to end of line.",
  },
  {
   term: "Comparisons",
   detail:
    "is, matches (RE2), contains, in, differs from, eq, ne — combined with and, or, not and parentheses. <any|dns|http|smtp> interactions polls a Collaborator.",
   note:
    'An absent operand makes a comparison false, never true. Coercing an unresolvable path to the empty string once made {missing} in {latest.response} report on every response, because contains("") is true.',
  },
  {
   term: "report issue:",
   detail:
    "severity (high, medium, low, info) and confidence (certain, firm, tentative) are required; name, detail and remediation are optional.",
  },
  {
   term: "base and latest",
   detail:
    "Two different messages once anything has been sent. Every send updates latest; before the first send they are the same exchange.",
   note:
    "Every send is built from base.request, never from the previous send — a second send payload is base plus payload, not payload plus payload. Modifiers accumulate within one send request; sends do not accumulate.",
  },
  {
   term: "A failed send abandons the check",
   detail:
    "Continuing would leave {check.response} absent and invite exactly the false positive the absence rules prevent. The failure is counted, not swallowed.",
  },
  {
   term: "One insertion point per send",
   detail:
    "A given insertion point check runs once per point and mutates exactly one, so a finding is attributable to a single parameter. Outside such a check the finding's Parameter column is empty on purpose — a per-host finding is about a resource, not a parameter.",
   note:
    "Nested insertion points are deliberately not enumerated: a miss, never a false positive. any includes headers, which the JWT checks depend on.",
  },
  {
   term: "run tool:",
   detail:
    "Shells out to an external binary, so it is never passive. Not dispatched unless burpsy was started with -tools name=/abs/path; without a runner it is counted at load and refused.",
  },
 ],
};

/* --- what burpsy deliberately does not do --------------------------------- */

export const LIMITS_PANEL: ReferencePanel = {
 id: "limits",
 title: "What burpsy does not do",
 summary:
  "Every row is a decision, not a defect — and each one is a way a result can be narrower than it looks. Read this before reading a quiet scan as an absent vulnerability.",
 source: "ROADMAP.md § Deliberately out of scope; burpsy-go/ui-gaps.md; each row re-checked against the code",
 rows: [
  {
   term: "Out-of-band BCheck checks",
   detail:
    "BCheck's interactions operator has no interaction server behind it. The 26 corpus checks that use it are counted into a Collaborator bucket when the corpus loads and are never dispatched.",
   note:
    "generate_collaborator_address() is deliberately not stubbed: an address nothing polls would convert all 26 into silent false negatives. The catalog's own OOB rows — SSRF, blind SQLi, XXE, the three external-service-interaction issues — do run, but only when the interactsh-client binary is on PATH; without it they decline with a reason instead of reporting clean.",
  },
  {
   term: "HTTPS without -intercept-tls",
   detail:
    "The proxy blind-tunnels CONNECT and records one message-less row with tls: true. The requests inside that tunnel are never in HTTP history, and nothing scans them.",
   note:
    'The same is true per host for anything matched by TLS passthrough. /ca.crt answers 404 and the status bar reads "no CA" when interception is off, so the console never offers a certificate it cannot hand out.',
  },
  {
   term: "Parse rate is not run rate",
   detail: "All 264 published BCheck files parse. That number says nothing about how many reached a verdict against your traffic.",
   note:
    "GET /api/scanner/coverage reports every loaded check as never dispatched, ran clean, ran and found, or errored, with a reason for each skip. With nothing loaded it says so rather than implying a clean scan.",
  },
  {
   term: "Loading Burp extensions",
   detail:
    "Impossible: no JVM, and no binary or source compatibility with MontoyaApi. There is no plugin surface of any kind — the extension phase was never shipped.",
   note:
    "Of userInterface()'s registration points, the ten Swing ones are out of scope for lack of an honest web analogue. The three declarative ones — context-menu items, message-editor tabs, menu actions — are in scope.",
  },
  {
   term: "Deleting captured traffic",
   detail:
    "The capture store is append-only. It has put, add and annotate, and no delete of any kind; History's filters hide rows and remove nothing.",
  },
  {
   term: "The site map only grows",
   detail:
    "Same store, same property: the site map adds and never removes. A host on the map was observed at some point — that is not evidence it is reachable now.",
  },
  {
   term: "Custom scan configurations",
   detail:
    "Six of Burp's 29 shipped configurations set a key this engine implements, and there are no custom-config knobs, so there is no configuration wizard — it would offer controls that do nothing.",
   note: 'The working path is the row context menu\'s "Audit exchange", or Target → Issues → targeted audit with the config selector.',
  },
  {
   term: "Bambda filters",
   detail:
    "importBambda takes Java source. The filter substrate here is the closed typed grammar above, deliberately not a scripting engine.",
   note: 'The route answers 400 with a grammar reference — never {"imported": true} for something that was never executed.',
  },
  {
   term: "Project files",
   detail:
    "Burp's exportProjectFileAndExit, loadProjectFile and restart all presuppose a project file. Durable state here is a capture directory plus a SQLite mirror, which is a different object.",
   note:
    "project().name() returns null on purpose. A name derived from the -db filename would land in report headers as if an operator had chosen it.",
  },
  {
   term: "An IP address column",
   detail:
    "The exchange record carries no IP field, so History cannot show one. A column filled from a fresh lookup would report where the host resolves now, not where the request went.",
  },
  {
   term: "Show response in browser",
   detail:
    "Absent. Burp loops the response back through its own listener and burpsy has no loopback surface, so the menu item does not exist rather than existing and failing.",
  },
  {
   term: "An MCP server",
   detail:
    "Not shipped, in this port or in the Rust reference. The JSON API is what drives burpsy today; docs/MCP.md records the plan as a plan.",
  },
  {
   term: "A desktop shell",
   detail:
    "A native window ships: cmd/desktop is a Wails v2 shell with a native File/View/Tools/Help menu bar, native dialogs and the same console UI served over a reverse proxy. There is no system tray, and the browser page on the -web address remains the headless path — burpsy stays usable over SSH without the shell.",
  },
  {
   term: "Porting Burp's Java scan checks",
   detail:
    "Out of scope as derivative work. Checks are implemented from the published specs and the public BCheck and Montoya contracts instead — which is also why the corpus is loaded at runtime rather than vendored.",
  },
  {
   term: "Enterprise and CI features",
   detail: "Out of scope. Several are Enterprise-only in Burp itself and have no desktop-product behaviour to match.",
  },
 ],
};

/* --- shipped documentation ------------------------------------------------ */

export const DOCS_PANEL: ReferencePanel = {
 id: "docs",
 title: "Shipped documentation",
 summary:
  "Files in the repository, not URLs. The console serves no documentation route, so these are paths to open in a checkout rather than links that would 404 here.",
 source: "burpsy-go/docs/",
 rows: [
  { term: "docs/QUICKSTART.md", detail: "Clone to a running headless proxy and JSON API, including CA installation and BCheck loading." },
  {
   term: "docs/JSON-API.md",
   detail: "Every route, derived from setupRoutes and the canonical route manifest rather than written by hand.",
  },
  { term: "docs/DATA-MODEL.md", detail: "The entities, how they are identified, how they relate — and which relations do not exist yet." },
  {
   term: "docs/SCANNER-COVERAGE.md",
   detail: "The 183-issue catalog: what is registered, and the separate question of what has been demonstrated at runtime.",
  },
  { term: "docs/SCANNER-INFRA.md", detail: "The capability layer behind the catalog checks and the wiring that sits on it." },
  { term: "docs/BCHECK-COVERAGE.md", detail: "Parse conformance versus runtime coverage, and why the two are counted separately." },
  { term: "docs/MCP.md", detail: "Status and plan for an MCP surface — explicitly not shipped." },
  { term: "docs/DESKTOP.md", detail: "What a native shell would need, and why there is not one." },
  {
   term: "ROADMAP.md",
   detail: "Phase-by-phase state, with a Deliberately out of scope table that this page's limits panel is drawn from.",
  },
  { term: "DESIGN.md", detail: "The console's density rules: 24px rows, hairlines, no shadows, no gradients." },
 ],
};

/* --- per-tool menus (u9zz) ------------------------------------------------ */

/**
 * One panel per tool whose context menu ends with a "<Tool> documentation" entry (lib/docs.ts).
 * Each lists what that menu's entries do, in the menu's own words, plus where burpsy differs from
 * Burp. lib/reference-topics.test.ts requires a panel for every topic a menu names.
 */
export const TOOL_PANELS: ReferencePanel[] = [
 {
  id: "tool-tables",
  title: "Tables",
  summary: "What every table in the console does, whichever tool it belongs to.",
  source: "src/ui/table.tsx, src/lib/table-selection.ts, src/lib/filter-presets.ts",
  rows: [
   {
    term: "Click / Ctrl-click / Shift-click",
    detail:
     "Select one row, toggle one, or select the range from the last plain click. Ranges follow the rows as displayed — sorted and filtered.",
    note: "Opt-in per table: History, Logger and the site map's request table have it.",
   },
   { term: "Shift+arrows, Ctrl+A", detail: "Extend the selection from the keyboard; select every displayed row (with the table focused)." },
   {
    term: "Right-click inside a selection",
    detail:
     "Keeps the selection and offers the N-row menu: Send to Comparer (A and B), Copy URLs, Add to Organizer, Add hosts to scope, and the table's own bulk actions.",
   },
   {
    term: "Column header right-click",
    detail: "Copy <column> column (every loaded row's value), Hide <column> column, Restore default table layout.",
   },
   { term: "Columns button", detail: "Show or hide columns; the choice is remembered per table." },
   { term: "Drag a header grip", detail: "Reorder columns; the order is remembered per table." },
   {
    term: "Saved filters",
    detail: "History, Logger and Organizer: restore defaults, save the filter as a named preset or to a file, and load either back.",
   },
   {
    term: "Go to entry",
    detail: "History: jump to a row by its # number; says when the row is filtered out, older than the loaded rows, or gone.",
   },
  ],
 },
 {
  id: "tool-proxy-history",
  title: "Proxy history",
  summary: "The HTTP history row menu (and the same menu on the site map's request table).",
  source: "src/lib/actions.ts (useExchangeActions().menu), src/pages/history.tsx",
  rows: [
   {
    term: "Send to Repeater / Intruder / Sequencer / Decoder",
    detail: "Hand the exchange's request to that tool. Repeater opens a new tab; the others seed their input.",
   },
   { term: "Send to Comparer (A) / (B)", detail: "Load the request into one side of Comparer." },
   {
    term: "Edit a copy in Repeater",
    detail:
     "Change request method, change body encoding, toggle chunked framing — each on a copy in a new Repeater tab; the history row never changes.",
   },
   {
    term: "Copy URL / Copy as curl / Copy as sqlmap command / Copy links",
    detail: "The URL; a curl or sqlmap command with the request's headers and body; every link the response carries.",
   },
   { term: "Copy request to file / Save request and response", detail: "Download the request alone, or both halves in one labelled file." },
   { term: "Highlight / Add comment", detail: "Annotate the row; both are filterable (highlight and comment are query fields)." },
   {
    term: "Add to Organizer / Add to site map",
    detail: "Keep the exchange in Organizer; record its URL on the site map without sending anything.",
   },
   { term: "Show details in new window", detail: "The request and response in a separate window (also: double-click a row)." },
   { term: "Filter history by <host>", detail: "Replace the query with host = <host>." },
   {
    term: "Open URL in browser / Show response in browser",
    detail: "Fetch the URL through burpsy's browser, or serve this exchange's stored response as-is.",
   },
   { term: "Add <host> to scope", detail: "An include rule for the host. The status bar's rule count updates." },
   {
    term: "Audit exchange / Actively scan this branch or host (crawl)",
    detail: "Queue an active audit of this exchange, or crawl from it.",
   },
   {
    term: "Record an issue / Generate CSRF PoC",
    detail: "Record a finding against this exchange; open an auto-submitting PoC page for it.",
   },
   {
    term: "Delete selected items",
    detail: "Multi-row menu: remove the rows from the history view, after a confirmation.",
    note: "Burp's Delete item; the underlying capture is not renumbered.",
   },
  ],
 },
 {
  id: "tool-websockets",
  title: "WebSockets history",
  summary: "The frame and connection menus on Proxy › WebSockets history.",
  source: "src/pages/wshistory.tsx",
  rows: [
   { term: "Send to Repeater", detail: "Open the connection in a Repeater WebSocket tab." },
   { term: "Send payload to Comparer (A) / (B) / Decoder", detail: "Hand one frame's payload to that tool." },
   { term: "Copy frame summary / frame id / exchange id", detail: "Identifiers and a one-line description for notes and tickets." },
   { term: "Save payload to file", detail: "The frame's payload bytes, as a download." },
   { term: "Show this exchange in HTTP history", detail: "Jump to the upgrade request that opened the connection." },
  ],
 },
 {
  id: "tool-site-map",
  title: "Site map",
  summary: "The site map tree's node menu; its request table uses the Proxy history menu.",
  source: "src/pages/sitemap.tsx",
  rows: [
   {
    term: "Expand / Collapse host or branch",
    detail: "Open or close every folder under the node. Expanding stops at 5,000 folders and says how many stayed closed.",
   },
   { term: "Add <host> to scope", detail: "An include rule for the node's host." },
   {
    term: "Passively scan this host / branch",
    detail: "Re-read the stored traffic under the node through the passive checks; nothing is sent.",
   },
   { term: "Actively scan (crawl)", detail: "Crawl from the node, retained to its host or branch." },
   { term: "Copy URLs in this host / branch", detail: "Every URL under the node, one per line." },
   { term: "Open in Issues", detail: "The issues found under the node." },
   {
    term: "Delete host / branch / item",
    detail: "Hide the node from the map, after a confirmation.",
    note: "Suppression, not deletion: the captured bytes stay in the store.",
   },
  ],
 },
 {
  id: "tool-scope",
  title: "Scope",
  summary: "The scope rule table.",
  source: "src/pages/scope.tsx",
  rows: [
   {
    term: "Include / exclude rules",
    detail: "A URL is in scope when an enabled include rule matches it and no enabled exclude rule does.",
   },
   { term: "Add to scope from traffic", detail: "Proxy history, the site map and Logger rows all offer Add <host> to scope." },
  ],
 },
 {
  id: "tool-intercept",
  title: "Intercept",
  summary: "The held-message menu and the queue toolbar on Proxy › Intercept.",
  source: "src/pages/intercept.tsx",
  rows: [
   { term: "Forward / Drop", detail: "Release the held message (edited or not), or fail it." },
   { term: "Do intercept the response to this request", detail: "Forward the request and hold its response when it comes back." },
   { term: "Don't intercept requests to <host> / for .<ext> files", detail: "Add a request rule that stops holding traffic like this." },
   { term: "Forward all / Drop all", detail: "The whole queue. Drop all asks first — from the toolbar, the palette or its hotkey alike." },
   { term: "Send to Repeater / Comparer / Decoder, Copy URL, Copy as curl", detail: "As in Proxy history, on the held bytes." },
  ],
 },
 {
  id: "tool-logger",
  title: "Logger",
  summary: "The Logger row menu: requests burpsy itself made or relayed.",
  source: "src/pages/logger.tsx",
  rows: [
   { term: "Add / Edit comment, highlight colours", detail: "Annotate the log row." },
   {
    term: "Copy URL (as logged) / Copy as curl (request line only)",
    detail: "The log keeps the request line, not the headers or body, and the labels say so.",
   },
   { term: "Add <host> to scope", detail: "An include rule for the row's host; a multi-row selection adds every distinct host." },
   { term: "Show <host> in HTTP history", detail: "Open History filtered to the host, or to the host and path." },
  ],
 },
 {
  id: "tool-organizer",
  title: "Organizer",
  summary: "The Organizer item menu.",
  source: "src/pages/organizer.tsx",
  rows: [
   { term: "Rename / Add a title", detail: "Give the saved item a title (an empty title clears it)." },
   { term: "Status", detail: "New, in progress, postponed, done or ignored — Burp's workflow statuses." },
   { term: "Highlight", detail: "Colour the item." },
   { term: "Move to… / Copy to…", detail: "File the item into a collection, or copy it into another." },
   { term: "Copy note / Copy exchange id", detail: "For tickets and reports." },
   { term: "Show exchange #N in HTTP history", detail: "Jump to the capture the item came from." },
   { term: "Remove item", detail: "Take the item out of Organizer; the capture keeps the exchange." },
  ],
 },
 {
  id: "tool-issues",
  title: "Issues",
  summary: "The issue list's menu on Target › Issues.",
  source: "src/pages/scanner.tsx, src/lib/issue-triage.ts",
  rows: [
   { term: "Set severity / Set confidence", detail: "An operator override; Engine default clears it." },
   { term: "Mark as false positive / Comment", detail: "Triage that stays with the issue and shows in exports." },
   { term: "Delete issue", detail: "Asks first. A re-audit of the same endpoint raises it again." },
   { term: "Copy issue name / location / detail", detail: "For reports and tickets." },
   { term: "Export this issue / Export scan report", detail: "HTML, JSON or SARIF." },
   { term: "Show exchange #N in HTTP history", detail: "The request that demonstrates the issue." },
  ],
 },
 {
  id: "tool-intruder",
  title: "Intruder",
  summary: "The attack results table's row menu.",
  source: "src/pages/intruder.tsx",
  rows: [
   { term: "Send to Repeater", detail: "The attempt's request, in a new Repeater tab." },
   { term: "Request / Response to slot A or B", detail: "Load one attempt's request or response into Comparer." },
   { term: "Copy request", detail: "The attempt's request as sent." },
  ],
 },
 {
  id: "tool-repeater",
  title: "Repeater",
  summary: "The Repeater tab menu.",
  source: "src/pages/repeater.tsx",
  rows: [
   { term: "Tab colour / Rename", detail: "Label the tab; double-click its name to rename too." },
   { term: "New group with this tab / Move to <group> / Remove from group", detail: "Tab groups, which can be sent together." },
   { term: "Send group in parallel / in sequence", detail: "Send every tab in the group, as Burp's group send does." },
   { term: "Duplicate tab", detail: "A copy of the tab, request draft included." },
   {
    term: "Close / Close other tabs / to the left / to the right",
    detail: "Closed tabs can be reopened, draft included (palette: Reopen the last closed tab).",
   },
  ],
 },
 {
  id: "tool-message-editor",
  title: "Message editor",
  summary: "The request/response editor's menu, in every tool that shows a message.",
  source: "src/ui/editor.tsx",
  rows: [
   {
    term: "Convert selection",
    detail:
     "URL, HTML and Base64 encode or decode the selected text (Ctrl+U/H/B, Shift to decode). A read-only message shows the result in a dialog.",
   },
   { term: "Insert Collaborator payload", detail: "Mint a payload and insert it at the cursor (editable messages)." },
   { term: "Add § payload marker", detail: "Intruder's base request: mark the selection as a payload position." },
   { term: "Actively audit this selection", detail: "Raw view: audit only the selected bytes as the insertion point." },
   { term: "Find in this message", detail: "Open the editor's search panel (Ctrl+S)." },
   { term: "Pretty / Raw / Hex and the typed views", detail: "Pretty reformats only the display; the bytes sent are Raw's." },
   {
    term: "Keys",
    detail: "Ctrl+S search, Ctrl+, / Ctrl+. previous/next match, Ctrl+D delete line, Ctrl+Up/Down paragraph, Ctrl+Alt+C copy prettified.",
   },
   { term: "The tool's own entries", detail: "Above these, the same send-to and copy actions as the tool's table menu." },
  ],
 },
];

/* --- keyboard ------------------------------------------------------------- */

/**
 * The hotkey sheet, one panel per group, rendered from `lib/shortcuts.ts` rather
 * than restated. That registry already feeds the ? modal and Settings → Hotkeys;
 * this is a third renderer of one list, which is fine, where a third
 * hand-maintained list would not be.
 */
export function shortcutPanels(keymap: Keymap): ReferencePanel[] {
 return shortcutGroups().map((group) => ({
  id: `keys-${group.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
  title: `Keyboard — ${group.title}`,
  summary: "mod is ⌘ on macOS and Ctrl elsewhere. A binding that differs from Burp's says why.",
  source: "src/lib/shortcuts.ts — the same registry behind the ? sheet and Settings → Hotkeys",
  rows: group.rows.map((row) => {
   const keys = chordKeys(row, keymap);
   return { key: row.id, term: keys.join(" + "), detail: row.label, keys, note: row.note };
  }),
 }));
}

/** Every panel, in reading order: the gaps first, because they change how the rest is read. */
export function referencePanels(keymap: Keymap): ReferencePanel[] {
 return [LIMITS_PANEL, QUERY_PANEL, BCHECK_PANEL, ...TOOL_PANELS, ...shortcutPanels(keymap), DOCS_PANEL];
}

/* --- search --------------------------------------------------------------- */

function rowText(row: ReferenceRow): string {
 return `${row.term} ${row.detail} ${row.note ?? ""}`;
}

function panelText(panel: ReferencePanel): string {
 return `${panel.title} ${panel.summary} ${panel.source} ${(panel.blocks ?? []).map((block) => `${block.label} ${block.body}`).join(" ")}`;
}

/**
 * Filter panels by a free-text term.
 *
 * A term matching the panel's own title, summary or code blocks keeps the panel
 * whole — searching "bcheck" should hand back the whole BCheck section, not the
 * two rows that happen to repeat the word. Otherwise only matching rows survive,
 * and a panel with no surviving rows drops out entirely so the result is the
 * answer rather than a page of headings.
 */
export function filterPanels(panels: ReferencePanel[], term: string): ReferencePanel[] {
 const needle = term.trim().toLowerCase();
 if (!needle) return panels;
 const out: ReferencePanel[] = [];
 for (const panel of panels) {
  if (panelText(panel).toLowerCase().includes(needle)) {
   out.push(panel);
   continue;
  }
  const rows = panel.rows.filter((row) => rowText(row).toLowerCase().includes(needle));
  if (rows.length) out.push({ ...panel, blocks: undefined, rows });
 }
 return out;
}

/** Total rows across a panel list — the count the page reports next to its search box. */
export function countRows(panels: ReferencePanel[]): number {
 return panels.reduce((total, panel) => total + panel.rows.length, 0);
}
