/** Wire types for the burpsy HTTP API. Field names mirror the Go json tags exactly. */

/**
 * The highlight vocabulary an operator can paint on a row — an Exchange (Task 5 / UX-15) or an
 * OrganizerItem (organizer.tsx). "none" is the absence of a highlight, and it is a UI-only sentinel:
 * the wire never carries the string "none", it carries "" (see `Exchange.highlight` below and Go's
 * `core.ValidHighlights`). Moved here from organizer.tsx so both pages read one copy — see
 * .superpowers/task-5-report.md.
 */
export const HIGHLIGHTS = ["none", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"];

/**
 * Tone to render each highlight as when it needs a `Badge` rather than a swatch (Organizer's table).
 * `gray` and `none` are deliberately unmapped — neither reads as a severity/status colour, so callers
 * fall back to `"neutral"`.
 */
export const HIGHLIGHT_TONE: Record<string, "neutral" | "bad" | "warn" | "good" | "info" | "accent"> = {
 red: "bad",
 orange: "warn",
 yellow: "warn",
 green: "good",
 cyan: "info",
 blue: "info",
 pink: "accent",
 magenta: "accent",
};

export interface ScannerConfig {
 max_concurrency: number;
 timeout_ms: number;
 probe_timeout_ms: number;
 check_sqli: boolean;
 check_xss: boolean;
 check_path_traversal: boolean;
 check_ssrf: boolean;
 check_xxe: boolean;
 check_jwt_weak: boolean;
 check_js_vulns: boolean;
 check_headers: boolean;
 check_cache_poisoning: boolean;
 check_corpus: boolean;
 check_dom: boolean;
 check_extended_coverage: boolean;
 check_reflection_probes: boolean;
 check_host_discovery: boolean;
 check_response_dependence: boolean;
 check_passive_posture: boolean;
 check_passive_analysis: boolean;
 check_active_injection: boolean;
 check_extended_active: boolean;
 check_out_of_band: boolean;
 check_stored: boolean;
}

export interface Stats {
 exchanges: number;
 messages: number;
 stored_bytes: number;
 proxy_bind?: string;
 web_bind?: string;
 tls_interception?: boolean;
 /** The -dom value ("chrome", a path, a ws:// endpoint) or "off". */
 dom_engine?: string;
 /** Whether the audit engine can dispatch the DOM-based checks at all. */
 dom_checks?: boolean;
}

export interface ScopeRule {
 host?: string;
 port?: number;
 protocol?: string;
 path_prefix?: string;
 include?: boolean;
}

export interface Scope {
 allow_all: boolean;
 rules: ScopeRule[];
}

export interface Exchange {
 id: number;
 request: number;
 response: number | null;
 host: string;
 port: number;
 method: string;
 path: string;
 status: number | null;
 response_len: number;
 started_ms: number;
 duration_ms: number;
 /** Whether the exchange was carried over TLS. This — not `protocol` — decides http vs https. */
 tls: boolean;
 /** The HTTP version the exchange used: "Http1" or "Http2". Never "http"/"https". */
 protocol: string;
 /**
  * The response's media type, parameters stripped and lowercased — `"text/html"` for a response
  * whose header read `Content-Type: text/HTML; charset=utf-8`. Always present on the wire
  * (`api_types.go`'s `exchangeView` populates it unconditionally), so not optional — same as
  * `highlight` below.
  *
  * `""` is two different facts and must not be rendered as one. Either no response arrived, or a
  * response arrived declaring no usable Content-Type. `response === null` is what separates them,
  * and every consumer here goes through `mimeLabel` in `history.tsx` rather than deciding again.
  *
  * It was declared here as `mime?: string` for some time while nothing on the wire set it, which is
  * how a MIME column that rendered empty for every row, and a type filter that emptied the table
  * for every value, both passed as shipped features.
  */
 mime: string;
 source?: string;
 notes?: string | null;
 related?: number[];
 /**
  * "" means no highlight. One of the colours in `HIGHLIGHTS` minus its `"none"` sentinel — see Go's
  * `core.ValidHighlights` (UX-15). Always present on the wire (api_types.go's `exchangeView`
  * populates it unconditionally), not optional.
  */
 highlight: string;
 /** Cookie names the response set, in first-seen order. Empty when none were set; `response`
     being null is what separates that from "no response yet". Always on the wire. */
 cookies: string[] | null;
 /** The response's HTML title text, "" when it has none. Always on the wire. */
 title: string;
}

export interface MessageView {
 text: string;
 truncated?: boolean;
 len?: number;
 hex?: string;
 /** The body's exact octets, base64 — present when the body is not valid UTF-8 and `text`
  *  cannot carry it (a JSON string would arrive with those bytes already destroyed). */
 body_base64?: string;
}

export interface CoverageBreakdown {
 found: number;
 skipped: number;
 errored: number;
 gated: number;
 unaccounted: number;
 complete: boolean;
}

export interface CoverageSummary {
 label: string;
 unit: string;
 work_unit: string;
 breakdown: CoverageBreakdown;
}

export interface TaskResult {
 summary: string;
}

export interface TaskRow {
 id: number;
 kind: string;
 target: string;
 state: string;
 done: number;
 total: number;
 fraction: number;
 fraction_known: boolean;
 cancellable: boolean;
 note?: string;
 progress: string;
 elapsed_ms: number;
 result: TaskResult;
}

export interface ActivityRow {
 tool: string;
 method: string;
 path: string;
 status: number | null;
 started_ms: number;
 host?: string;
 port?: number;
}

export interface ToolEvent {
 kind: string;
 severity: string;
 detail: string;
 at_ms: number;
}

export interface Dashboard {
 summaries: CoverageSummary[];
 tasks: TaskRow[];
 tasks_running: number;
 activity: ActivityRow[];
 events: ToolEvent[];
 exchanges: number;
 messages: number;
 stored_bytes: number;
 sources: Record<string, number>;
}

export interface Occurrence {
 exchange_id: number;
 path: string;
}

/** A titled URL from the issue-definition catalogue: further reading, or a CWE/CAPEC entry. */
export interface AdvisoryLink {
 title: string;
 url: string;
}

/**
 * The catalogue entry a finding resolved to. Prose arrives pre-split into plain-text paragraphs
 * rather than as markup, so the console renders it without dangerouslySetInnerHTML — the catalogue
 * is trusted and server-sanitised, but "structurally impossible" beats "defensible" for XSS in the
 * operator's own console. The downloadable report keeps the full markup.
 */
export interface Advisory {
 type_index: string;
 name: string;
 typical_severity: string;
 description_paragraphs?: string[];
 remediation_paragraphs?: string[];
 references?: AdvisoryLink[];
 classifications?: AdvisoryLink[];
}

export interface Finding {
 check_name?: string;
 issue_name?: string | null;
 severity: string;
 confidence: string;
 host: string;
 detail: string;
 remediation: string;
 /** The parameter this finding was observed at; absent for resource-level findings. */
 param?: string;
 times_seen: number;
 occurrences: Occurrence[];
 /** Present when the check resolved to a catalogue entry. */
 advisory?: Advisory | null;
 /** Present instead when it deliberately resolved to none, explaining why. */
 advisory_note?: string;
}

export interface Issues {
 enabled: boolean;
 hint?: string;
 findings: Finding[];
 counts?: Record<string, number>;
}

export interface HeldMessage {
 id: number;
 direction: string;
 host: string;
 method: string;
 path: string;
 raw: string;
}

export interface InterceptState {
 enabled: boolean;
 wired: boolean;
 hint?: string;
 pending: number;
 held: HeldMessage[];
}

/**
 * Per-send config overrides — Burp Repeater's config-override menu, carried on the send payload.
 * Mirrors internal/web/repeaterSendOptions exactly; every field is optional and absent means
 * "the standing behaviour". Deliberately absent from this shape: an ALPN override and a
 * cookies-on-redirect switch — the backend refuses to offer switches that cannot be honest.
 */
export interface RepeaterSendOptions {
 redirect_mode?: "" | "never" | "on_site" | "in_scope" | "always";
 protocol_preference?: "" | "auto" | "http1";
 process_cookies?: boolean;
 strip_connection?: boolean;
 normalize_line_endings?: boolean;
 update_content_length?: boolean;
}

export interface RepeaterResult {
 status: number;
 duration_ms: number;
 response: string;
 exchange_id: number;  /**
   * The redirect chain this send produced, present only when the response was a 30x.
   *
   * `response` above stays the response to the request the operator wrote, so this
   * reports the chain rather than substituting it — the Location and Set-Cookie on a
   * 30x are usually the thing being looked at. Absent means "not a redirect"; present
   * with every hop unfollowed means the policy or the scope stopped it, and `reason`
   * says which.
   */
 redirects?: RepeaterRedirects;
}

/**
 * One position in a Repeater tab's response history: a send's result *paired with the request
 * that produced it*.
 *
 * The pair is the point. Repeater's whole method is "change one thing and compare", and a history
 * entry that carried only the response left the operator reading entry 2 of 5 beside whatever the
 * request pane happened to hold — the current draft, which is not what entry 2 was sent with.
 *
 * `request` is the draft text as the operator wrote it, captured client-side at send time. It is
 * NOT declared on `RepeaterResult` because the server does not return it: /api/repeater/send
 * answers with the response side plus ids, and claiming otherwise on the wire type would be a
 * contract this UI invented. Nor is it the exact bytes that went out — per-send overrides such as
 * `normalize_line_endings` and `update_content_length` are applied server-side — so this is "as
 * written", which is what an operator comparing two variations is actually looking for.
 */
export interface RepeaterHistoryEntry extends RepeaterResult {
 request: string;
 /**
  * How this entry was sent, when it was not an ordinary single Send. Absent means the Send button.
  *
  * Carried because a history entry that rode a shared socket is not comparable to one that dialled
  * fresh — that difference is the whole subject of a smuggling or desync test — and an operator
  * paging back through five entries has no other way to tell which was which.
  */
 group_mode?: RepeaterGroupSendMode;
 /**
  * False when `duration_ms` is not a measurement. Only a single-connection group send sets it:
  * sender.SendKeepAlive owns the write/read loop and reports no per-exchange timing, so the panel
  * renders the batch time instead of a zero that looks measured. Absent means measured.
  */
 duration_measured?: boolean;
 /** The HTTP/1.1 rule that delimited this response's body, for a single-connection group send only. */
 framing?: string;
 /** False when the response was not read to a boundary the server is confident of. */
 response_complete?: boolean;
}

/**
 * How a Repeater tab group is sent — Burp's dropdown beside Send, which appears only when the active
 * tab belongs to a group.
 *
 * `sequence_single_conn` is HTTP/1.1 keep-alive: every request in tab order down one socket, which is
 * the only way a request-smuggling or client-side-desync test can be performed from Repeater at all.
 * It is NOT HTTP/2 multiplexing (burpsy-react-ui-745), and it does not follow redirects — a hop is a
 * new request on a new connection, which is the one thing that mode cannot do.
 */
export type RepeaterGroupSendMode = "sequence_single_conn" | "sequence_separate_conn" | "parallel";

/** One tab's request within a group send. `tab_id` is echoed back on the result that answers it. */
export interface RepeaterGroupSendItem {
 tab_id: string;
 target: string;
 protocol: string;
 request: string;
 from_exchange?: number;
 options?: RepeaterSendOptions;
}

/**
 * One tab's outcome. `result` is the same shape a single send returns, so results render with the
 * code that already exists.
 *
 * `result` and `error` are not exclusive: a response whose head arrived and whose body then failed to
 * delimit is the evidence a smuggling test is reading, so the bytes are reported *and* the failure is
 * named. `result` is null only when nothing came back at all.
 */
export interface RepeaterGroupItemResult {
 tab_id: string;
 result?: RepeaterResult;
 error?: string;
 /** "content-length", "chunked", "eof" or "none" — single-connection mode only. */
 framing?: string;
 /** Absent for the separate-connection modes, where there is no second take to compare against. */
 response_complete?: boolean;
 /** False when `result.duration_ms` is not a measurement. See RepeaterHistoryEntry.duration_measured. */
 duration_measured: boolean;
}

export interface RepeaterGroupSendResult {
 mode: RepeaterGroupSendMode;
 /** One result per request, in the order they were sent — tab order, never completion order. */
 items: RepeaterGroupItemResult[];
 /** The authority the one socket addressed. Present only for `sequence_single_conn`. */
 shared_connection?: string;
 /** Wall time of the whole group send. The only honest timing a single-connection send has. */
 batch_duration_ms: number;
 /**
  * Whether each send's redirect policy was applied at all. False for `sequence_single_conn`, so
  * "no chain" never renders as "we looked and found none".
  */
 followed_redirects: boolean;
}

export interface RepeaterRedirectHop {
 from: string;
 status: number;
 location: string;
 to?: string;
 followed: boolean;
 reason?: string;
 /**
  * The hop's request and response bytes, present only when the hop was followed —
  * a hop that was never sent has no bytes, and absence says exactly that.
  */
 request?: string;
 response?: string;
}

export interface RepeaterRedirects {
 mode: string;
 /** Every request this exchange put on the wire, the operator's own included. */
 sent: number;
 /** False when the chain was still redirecting when it stopped. */
 complete: boolean;
 hops: RepeaterRedirectHop[];
 final_status: number;
 /** Set when the chain could not be evaluated at all, so "did not look" never renders as "nothing to follow". */
 error?: string;
}

export interface InsertionPoint {
 index: number;
 kind: string;
 label: string;
 current: string;
}

export interface SequencerReport {
 tokens: number;
 grade: string;
 verdict: string;
 warnings: string[];
 encoding: string;
 bits?: { bit_entropy?: number;[key: string]: unknown };
 chars?: Record<string, unknown>;
}

export interface WsConnection {
 exchange: number;
 host: string;
 port: number;
 path: string;
 messages: number;
 sent: number;
 received: number;
 last_ms: number;
}

export interface WsRow {
 id: number;
 direction: string;
 opcode: string;
 len: number;
 at_ms: number;
 truncated: boolean;
}

export interface WsHistory {
 total: number;
 rows: WsRow[];
}

export interface WsMessage {
 text?: string;
 hex?: string;
 close?: { code: number; reason: string };
}

export interface SiteNode {
 path: string;
 exchanges: number;
 subtree_exchanges: number;
 methods: string[];
 statuses: number[];
 children: SiteNode[];
}

export interface SiteMap {
 exchanges: number;
 nodes: number;
 synced: number;
 in_flight: number;
 tree: SiteNode[];
}

export interface LogEntry {
 tool: string;
 host: string;
 port: number;
 method: string;
 path: string;
 status: number | null;
 error?: string;
 started_ms: number;
 duration_ms: number;
}

export interface ToolLog {
 total: number;
 shown: number;
 dropped: number;
 entries: LogEntry[];
}

/**
 * The user-applied workflow status of one saved exchange — Burp's organizer "Statuses"
 * (New / In progress / Postponed / Done / Ignored): "which saved requests still need attention and
 * which ones you have already tested". This is the operator's decision and must not be confused
 * with `OrganizerItem.status`, the HTTP response code the server recorded — the page shows both as
 * separate columns, which is exactly how they get mistaken for one field.
 */
export const WORKFLOW_STATUSES = ["new", "in_progress", "postponed", "done", "ignored"] as const;
export type WorkflowStatus = (typeof WORKFLOW_STATUSES)[number];

/** Tone to render each workflow status as; "new" is deliberately unmapped (falls back to neutral). */
export const WORKFLOW_STATUS_TONE: Record<WorkflowStatus, "neutral" | "bad" | "warn" | "good" | "info" | "accent"> = {
 new: "neutral",
 in_progress: "info",
 postponed: "warn",
 done: "good",
 ignored: "neutral",
};

/** The human label for a workflow status; the wire values are underscore-separated. */
export const WORKFLOW_STATUS_LABEL: Record<WorkflowStatus, string> = {
 new: "New",
 in_progress: "In progress",
 postponed: "Postponed",
 done: "Done",
 ignored: "Ignored",
};

/**
 * The editable half of an organizer item: what a save sends back.
 *
 * Split from OrganizerItem because the read shape now carries resolved fields — status, MIME, scope
 * — that the server derives and a client must never send. Typing the save payload as the read shape
 * made a write claim to carry a status, which is not the client's to state.
 */
export interface OrganizerEdit {
 id: number;
 title: string;
 note: string;
 highlight: string;
}

/** One named group of saved exchanges; an item not in any group is in the inbox (collection 0). */
export interface OrganizerCollection {
 id: number;
 name: string;
 note: string;
}

/**
 * A saved exchange, plus what the server resolved about it so the page can filter.
 *
 * The first five fields are the item as stored. Everything after `resolved` is a join against the
 * traffic store and the scope, done server-side because that is where both live — see
 * internal/web/api_organizer_view.go.
 *
 * # `resolved` is the field to read first
 *
 * The organizer outlives the traffic store: an exchange saved a thousand requests ago can be
 * evicted while the note about it survives, which is much of the point of keeping notes. Such a row
 * has no status, no MIME and no scope answer, and every optional field below is absent rather than
 * zero — `status: 0`, `mime: ""` and `in_scope: false` are all *answers*, and this row has none to
 * give. A filter must therefore let unresolved rows through rather than judge them, or it hides a
 * note the operator wrote at exactly the moment they are looking for it.
 */
export interface OrganizerItem extends OrganizerEdit {
 exchange: number;

 /**
  * The workflow status the operator applied — a different axis from `status` below, which is the
  * HTTP response code. Absent means the item predates the field and reads as "new".
  */
 workflow_status?: WorkflowStatus;

 /** The collection this item sits in; 0 (or absent) means the inbox. */
 collection?: number;

 /** False when the exchange is no longer in the traffic store; every field below is then absent. */
 resolved: boolean;
 host?: string;
 port?: number;
 method?: string;
 path?: string;
 /** Absent when the exchange has no response. A request that never came back is not a status of 0. */
 status?: number;
 /**
  * Whether a response was recorded at all. This is what makes an empty `mime` readable: without it,
  * "no response yet" and "a response that named no usable Content-Type" are the same empty string.
  */
 has_response: boolean;
 /** Response media type, parameters stripped and lowercased ("text/html"). */
 mime?: string;
 /** Absent exactly when `resolved` is false — see the note above on why this is not a plain bool. */
 in_scope?: boolean;
}

export interface TrafficRule {
 rule_type: string;
 enabled: boolean;
 string_match: string;
 string_replace: string;
 category: string;
 comment?: string;
}

export interface MatchReplaceConfig {
 rules: TrafficRule[];
 update_content_length: boolean;
}

export interface MatchReplaceResponse {
 affects_requests: boolean;
 affects_responses: boolean;
 config: MatchReplaceConfig;
}

export interface SessionStep {
 method?: string;
 url?: string;
 headers?: string[][];
 body?: string;
}

export interface SessionRule {
 id?: number;
 name?: string;
 enabled: boolean;
 method?: string;
 url?: string;
 headers?: string[][];
 body?: string;
 steps?: SessionStep[];
}

export interface SessionRules {
 wired: boolean;
 rules: SessionRule[];
 hint?: string;
}

export interface ToolOutput {
 text: string;
 [key: string]: unknown;
}
